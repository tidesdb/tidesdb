/*
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "block_manager.h"

#include <openssl/sha.h>
#include <time.h>

/* fcntl.h and sys/stat.h are included via compat.h in block_manager.h */

/* file format:
 * [HEADER]
 * - magic (3 bytes) 0x544442 "TDB"
 * - version (1 byte) 1
 * - block_size (4 bytes) default block size
 * - padding (4 bytes) reserved
 * [BLOCKS]
 * - block_size (8 bytes)
 * - checksum (20 bytes) SHA1 of data
 * - data (variable size)
 * - overflow_offset (8 bytes): 0 if no overflow, otherwise offset to next overflow block
 *
 * CONCURRENCY MODEL:
 * - Single file descriptor shared by all operations
 * - pread/pwrite for lock-free reads (readers don't block readers or writers)
 * - write_mutex only for serializing writes (writers block writers)
 * - Readers NEVER block - they can read while writes happen
 */

/* internal helper to compute SHA1 checksum */
static void compute_sha1(const void *data, size_t size, unsigned char *digest)
{
    SHA1((const unsigned char *)data, size, digest);
}

/* internal helper to verify SHA1 checksum */
static int verify_sha1(const void *data, size_t size, const unsigned char *expected_digest)
{
    unsigned char computed_digest[BLOCK_MANAGER_SHA1_DIGEST_LENGTH];
    compute_sha1(data, size, computed_digest);
    return memcmp(computed_digest, expected_digest, BLOCK_MANAGER_SHA1_DIGEST_LENGTH) == 0 ? 0 : -1;
}

/* internal helper to write file header using pwrite */
static int write_header(int fd, uint32_t block_size)
{
    unsigned char header[BLOCK_MANAGER_HEADER_SIZE];
    uint32_t magic = BLOCK_MANAGER_MAGIC;
    uint8_t version = BLOCK_MANAGER_VERSION;
    uint32_t padding = 0;

    /* build header buffer */
    memcpy(header, &magic, 3);
    memcpy(header + 3, &version, sizeof(uint8_t));
    memcpy(header + 4, &block_size, sizeof(uint32_t));
    memcpy(header + 8, &padding, sizeof(uint32_t));

    /* write atomically at offset 0 */
    ssize_t written = pwrite(fd, header, BLOCK_MANAGER_HEADER_SIZE, 0);
    return (written == BLOCK_MANAGER_HEADER_SIZE) ? 0 : -1;
}

/* internal helper to read and validate file header using pread */
static int read_header(int fd, uint32_t *block_size)
{
    unsigned char header[BLOCK_MANAGER_HEADER_SIZE];

    /* read header atomically */
    ssize_t nread = pread(fd, header, BLOCK_MANAGER_HEADER_SIZE, 0);
    if (nread != BLOCK_MANAGER_HEADER_SIZE) return -1;

    /* extract and validate magic */
    uint32_t magic;
    memcpy(&magic, header, 3);
    magic &= 0xFFFFFF; /* mask to 3 bytes */

    if (magic != BLOCK_MANAGER_MAGIC) return -1;

    /* extract and validate version */
    uint8_t version;
    memcpy(&version, header + 3, sizeof(uint8_t));
    if (version != BLOCK_MANAGER_VERSION) return -1;

    /* extract block size */
    memcpy(block_size, header + 4, sizeof(uint32_t));

    return 0;
}

/* internal helper to get file size */
static int get_file_size(int fd, uint64_t *size)
{
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;
    *size = (uint64_t)st.st_size;
    return 0;
}

int block_manager_open(block_manager_t **bm, const char *file_path, tidesdb_sync_mode_t sync_mode,
                       int fsync_interval)
{
    (*bm) = malloc(sizeof(block_manager_t));
    if (!(*bm)) return -1;

    int file_exists = access(file_path, F_OK) == 0;

    /* open with O_RDWR for read/write, O_CREAT to create if needed */
    int flags = O_RDWR | O_CREAT;
    mode_t mode = 0644;

    (*bm)->fd = open(file_path, flags, mode);
    if ((*bm)->fd == -1)
    {
        free(*bm);
        return -1;
    }

    strncpy((*bm)->file_path, file_path, MAX_FILE_PATH_LENGTH - 1);
    (*bm)->file_path[MAX_FILE_PATH_LENGTH - 1] = '\0';

    /* set sync mode and interval */
    (*bm)->sync_mode = sync_mode;
    (*bm)->fsync_interval = fsync_interval;

    (*bm)->stop_fsync_thread = 0;

    /* initialize write mutex for thread safety on writes only */
    if (pthread_mutex_init(&(*bm)->write_mutex, NULL) != 0)
    {
        close((*bm)->fd);
        free(*bm);
        return -1;
    }

    if (pthread_cond_init(&(*bm)->fsync_cond, NULL) != 0)
    {
        pthread_mutex_destroy(&(*bm)->write_mutex);
        close((*bm)->fd);
        free(*bm);
        return -1;
    }

    /* handle file header */
    if (file_exists)
    {
        /* read existing header */
        if (read_header((*bm)->fd, &(*bm)->block_size) != 0)
        {
            pthread_mutex_destroy(&(*bm)->write_mutex);
            close((*bm)->fd);
            free(*bm);
            return -1;
        }

        /* validate last block */
        int validation_result = block_manager_validate_last_block(*bm);
        if (validation_result != 0)
        {
            pthread_mutex_destroy(&(*bm)->write_mutex);
            close((*bm)->fd);
            free(*bm);
            return -1;
        }
    }
    else
    {
        /* new file, write header */
        (*bm)->block_size = MAX_INLINE_BLOCK_SIZE;
        if (write_header((*bm)->fd, (*bm)->block_size) != 0)
        {
            pthread_mutex_destroy(&(*bm)->write_mutex);
            close((*bm)->fd);
            free(*bm);
            return -1;
        }
        if (fdatasync((*bm)->fd) != 0)
        {
            pthread_mutex_destroy(&(*bm)->write_mutex);
            close((*bm)->fd);
            free(*bm);
            return -1;
        }
    }

    /* create and start the fsync thread only for background sync */
    if (sync_mode == TDB_SYNC_BACKGROUND)
    {
        if (pthread_create(&(*bm)->fsync_thread, NULL, block_manager_fsync_thread, *bm) != 0)
        {
            pthread_mutex_destroy(&(*bm)->write_mutex);
            pthread_cond_destroy(&(*bm)->fsync_cond);
            close((*bm)->fd);
            free(*bm);
            return -1;
        }
    }

    return 0;
}

int block_manager_close(block_manager_t *bm)
{
    /* signal the fsync thread to stop and wait for it (only if background sync) */
    if (bm->sync_mode == TDB_SYNC_BACKGROUND)
    {
        bm->stop_fsync_thread = 1;

        /* wake up the fsync thread if it's sleeping on the condition variable */
        pthread_mutex_lock(&bm->write_mutex);
        pthread_cond_signal(&bm->fsync_cond);
        pthread_mutex_unlock(&bm->write_mutex);

        /* wait for the fsync thread to finish */
        if (pthread_join(bm->fsync_thread, NULL) != 0) return -1;
    }

    /* flush the file to disk one final time */
    (void)fdatasync(bm->fd);

    /* close the file descriptor */
    if (close(bm->fd) != 0) return -1;

    /* destroy synchronization primitives */
    pthread_cond_destroy(&bm->fsync_cond);
    pthread_mutex_destroy(&bm->write_mutex);

    /* free the block manager */
    free(bm);
    bm = NULL;

    return 0;
}

block_manager_block_t *block_manager_block_create(uint64_t size, void *data)
{
    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = size;

    block->data = malloc(size);
    if (!block->data)
    {
        free(block);
        block = NULL;
        return NULL;
    }

    memcpy(block->data, data, size);
    return block;
}

long block_manager_block_write(block_manager_t *bm, block_manager_block_t *block)
{
    if (!bm || !block || !block->data) return -1;

    (void)pthread_mutex_lock(&bm->write_mutex);

    /* get current file size for append position */
    uint64_t file_size;
    if (get_file_size(bm->fd, &file_size) != 0)
    {
        (void)pthread_mutex_unlock(&bm->write_mutex);
        return -1;
    }

    long offset = (long)file_size;

    /* compute SHA1 checksum */
    unsigned char checksum[BLOCK_MANAGER_SHA1_DIGEST_LENGTH];
    compute_sha1(block->data, block->size, checksum);

    /* determine if we need overflow blocks */
    uint64_t inline_size = block->size <= bm->block_size ? block->size : bm->block_size;
    uint64_t remaining = block->size > bm->block_size ? block->size - bm->block_size : 0;

    /* build main block in memory buffer for atomic write */
    size_t main_block_total_size =
        sizeof(uint64_t) + BLOCK_MANAGER_SHA1_DIGEST_LENGTH + inline_size + sizeof(uint64_t);
    unsigned char *main_block_buffer = malloc(main_block_total_size);
    if (!main_block_buffer)
    {
        (void)pthread_mutex_unlock(&bm->write_mutex);
        return -1;
    }

    size_t buf_offset = 0;

    /* write block size */
    memcpy(main_block_buffer + buf_offset, &block->size, sizeof(uint64_t));
    buf_offset += sizeof(uint64_t);

    /* write checksum */
    memcpy(main_block_buffer + buf_offset, checksum, BLOCK_MANAGER_SHA1_DIGEST_LENGTH);
    buf_offset += BLOCK_MANAGER_SHA1_DIGEST_LENGTH;

    /* write inline data */
    memcpy(main_block_buffer + buf_offset, block->data, inline_size);
    buf_offset += inline_size;

    /* placeholder for overflow offset */
    uint64_t overflow_offset = 0;
    memcpy(main_block_buffer + buf_offset, &overflow_offset, sizeof(uint64_t));

    /* write main block atomically using pwrite */
    ssize_t written = pwrite(bm->fd, main_block_buffer, main_block_total_size, offset);
    free(main_block_buffer);

    if (written != (ssize_t)main_block_total_size)
    {
        (void)pthread_mutex_unlock(&bm->write_mutex);
        return -1;
    }

    /* handle overflow if needed */
    if (remaining > 0)
    {
        uint64_t overflow_link_pos =
            (uint64_t)offset + sizeof(uint64_t) + BLOCK_MANAGER_SHA1_DIGEST_LENGTH + inline_size;
        uint64_t data_offset = inline_size;
        uint64_t current_write_pos = (uint64_t)offset + main_block_total_size;

        while (remaining > 0)
        {
            /* determine chunk size */
            uint64_t chunk_size = remaining <= bm->block_size ? remaining : bm->block_size;

            /* compute checksum for this chunk */
            unsigned char chunk_checksum[BLOCK_MANAGER_SHA1_DIGEST_LENGTH];
            compute_sha1((unsigned char *)block->data + data_offset, chunk_size, chunk_checksum);

            /* build overflow block buffer */
            size_t overflow_block_size =
                sizeof(uint64_t) + BLOCK_MANAGER_SHA1_DIGEST_LENGTH + chunk_size + sizeof(uint64_t);
            unsigned char *overflow_buffer = malloc(overflow_block_size);
            if (!overflow_buffer)
            {
                (void)pthread_mutex_unlock(&bm->write_mutex);
                return -1;
            }

            size_t obuf_offset = 0;

            /* write chunk size */
            memcpy(overflow_buffer + obuf_offset, &chunk_size, sizeof(uint64_t));
            obuf_offset += sizeof(uint64_t);

            /* write chunk checksum */
            memcpy(overflow_buffer + obuf_offset, chunk_checksum, BLOCK_MANAGER_SHA1_DIGEST_LENGTH);
            obuf_offset += BLOCK_MANAGER_SHA1_DIGEST_LENGTH;

            /* write chunk data */
            memcpy(overflow_buffer + obuf_offset, (unsigned char *)block->data + data_offset,
                   chunk_size);
            obuf_offset += chunk_size;

            /* next overflow offset (0 if last) */
            uint64_t next_overflow =
                (remaining - chunk_size > 0) ? (current_write_pos + overflow_block_size) : 0;
            memcpy(overflow_buffer + obuf_offset, &next_overflow, sizeof(uint64_t));

            /* update previous overflow link to point to this block using pwrite */
            if (pwrite(bm->fd, &current_write_pos, sizeof(uint64_t), (off_t)overflow_link_pos) !=
                sizeof(uint64_t))
            {
                free(overflow_buffer);
                (void)pthread_mutex_unlock(&bm->write_mutex);
                return -1;
            }

            /* write overflow block atomically using pwrite */
            if (pwrite(bm->fd, overflow_buffer, overflow_block_size, (off_t)current_write_pos) !=
                (ssize_t)overflow_block_size)
            {
                free(overflow_buffer);
                (void)pthread_mutex_unlock(&bm->write_mutex);
                return -1;
            }

            free(overflow_buffer);

            /* update for next iteration */
            overflow_link_pos = current_write_pos + sizeof(uint64_t) +
                                BLOCK_MANAGER_SHA1_DIGEST_LENGTH + chunk_size;
            data_offset += chunk_size;
            remaining -= chunk_size;
            current_write_pos += overflow_block_size;
        }
    }

    /* perform sync based on sync_mode */
    if (bm->sync_mode == TDB_SYNC_FULL)
    {
        /* full sync on every write */
        if (fdatasync(bm->fd) != 0)
        {
            (void)pthread_mutex_unlock(&bm->write_mutex);
            return -1;
        }
    }
    /* TDB_SYNC_BACKGROUND fsync thread handles it */
    /* TDB_SYNC_NONE no sync */

    (void)pthread_mutex_unlock(&bm->write_mutex);
    return offset;
}

void block_manager_block_free(block_manager_block_t *block)
{
    if (block)
    {
        if (block->data) free(block->data);
        free(block);
        block = NULL;
    }
}

int block_manager_cursor_init(block_manager_cursor_t **cursor, block_manager_t *bm)
{
    if (!bm) return -1;

    /* allocate memory for the new cursor */
    (*cursor) = malloc(sizeof(block_manager_cursor_t));
    if (!(*cursor)) return -1;

    /* set the block manager of the cursor - shares same fd, no extra file handles */
    (*cursor)->bm = bm;

    /* initialize to position after header */
    (*cursor)->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    (*cursor)->current_block_size = 0;

    return 0;
}

int block_manager_cursor_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* read block size at current position using pread */
    uint64_t block_size;
    ssize_t nread =
        pread(cursor->bm->fd, &block_size, sizeof(uint64_t), (off_t)cursor->current_pos);
    if (nread != sizeof(uint64_t))
    {
        if (nread == 0) return 1; /* EOF */
        return -1;
    }

    /* calculate inline size */
    uint64_t inline_size =
        block_size <= cursor->bm->block_size ? block_size : cursor->bm->block_size;

    /* calculate overflow offset position */
    off_t overflow_offset_pos = (off_t)cursor->current_pos + (off_t)sizeof(uint64_t) +
                                (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)inline_size;

    /* read overflow offset using pread */
    uint64_t overflow_offset;
    if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)overflow_offset_pos) !=
        sizeof(uint64_t))
        return -1;

    /* if no overflow, next block starts immediately after this one */
    if (overflow_offset == 0)
    {
        cursor->current_pos = (uint64_t)(overflow_offset_pos + (off_t)sizeof(uint64_t));
        cursor->current_block_size = block_size;
        return 0;
    }

    /* skip overflow chain to find end */
    uint64_t last_overflow_pos = (uint64_t)(overflow_offset_pos + (off_t)sizeof(uint64_t));
    while (overflow_offset != 0)
    {
        off_t chunk_offset = (off_t)overflow_offset;

        /* read chunk size using pread */
        uint64_t chunk_size;
        if (pread(cursor->bm->fd, &chunk_size, sizeof(uint64_t), (off_t)chunk_offset) !=
            sizeof(uint64_t))
            return -1;

        /* calculate next overflow offset position */
        off_t next_overflow_pos = chunk_offset + (off_t)sizeof(uint64_t) +
                                  (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)chunk_size;

        /* read next overflow offset using pread */
        if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)next_overflow_pos) !=
            sizeof(uint64_t))
            return -1;

        last_overflow_pos = (uint64_t)(next_overflow_pos + (off_t)sizeof(uint64_t));
    }

    /* update cursor position to after last overflow block */
    cursor->current_pos = last_overflow_pos;
    cursor->current_block_size = block_size;

    return 0;
}

int block_manager_cursor_has_next(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* save current state */
    uint64_t saved_cursor_pos = cursor->current_pos;
    uint64_t saved_block_size = cursor->current_block_size;

    /* try to move to next */
    int result = block_manager_cursor_next(cursor);

    /* restore cursor state */
    cursor->current_pos = saved_cursor_pos;
    cursor->current_block_size = saved_block_size;

    if (result == 0) return 1; /* has next */
    if (result == 1) return 0; /* EOF */
    return -1;                 /* error */
}

int block_manager_cursor_has_prev(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;
    return (cursor->current_pos > BLOCK_MANAGER_HEADER_SIZE) ? 1 : 0;
}

block_manager_block_t *block_manager_cursor_read(block_manager_cursor_t *cursor)
{
    if (!cursor) return NULL;

    /* read block size using pread */
    uint64_t block_size;
    if (pread(cursor->bm->fd, &block_size, sizeof(uint64_t), (off_t)cursor->current_pos) !=
        sizeof(uint64_t))
        return NULL;

    const uint64_t MAX_REASONABLE_BLOCK_SIZE = 1ULL << 30; /* 1GB */
    if (block_size == 0 || block_size > MAX_REASONABLE_BLOCK_SIZE)
    {
        return NULL;
    }

    /* read checksum using pread */
    unsigned char checksum[BLOCK_MANAGER_SHA1_DIGEST_LENGTH];
    off_t checksum_pos = (off_t)cursor->current_pos + (off_t)sizeof(uint64_t);
    if (pread(cursor->bm->fd, checksum, BLOCK_MANAGER_SHA1_DIGEST_LENGTH, (off_t)checksum_pos) !=
        BLOCK_MANAGER_SHA1_DIGEST_LENGTH)
        return NULL;

    /* allocate block */
    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = block_size;
    block->data = malloc(block_size);
    if (!block->data)
    {
        free(block);
        return NULL;
    }

    /* read inline data using pread */
    uint64_t inline_size =
        block_size <= cursor->bm->block_size ? block_size : cursor->bm->block_size;
    off_t data_pos = (off_t)cursor->current_pos + (off_t)sizeof(uint64_t) +
                     (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH;

    if (pread(cursor->bm->fd, block->data, inline_size, (off_t)data_pos) != (ssize_t)inline_size)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    /* read overflow offset using pread */
    off_t overflow_offset_pos = data_pos + (off_t)inline_size;
    uint64_t overflow_offset;
    if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)overflow_offset_pos) !=
        sizeof(uint64_t))
    {
        free(block->data);
        free(block);
        return NULL;
    }

    /* read overflow blocks using pread */
    uint64_t data_offset = inline_size;
    while (overflow_offset != 0)
    {
        /* read chunk size using pread */
        uint64_t chunk_size;
        if (pread(cursor->bm->fd, &chunk_size, sizeof(uint64_t), (off_t)overflow_offset) !=
            sizeof(uint64_t))
        {
            free(block->data);
            free(block);
            return NULL;
        }

        /* validate chunk_size to prevent corrupted data from causing overflow or OOM */
        if (chunk_size == 0 || chunk_size > cursor->bm->block_size ||
            data_offset + chunk_size > block_size)
        {
            free(block->data);
            free(block);
            return NULL;
        }

        /* read chunk checksum using pread */
        unsigned char chunk_checksum[BLOCK_MANAGER_SHA1_DIGEST_LENGTH];
        off_t chunk_checksum_pos = (off_t)overflow_offset + (off_t)sizeof(uint64_t);
        if (pread(cursor->bm->fd, chunk_checksum, BLOCK_MANAGER_SHA1_DIGEST_LENGTH,
                  (off_t)chunk_checksum_pos) != BLOCK_MANAGER_SHA1_DIGEST_LENGTH)
        {
            free(block->data);
            free(block);
            return NULL;
        }

        /* read chunk data using pread */
        off_t chunk_data_pos = chunk_checksum_pos + (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH;
        if (pread(cursor->bm->fd, (unsigned char *)block->data + data_offset, chunk_size,
                  (off_t)chunk_data_pos) != (ssize_t)chunk_size)
        {
            free(block->data);
            free(block);
            return NULL;
        }

        /* verify chunk checksum */
        if (verify_sha1((unsigned char *)block->data + data_offset, chunk_size, chunk_checksum) !=
            0)
        {
            free(block->data);
            free(block);
            return NULL;
        }

        /* read next overflow offset using pread */
        off_t next_overflow_pos = chunk_data_pos + (off_t)chunk_size;
        if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)next_overflow_pos) !=
            sizeof(uint64_t))
        {
            free(block->data);
            free(block);
            return NULL;
        }

        data_offset += chunk_size;
    }

    /* verify main block checksum */
    if (verify_sha1(block->data, block_size, checksum) != 0)
    {
        free(block->data);
        free(block);
        return NULL;
    }

    return block;
}

void block_manager_cursor_free(block_manager_cursor_t *cursor)
{
    if (cursor)
    {
        /* no file descriptor to close - we share bm->fd */
        free(cursor);
        cursor = NULL;
    }
}

int block_manager_cursor_prev(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* can't go back from first block */
    if (cursor->current_pos <= BLOCK_MANAGER_HEADER_SIZE) return -1;

    /* scan from beginning using pread to find previous block */
    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;

    while (scan_pos < cursor->current_pos)
    {
        /* read block size using pread */
        uint64_t block_size;
        if (pread(cursor->bm->fd, &block_size, sizeof(uint64_t), (off_t)scan_pos) !=
            sizeof(uint64_t))
            return -1;

        /* calculate inline size */
        uint64_t inline_size =
            block_size <= cursor->bm->block_size ? block_size : cursor->bm->block_size;

        /* read overflow offset using pread */
        off_t overflow_offset_pos = (off_t)scan_pos + (off_t)sizeof(uint64_t) +
                                    (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)inline_size;
        uint64_t overflow_offset;
        if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)overflow_offset_pos) !=
            sizeof(uint64_t))
            return -1;

        /* calculate next block position */
        uint64_t next_pos = (uint64_t)(overflow_offset_pos + (off_t)sizeof(uint64_t));

        /* skip overflow chain using pread */
        while (overflow_offset != 0)
        {
            uint64_t chunk_size;
            if (pread(cursor->bm->fd, &chunk_size, sizeof(uint64_t), (off_t)overflow_offset) !=
                sizeof(uint64_t))
                return -1;

            off_t next_overflow_pos = (off_t)overflow_offset + (off_t)sizeof(uint64_t) +
                                      (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)chunk_size;
            if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t),
                      (off_t)next_overflow_pos) != sizeof(uint64_t))
                return -1;

            next_pos = (uint64_t)(next_overflow_pos + (off_t)sizeof(uint64_t));
        }

        /* check if next block is our current position */
        if (next_pos >= cursor->current_pos)
        {
            cursor->current_pos = scan_pos;
            cursor->current_block_size = block_size;
            return 0;
        }

        scan_pos = next_pos;
    }

    return -1;
}

void *block_manager_fsync_thread(void *arg)
{
    block_manager_t *bm = (block_manager_t *)arg;

    struct timespec ts;

    pthread_mutex_lock(&bm->write_mutex);

    while (!bm->stop_fsync_thread)
    {
        /* calculate absolute timeout time from milliseconds */
        clock_gettime(CLOCK_REALTIME, &ts);

        /* convert milliseconds to seconds and nanoseconds */
        long ms = bm->fsync_interval;
        ts.tv_sec += ms / 1000;
        ts.tv_nsec += (ms % 1000) * 1000000;

        /* handle nanosecond overflow */
        if (ts.tv_nsec >= 1000000000)
        {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000;
        }

        /* wait on condition variable with timeout */
        int result = pthread_cond_timedwait(&bm->fsync_cond, &bm->write_mutex, &ts);

        /* if we were signaled to stop, exit loop */
        if (bm->stop_fsync_thread) break;

        /* if timeout occurred (not spurious wakeup or signal), perform fdatasync */
        if (result == ETIMEDOUT)
        {
            pthread_mutex_unlock(&bm->write_mutex);
            (void)fdatasync(bm->fd);
            pthread_mutex_lock(&bm->write_mutex);
        }
    }

    pthread_mutex_unlock(&bm->write_mutex);

    return NULL;
}

int block_manager_cursor_goto_first(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    cursor->current_pos = BLOCK_MANAGER_HEADER_SIZE;
    cursor->current_block_size = 0;

    return 0;
}

int block_manager_cursor_goto_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* position to first block position (before any data) */
    if (block_manager_cursor_goto_first(cursor) != 0) return -1;

    /* move forward until we hit EOF (no more blocks to read) */
    while (block_manager_cursor_next(cursor) == 0)
    {
        /* keep advancing through blocks */
    }

    /* at this point, cursor is positioned after the last block.
     * move back one block to be AT the last block (readable). */
    return block_manager_cursor_prev(cursor);
}

int block_manager_truncate(block_manager_t *bm)
{
    if (!bm) return -1;

    pthread_mutex_lock(&bm->write_mutex);

    if (ftruncate(bm->fd, 0) != 0)
    {
        pthread_mutex_unlock(&bm->write_mutex);
        return -1;
    }

    if (close(bm->fd) != 0)
    {
        pthread_mutex_unlock(&bm->write_mutex);
        return -1;
    }

    bm->fd = open(bm->file_path, O_RDWR | O_CREAT, 0644);
    if (bm->fd == -1)
    {
        pthread_mutex_unlock(&bm->write_mutex);
        return -1;
    }

    /* write new header */
    if (write_header(bm->fd, bm->block_size) != 0)
    {
        pthread_mutex_unlock(&bm->write_mutex);
        return -1;
    }

    if (fdatasync(bm->fd) != 0)
    {
        pthread_mutex_unlock(&bm->write_mutex);
        return -1;
    }

    pthread_mutex_unlock(&bm->write_mutex);
    return 0;
}

int block_manager_cursor_at_first(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;
    return (cursor->current_pos == BLOCK_MANAGER_HEADER_SIZE) ? 1 : 0;
}

int block_manager_cursor_at_second(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* if at first block, not at second */
    if (cursor->current_pos == BLOCK_MANAGER_HEADER_SIZE) return 0;

    /* read first block size using pread */
    uint64_t first_block_size;
    if (pread(cursor->bm->fd, &first_block_size, sizeof(uint64_t),
              (off_t)BLOCK_MANAGER_HEADER_SIZE) != sizeof(uint64_t))
        return -1;

    /* calculate inline size */
    uint64_t inline_size =
        first_block_size <= cursor->bm->block_size ? first_block_size : cursor->bm->block_size;

    /* calculate overflow offset position */
    off_t overflow_offset_pos = (off_t)BLOCK_MANAGER_HEADER_SIZE + (off_t)sizeof(uint64_t) +
                                (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)inline_size;

    /* read overflow offset using pread */
    uint64_t overflow_offset;
    if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)overflow_offset_pos) !=
        sizeof(uint64_t))
        return -1;

    /* calculate second block position */
    uint64_t second_block_pos = (uint64_t)(overflow_offset_pos + (off_t)sizeof(uint64_t));

    /* skip overflow chain if present using pread */
    while (overflow_offset != 0)
    {
        uint64_t chunk_size;
        if (pread(cursor->bm->fd, &chunk_size, sizeof(uint64_t), (off_t)overflow_offset) !=
            sizeof(uint64_t))
            return -1;

        off_t next_overflow_pos = (off_t)overflow_offset + (off_t)sizeof(uint64_t) +
                                  (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)chunk_size;
        if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)next_overflow_pos) !=
            sizeof(uint64_t))
            return -1;

        second_block_pos = (uint64_t)(next_overflow_pos + (off_t)sizeof(uint64_t));
    }

    return (cursor->current_pos == second_block_pos) ? 1 : 0;
}

int block_manager_cursor_at_last(block_manager_cursor_t *cursor)
{
    if (!cursor) return -1;

    /* read current block size using pread */
    uint64_t block_size;
    if (pread(cursor->bm->fd, &block_size, sizeof(uint64_t), (off_t)cursor->current_pos) !=
        sizeof(uint64_t))
        return -1;

    /* calculate inline size */
    uint64_t inline_size =
        block_size <= cursor->bm->block_size ? block_size : cursor->bm->block_size;

    /* calculate overflow offset position */
    off_t overflow_offset_pos = (off_t)cursor->current_pos + (off_t)sizeof(uint64_t) +
                                (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)inline_size;

    /* read overflow offset using pread */
    uint64_t overflow_offset;
    if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)overflow_offset_pos) !=
        sizeof(uint64_t))
        return -1;

    /* calculate position after current block */
    uint64_t after_current_pos = (uint64_t)(overflow_offset_pos + (off_t)sizeof(uint64_t));

    /* skip overflow chain using pread */
    while (overflow_offset != 0)
    {
        uint64_t chunk_size;
        if (pread(cursor->bm->fd, &chunk_size, sizeof(uint64_t), (off_t)overflow_offset) !=
            sizeof(uint64_t))
            return -1;

        off_t next_overflow_pos = (off_t)overflow_offset + (off_t)sizeof(uint64_t) +
                                  (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)chunk_size;
        if (pread(cursor->bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)next_overflow_pos) !=
            sizeof(uint64_t))
            return -1;

        after_current_pos = (uint64_t)(next_overflow_pos + (off_t)sizeof(uint64_t));
    }

    /* try to read next block using pread */
    uint64_t next_block_size;
    ssize_t read_result =
        pread(cursor->bm->fd, &next_block_size, sizeof(uint64_t), (off_t)after_current_pos);

    return (read_result != sizeof(uint64_t)) ? 1 : 0;
}

int block_manager_get_size(block_manager_t *bm, uint64_t *size)
{
    if (!bm || !size) return -1;

    struct stat st;
    if (stat(bm->file_path, &st) != 0) return -1;
    *size = (uint64_t)st.st_size;
    return 0;
}

int block_manager_cursor_goto(block_manager_cursor_t *cursor, uint64_t pos)
{
    if (!cursor) return -1;

    cursor->current_pos = pos;
    return 0;
}

int block_manager_escalate_fsync(block_manager_t *bm)
{
    if (!bm) return -1;
    return fdatasync(bm->fd);
}

time_t block_manager_last_modified(block_manager_t *bm)
{
    if (!bm) return -1;

    struct stat st;
    if (stat(bm->file_path, &st) != 0) return -1;
    return st.st_mtime;
}

int block_manager_count_blocks(block_manager_t *bm)
{
    if (!bm) return -1;

    block_manager_cursor_t *cursor;
    int count = 0;

    if (block_manager_cursor_init(&cursor, bm) != 0) return -1;

    /* position at first block */
    block_manager_cursor_goto_first(cursor);

    /* check if there are any blocks */
    if (block_manager_cursor_has_next(cursor) > 0)
    {
        /* move to first block and count it */
        block_manager_cursor_next(cursor);
        count++;

        /* count remaining blocks */
        while (block_manager_cursor_next(cursor) == 0)
        {
            count++;
        }
    }

    block_manager_cursor_free(cursor);
    return count;
}

int block_manager_validate_last_block(block_manager_t *bm)
{
    if (!bm) return -1;

    /* get file size using pread-compatible approach */
    uint64_t file_size;
    if (get_file_size(bm->fd, &file_size) != 0) return -1;

    /* if file is empty, write header */
    if (file_size == 0)
    {
        pthread_mutex_lock(&bm->write_mutex);
        if (write_header(bm->fd, bm->block_size) != 0)
        {
            pthread_mutex_unlock(&bm->write_mutex);
            return -1;
        }
        fdatasync(bm->fd);
        pthread_mutex_unlock(&bm->write_mutex);
        return 0;
    }

    if (file_size == BLOCK_MANAGER_HEADER_SIZE)
    {
        return 0; /* valid empty file with header */
    }

    /* ensure we have at least header + one block header */
    if (file_size < BLOCK_MANAGER_HEADER_SIZE + sizeof(uint64_t) +
                        BLOCK_MANAGER_SHA1_DIGEST_LENGTH + sizeof(uint64_t))
    {
        /* truncate to header only */
        pthread_mutex_lock(&bm->write_mutex);
        ftruncate(bm->fd, BLOCK_MANAGER_HEADER_SIZE);
        lseek(bm->fd, 0, SEEK_SET);
        pthread_mutex_unlock(&bm->write_mutex);
        return (bm->fd != -1) ? 0 : -1;
    }

    /* scan through blocks to find last complete one using pread */
    uint64_t valid_size = BLOCK_MANAGER_HEADER_SIZE;
    uint64_t scan_pos = BLOCK_MANAGER_HEADER_SIZE;

    while (scan_pos < file_size)
    {
        /* try to read block size using pread */
        uint64_t block_size;
        if (pread(bm->fd, &block_size, sizeof(uint64_t), (off_t)scan_pos) != sizeof(uint64_t))
            break;

        /* calculate inline size */
        uint64_t inline_size = block_size <= bm->block_size ? block_size : bm->block_size;

        /* check if we have complete inline block */
        if (scan_pos + sizeof(uint64_t) + BLOCK_MANAGER_SHA1_DIGEST_LENGTH + inline_size +
                sizeof(uint64_t) >
            file_size)
        {
            valid_size = scan_pos;
            break;
        }

        /* read overflow offset using pread */
        off_t overflow_offset_pos = (off_t)scan_pos + (off_t)sizeof(uint64_t) +
                                    (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)inline_size;
        uint64_t overflow_offset;
        if (pread(bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)overflow_offset_pos) !=
            sizeof(uint64_t))
            break;

        uint64_t next_pos = (uint64_t)(overflow_offset_pos + (off_t)sizeof(uint64_t));

        /* validate overflow chain using pread */
        while (overflow_offset != 0)
        {
            if (overflow_offset >= file_size)
            {
                valid_size = scan_pos;
                goto done_scanning;
            }

            uint64_t chunk_size;
            if (pread(bm->fd, &chunk_size, sizeof(uint64_t), (off_t)overflow_offset) !=
                sizeof(uint64_t))
            {
                valid_size = scan_pos;
                goto done_scanning;
            }

            /* check if complete overflow block exists */
            if (overflow_offset + sizeof(uint64_t) + BLOCK_MANAGER_SHA1_DIGEST_LENGTH + chunk_size +
                    sizeof(uint64_t) >
                file_size)
            {
                valid_size = scan_pos;
                goto done_scanning;
            }

            off_t next_overflow_pos = (off_t)overflow_offset + (off_t)sizeof(uint64_t) +
                                      (off_t)BLOCK_MANAGER_SHA1_DIGEST_LENGTH + (off_t)chunk_size;
            if (pread(bm->fd, &overflow_offset, sizeof(uint64_t), (off_t)next_overflow_pos) !=
                sizeof(uint64_t))
            {
                valid_size = scan_pos;
                goto done_scanning;
            }

            next_pos = (uint64_t)(next_overflow_pos + (off_t)sizeof(uint64_t));
        }

        /* this block and its overflow chain are complete */
        valid_size = next_pos;
        scan_pos = next_pos;
    }

done_scanning:
    /* truncate if needed */
    if (valid_size != file_size)
    {
        pthread_mutex_lock(&bm->write_mutex);

        if (ftruncate(bm->fd, (long)valid_size) != 0)
        {
            pthread_mutex_unlock(&bm->write_mutex);
            return -1;
        }

        close(bm->fd);
        bm->fd = open(bm->file_path, O_RDWR | O_CREAT, 0644);
        if (bm->fd == -1)
        {
            pthread_mutex_unlock(&bm->write_mutex);
            return -1;
        }

        pthread_mutex_unlock(&bm->write_mutex);
    }

    return 0;
}