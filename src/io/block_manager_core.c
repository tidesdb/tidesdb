/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/log.h"
#include "base/waitstat.h" /* tdb_wait_deadline and the condvar clock it pairs with */
#include "block_manager_internal.h"

/* set once the first preallocation failure has been reported, so a platform that lacks the call
 * does not repeat the warning for every file the database opens */
static _Atomic int g_prealloc_unsupported_logged;

/**
 * maybe_extend_allocation
 * extends the on-disk preallocation when a new reservation gets within LOWWATER of
 * the current preallocated extent. multiple writers may race here; the loop is
 * lock-free and at worst causes a redundant fallocate (idempotent on overlapping
 * ranges). on platforms without preallocation support, the first failure stamps
 * preallocated_size with UINT64_MAX so the slow path is never retaken.
 * @param bm the block manager
 * @param reservation_end one past the last byte just reserved by the caller
 */
void maybe_extend_allocation(block_manager_t *bm, const uint64_t reservation_end)
{
    for (;;)
    {
        const uint64_t prealloc =
            atomic_load_explicit(&bm->preallocated_size, memory_order_acquire);
        /* chunk is per-instance (block_manager_open_pre); lowwater derives as chunk >> 4 so the
         * default 64 MB chunk keeps its 4 MB lowwater while a small manifest chunk scales down */
        const uint64_t chunk = atomic_load_explicit(&bm->prealloc_chunk, memory_order_relaxed);
        if (chunk == 0) return; /* preallocation disabled -- writes extend the file exactly */
        const uint64_t lowwater = chunk >> BLOCK_MANAGER_PREALLOC_LOWWATER_SHIFT;
        if (BM_LIKELY(reservation_end + lowwater <= prealloc)) return;

        /* round up to the next CHUNK boundary so successive extends stay aligned */
        const uint64_t target = ((reservation_end + chunk - 1) / chunk) * chunk;
        if (target <= prealloc) return; /* another writer already extended past this target */

        if (tdb_preallocate_extent(bm->fd, (off_t)prealloc, (off_t)(target - prealloc)) != 0)
        {
            /* unsupported on this fs or platform, so disable further attempts and let subsequent
             * pwrites take the slower extending-write path. worth a line, because the cost is large
             * and otherwise invisible -- but only the first one, since a platform without the call
             * fails this for every file it ever opens */
            atomic_store_explicit(&bm->preallocated_size, UINT64_MAX, memory_order_release);
            if (!atomic_exchange_explicit(&g_prealloc_unsupported_logged, 1, memory_order_relaxed))
                TDB_DEBUG_LOG(TDB_LOG_WARN,
                              "preallocation unavailable on this platform or filesystem, writes "
                              "extend files instead, starting with %s",
                              bm->file_path);
            return;
        }

        uint64_t expected = prealloc;
        if (atomic_compare_exchange_strong_explicit(&bm->preallocated_size, &expected, target,
                                                    memory_order_release, memory_order_acquire))
        {
            return;
        }
        /* lost the CAS race; another writer also extended -- reload and re-check */
    }
}

/**
 * write_header
 * write file header using pwrite
 * @param fd the file descriptor to write to
 * @return 0 if successful, -1 otherwise
 */
int write_header(const int fd)
{
    unsigned char header[BLOCK_MANAGER_HEADER_SIZE];
    const uint32_t padding = 0;

    /* header format
     * [3-byte magic][1-byte version][4-byte padding] = 8 bytes */
    encode_uint32_le_compat(header, BLOCK_MANAGER_MAGIC);
    header[BLOCK_MANAGER_MAGIC_SIZE] = BLOCK_MANAGER_VERSION;
    encode_uint32_le_compat(header + BLOCK_MANAGER_MAGIC_SIZE + BLOCK_MANAGER_VERSION_SIZE,
                            padding);

    return pwrite_all(fd, header, BLOCK_MANAGER_HEADER_SIZE, 0);
}

/**
 * read_header
 * read and validate file header using pread
 * @param fd the file descriptor to read from
 * @return 0 if successful, -1 otherwise
 */
static int read_header(const int fd)
{
    unsigned char header[BLOCK_MANAGER_HEADER_SIZE];

    const ssize_t nread = pread(fd, header, BLOCK_MANAGER_HEADER_SIZE, 0);
    if (nread != BLOCK_MANAGER_HEADER_SIZE) return -1;

    /* decode magic using little-endian conversion for cross-platform compatibility */
    uint32_t magic = decode_uint32_le_compat(header);
    magic &= BLOCK_MANAGER_MAGIC_MASK;

    if (magic != BLOCK_MANAGER_MAGIC) return -1;

    uint8_t version;
    memcpy(&version, header + BLOCK_MANAGER_MAGIC_SIZE, BLOCK_MANAGER_VERSION_SIZE);
    if (version != BLOCK_MANAGER_VERSION) return -1;

    return 0;
}

/**
 * get_file_size
 * get file size using fstat
 * @param fd the file descriptor to get the size of
 * @param size the size to store the result in
 * @return 0 if successful, -1 otherwise
 */
int get_file_size(const int fd, uint64_t *size)
{
    struct STAT_STRUCT st;
    if (FSTAT_FUNC(fd, &st) != 0) return -1;
    *size = (uint64_t)st.st_size;
    return 0;
}

/**
 * reopen_fd
 * closes and reopens the block manager file descriptor with the same flags.
 * not safe against concurrent readers, a reader that already captured bm->fd will
 * pread on a closed (possibly recycled) descriptor. callers (truncate, permissive
 * validation) must hold the bm exclusively / quiesce readers first.
 * @param bm the block manager
 * @return 0 if successful, -1 if not
 */
int reopen_fd(block_manager_t *bm)
{
    close(bm->fd);

    int flags = O_RDWR | O_CREAT;
    if (is_sync_full(bm) && odsync_available())
    {
        flags |= O_DSYNC;
    }

    bm->fd = open(bm->file_path, flags, BLOCK_MANAGER_FILE_MODE);
    if (bm->fd == -1) return -1;

    return 0;
}

/**
 * bm_truncate_and_reset
 * truncate the file to size, make the truncation durable, and reset the in-memory watermarks so the
 * next write re-extends preallocation from scratch. the caller must have quiesced the flush thread
 * on a buffered handle, otherwise a stale-high flush frontier would let a post-truncate committer
 * treat bytes the truncation removed as already written
 * @param bm the block manager
 * @param size the byte length to truncate to
 * @return 0 on success, -1 on error
 */
static int bm_truncate_and_reset(block_manager_t *bm, uint64_t size)
{
    if (ftruncate(bm->fd, (off_t)size) == -1) return -1;

    /* ftruncate is not covered by O_DSYNC, so truncation always fdatasyncs under sync-full */
    if (bm_sync_after_truncate(bm) != 0) return -1;

    atomic_store(&bm->current_file_size, size);
    atomic_store(&bm->preallocated_size, size); /* ftruncate invalidates the preallocated extent */
    if (bm->buffered)
    {
        atomic_store(&bm->buf_flushed, size);
    }
    return 0;
}

/**
 * truncate_to_header
 * truncate the file back to just the header, resetting the tracked size and preallocation extent
 * @param bm the block manager
 * @return 0 on success, -1 on error
 */
int truncate_to_header(block_manager_t *bm)
{
    return bm_truncate_and_reset(bm, BLOCK_MANAGER_HEADER_SIZE);
}

void block_manager_set_io_stat(block_manager_t *bm, tdb_io_stat_t *io)
{
    if (bm) bm->io_stat = io;
}

/**
 * bm_init_fields
 * initialize a freshly allocated handle to the direct-path defaults for the given sync mode and
 * preallocation chunk, before its fd is opened. a prealloc_chunk of 0 disables preallocation so the
 * file grows to exactly what is written, which tiny append logs like the manifest rely on; the
 * buffered-append fields start on the direct path until block_manager_open_buffered turns them on,
 * and the zero-init is mandatory since a garbage buffered flag would misroute every append.
 * @param m the handle to initialize
 * @param sync_mode the durability mode this handle was opened with
 * @param prealloc_chunk the on-disk extend granularity, or 0 to disable preallocation
 */
static void bm_init_fields(block_manager_t *m, const block_manager_sync_mode_t sync_mode,
                           const uint64_t prealloc_chunk)
{
    atomic_init(&m->current_file_size, 0);
    atomic_init(&m->preallocated_size, 0);
    atomic_init(&m->prealloc_chunk, prealloc_chunk);

    /* no accounting until an opener claims this handle; the struct is malloc'd, so a field left
     * alone here holds whatever the allocator returned */
    m->io_stat = NULL;

    m->buffered = 0;
    m->ring = NULL;
    m->done_ring = NULL;
    m->ring_size = 0;
    atomic_init(&m->buf_flushed, 0);
    atomic_init(&m->flush_stop, 0);
    atomic_init(&m->flush_error, 0);
    atomic_init(&m->flush_sleeping, 0);
    atomic_init(&m->durable_waiters, 0);

    m->sync_mode = sync_mode;
    atomic_init(&m->sync_full_cached, sync_mode == BLOCK_MANAGER_SYNC_FULL);
}

/**
 * bm_open_header
 * read the header of an existing file or write and make durable a fresh one, returning 0 on success
 * and -1 with errno set on any io failure, leaving the caller to close and free the handle
 * @param m the handle whose fd is already open
 * @param file_exists nonzero when the file predated this open and its header must be read back
 * @return 0 on success, -1 with errno set on failure
 */
static int bm_open_header(block_manager_t *m, int file_exists)
{
    /* a crash between creating a file and finishing its header leaves a stub smaller than one full
     * header -- most often a just-rotated WAL. treat such a stub, and an empty existing file, as
     * fresh by writing a clean header, so recovery proceeds with the older generations rather than
     * rejecting the torn one */
    if (file_exists)
    {
        uint64_t file_size = 0;
        if (get_file_size(m->fd, &file_size) == 0 && file_size >= BLOCK_MANAGER_HEADER_SIZE)
            return read_header(m->fd);
    }
    if (write_header(m->fd) != 0) return -1;
    return bm_sync_after_write(m);
}

/**
 * block_manager_open_internal
 * allocate the handle, open or create the file, then read back an existing header or write a fresh
 * one; on failure the errno of the failing syscall is preserved for the caller
 * @param bm output, set to the opened block manager, NULL on failure
 * @param file_path the path of the file
 * @param sync_mode the sync mode driving durability
 * @param prealloc_chunk the on-disk extend granularity, or 0 to disable preallocation
 * @return 0 on success, -1 on error with errno preserved
 */
static int block_manager_open_internal(block_manager_t **bm, const char *file_path,
                                       const block_manager_sync_mode_t sync_mode,
                                       const uint64_t prealloc_chunk)
{
    block_manager_t *new_bm = malloc(sizeof(block_manager_t));
    if (!new_bm)
    {
        *bm = NULL;
        return -1;
    }

    bm_init_fields(new_bm, sync_mode, prealloc_chunk);

    const int file_exists = access(file_path, F_OK) == 0;

    int flags = O_RDWR | O_CREAT;

    /* O_DSYNC gives synchronous data writes in SYNC_FULL mode
     * this ensures each pwrite is durable before returning, eliminating
     * the need for per-write fdatasync() calls on platforms that support it.
     * this is also faster, fewer syscalls
     */
    if (is_sync_full(new_bm) && odsync_available())
    {
        flags |= O_DSYNC;
    }

    const mode_t mode = BLOCK_MANAGER_FILE_MODE;

    new_bm->fd = open(file_path, flags, mode);
    if (new_bm->fd == -1)
    {
        /* preserve the open() errno across free() so the caller can report the real cause
         * (EMFILE/ENFILE = fd exhaustion, ENOSPC = disk full, EACCES, ...) */
        const int open_errno = errno;
        /* say why here, because every caller above this point reduces the failure to a null handle
         * and then to a generic io code, so the cause is unrecoverable by the time anyone sees it
         */
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "open failed on %s, %s", file_path, strerror(open_errno));
        free(new_bm);
        *bm = NULL;
        errno = open_errno;
        return -1;
    }

    strncpy(new_bm->file_path, file_path, MAX_FILE_PATH_LENGTH - 1);
    new_bm->file_path[MAX_FILE_PATH_LENGTH - 1] = '\0';

    if (bm_open_header(new_bm, file_exists) != 0)
    {
        const int hdr_errno = errno;
        /* a file that opened but whose header would not read is the interesting case, since it
         * means the bytes on disk are not what this build expects rather than the descriptor being
         * denied */
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "header read failed on %s, existing %d, %s", file_path,
                      file_exists, strerror(hdr_errno));
        close(new_bm->fd);
        free(new_bm);
        *bm = NULL;
        errno = hdr_errno;
        return -1;
    }

    /* set current_file_size if not already set by validation */
    if (atomic_load(&new_bm->current_file_size) == 0)
    {
        uint64_t file_size = 0;
        if (get_file_size(new_bm->fd, &file_size) == 0)
        {
            atomic_store(&new_bm->current_file_size, file_size);
        }
        else
        {
            /* if the size is unavailable, use lseek to get current position (end of file) */
            const off_t pos = lseek(new_bm->fd, 0, SEEK_END);
            atomic_store(&new_bm->current_file_size, (pos >= 0) ? (uint64_t)pos : 0);
        }
    }

    /* preallocated extent starts at the current file size; first write will extend it */
    atomic_store(&new_bm->preallocated_size, atomic_load(&new_bm->current_file_size));

    *bm = new_bm;
    return 0;
}

int block_manager_last_errno(const block_manager_t *bm)
{
    if (!bm) return 0;
    return atomic_load_explicit(&bm->flush_error, memory_order_acquire);
}

int tdb_errno_to_result(const int err)
{
    if (err == ENOSPC) return TDB_ERR_NO_SPACE;
#ifdef EDQUOT
    /* the same condition wearing a quota's clothes -- the write cannot land now and will once room
     * is made, which is the distinction this code carries. not every platform defines it */
    if (err == EDQUOT) return TDB_ERR_NO_SPACE;
#endif
    return TDB_ERR_IO;
}

int block_manager_close(block_manager_t *bm)
{
    if (!bm) return -1;

    /* in buffered mode stop and join the flush thread, draining the ring, before touching the fd.
     * callers quiesce appenders first (no reservation left outstanding), so every reserved record
     * is completed and the flush thread drains to flushed == current_file_size then exits. */
    if (bm->buffered)
    {
        atomic_store_explicit(&bm->flush_stop, 1, memory_order_release);
        pthread_mutex_lock(&bm->buf_mtx);
        pthread_cond_signal(&bm->buf_work_cv);
        pthread_mutex_unlock(&bm->buf_mtx);
        pthread_join(bm->flush_tid, NULL);
        /* a clean drain left every done-ring flag cleared, so return the warm buffer pair to the
         * pool for the next WAL. a flush error may have left flags set, so free that pair instead.
         */
        if (atomic_load_explicit(&bm->flush_error, memory_order_acquire))
        {
            free(bm->ring);
            free(bm->done_ring);
        }
        else
            bm_buf_pool_release(bm->ring, bm->done_ring, bm->ring_size);
        bm->ring = NULL;
        bm->done_ring = NULL;
        pthread_mutex_destroy(&bm->buf_mtx);
        pthread_cond_destroy(&bm->buf_work_cv);
        pthread_cond_destroy(&bm->buf_durable_cv);
        bm->buffered = 0;
    }

    /* preallocation advances logical EOF past actual data; trim back so next-open
     * validation sees the real tail block instead of trailing zeros. crash recovery
     * still has to tolerate trailing zeros (size_field == 0 marks the boundary). */
    const uint64_t valid_size = atomic_load(&bm->current_file_size);
    const uint64_t prealloc = atomic_load(&bm->preallocated_size);
    if (prealloc != UINT64_MAX && prealloc > valid_size && bm->fd >= 0)
    {
        /* best-effort -- if it fails, next-open validate_last_block tolerates the
         * trailing-zero preallocation tail. (void) cast doesn't suppress glibc's
         * warn_unused_result, hence the explicit if. */
        if (ftruncate(bm->fd, (off_t)valid_size) != 0)
        {
            /* swallow */
        }
    }

    /* final sync on close -- only needed when O_DSYNC wasn't used;
     * with O_DSYNC every write is already durable */
    if (is_sync_full(bm) && !odsync_available())
    {
        (void)fdatasync(bm->fd);
    }

    int close_result = 0;
    if (bm->fd >= 0 && close(bm->fd) != 0)
    {
        close_result = -1;
    }

    free(bm);

    return close_result;
}

int block_manager_truncate_to(block_manager_t *bm, const uint64_t new_size)
{
    if (!bm || new_size < BLOCK_MANAGER_HEADER_SIZE) return -1;
    return bm_truncate_and_reset(bm, new_size);
}

int block_manager_truncate(block_manager_t *bm)
{
    if (!bm) return -1;

    /* truncate to header-only (preserves valid header, single sync) */
    if (truncate_to_header(bm) != 0) return -1;

    /* reopen the fd so any stale O_APPEND/seek state is reset and the descriptor
     * reflects the freshly truncated file (caller must have quiesced readers) */
    if (reopen_fd(bm) != 0) return -1;

    return 0;
}

int block_manager_get_size(block_manager_t *bm, uint64_t *size)
{
    if (!bm || !size) return -1;
    /* on a buffered handle current_file_size is the reservation watermark -- records reserved but
     * still in the staging ring are not yet in the file. report the flushed extent so a consumer
     * reading the file only sees bytes that are actually on disk. buffered handles are WAL-only, so
     * sstable callers are unaffected. */
    *size = atomic_load(bm->buffered ? &bm->buf_flushed : &bm->current_file_size);
    return 0;
}

uint64_t block_manager_framed_size(const uint32_t payload_size)
{
    return BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)payload_size + BLOCK_MANAGER_FOOTER_SIZE;
}

int block_manager_buffered_lag(block_manager_t *bm, uint64_t *out_lag, uint64_t *out_capacity)
{
    if (!bm || !out_lag || !out_capacity) return -1;

    if (!bm->buffered)
    {
        *out_lag = 0;
        *out_capacity = 0;
        return 0;
    }

    /* reserved first, then written: the other order can observe a write that landed after the
     * reservation was read and report a negative lag as an enormous one */
    const uint64_t reserved = atomic_load_explicit(&bm->current_file_size, memory_order_acquire);
    const uint64_t written = atomic_load_explicit(&bm->buf_flushed, memory_order_acquire);
    *out_lag = reserved > written ? reserved - written : 0;
    *out_capacity = bm->ring_size;
    return 0;
}

int block_manager_escalate_fsync(block_manager_t *bm)
{
    if (!bm) return -1;

    /* in buffered append mode an appender returns once its bytes are in the staging ring, which the
     * flush thread has not necessarily written yet. syncing the descriptor alone would then report
     * as durable a record that is still only in this process's memory, so wait for the frontier to
     * pass everything reserved before the barrier */
    if (bm->buffered && bm_wait_flushed(bm, atomic_load_explicit(&bm->current_file_size,
                                                                 memory_order_acquire)) != 0)
        return -1;

    if (fdatasync(bm->fd) != 0)
    {
        bm_note_write_failure(bm);
        return -1;
    }
    return 0;
}

time_t block_manager_last_modified(block_manager_t *bm)
{
    if (!bm) return -1;

    struct STAT_STRUCT st;
    if (STAT_FUNC(bm->file_path, &st) != 0) return -1;
    return st.st_mtime;
}

/* the db-layer sync-mode values convert_sync_mode maps from, mirrored here as local constants
 * so the io layer stays independent of the db-layer enum */
#define BM_TDB_SYNC_NONE 0
#define BM_TDB_SYNC_FULL 1

block_manager_sync_mode_t convert_sync_mode(const int tdb_sync_mode)
{
    switch (tdb_sync_mode)
    {
        case BM_TDB_SYNC_NONE:
            return BLOCK_MANAGER_SYNC_NONE;
        case BM_TDB_SYNC_FULL:
            return BLOCK_MANAGER_SYNC_FULL;
        default:
            return BLOCK_MANAGER_SYNC_NONE;
    }
}

void block_manager_set_sync_mode(block_manager_t *bm, const int sync_mode)
{
    if (!bm) return;
    bm->sync_mode = convert_sync_mode(sync_mode);
    atomic_store_explicit(&bm->sync_full_cached, bm->sync_mode == BLOCK_MANAGER_SYNC_FULL,
                          memory_order_relaxed);
}

int block_manager_open(block_manager_t **bm, const char *file_path, const int sync_mode)
{
    if (!bm || !file_path) return -1;
    return block_manager_open_internal(bm, file_path, convert_sync_mode(sync_mode),
                                       BLOCK_MANAGER_PREALLOC_CHUNK);
}

int block_manager_open_pre(block_manager_t **bm, const char *file_path, const int sync_mode,
                           const uint64_t prealloc_chunk)
{
    if (!bm || !file_path) return -1;
    return block_manager_open_internal(bm, file_path, convert_sync_mode(sync_mode), prealloc_chunk);
}

int block_manager_open_buffered(block_manager_t **bm, const char *file_path, const int sync_mode,
                                const uint64_t ring_size)
{
    if (!bm || !file_path) return -1;
    int rc = block_manager_open_internal(bm, file_path, convert_sync_mode(sync_mode),
                                         BLOCK_MANAGER_PREALLOC_CHUNK);
    if (rc != 0) return rc;
    block_manager_t *b = *bm;

    uint64_t R = ring_size ? ring_size : BM_BUF_DEFAULT_RING;
    if (R < BM_BUF_MIN_RING) R = BM_BUF_MIN_RING;
    /* reuse a retired, warm buffer pair when one of this size is pooled; else allocate fresh */
    if (!bm_buf_pool_acquire(R, &b->ring, &b->done_ring))
    {
        b->ring = malloc(R);
        b->done_ring = calloc(R, 1); /* per-ring-position completion flags, zeroed */
    }
    if (!b->ring || !b->done_ring)
    {
        free(b->ring);
        free(b->done_ring);
        b->ring = NULL;
        b->done_ring = NULL;
        (void)block_manager_close(b);
        *bm = NULL;
        return -1;
    }
    b->ring_size = R;

    /* watermarks start at the current (post-header / post-recovery) file size -- reservations
     * continue from there and the flush thread only ever writes newly-appended bytes. */
    const uint64_t fsz = atomic_load(&b->current_file_size);
    atomic_store(&b->buf_flushed, fsz);

    pthread_mutex_init(&b->buf_mtx, NULL);
    /* both on the clock their deadlines are built from, so a wall clock step cannot hold the
     * flush thread or a durability waiter past the backstop it asked for */
    tdb_cond_init_monotonic(&b->buf_work_cv);
    tdb_cond_init_monotonic(&b->buf_durable_cv);
    b->buffered = 1;

    if (pthread_create(&b->flush_tid, NULL, bm_flush_thread, b) != 0)
    {
        b->buffered = 0;
        pthread_mutex_destroy(&b->buf_mtx);
        pthread_cond_destroy(&b->buf_work_cv);
        pthread_cond_destroy(&b->buf_durable_cv);
        free(b->ring);
        free(b->done_ring);
        b->ring = NULL;
        b->done_ring = NULL;
        (void)block_manager_close(b);
        *bm = NULL;
        return -1;
    }
    return 0;
}
