/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "base/log.h"
#include "block_manager_internal.h"

/* record the errno of a failed write or sync on the handle, and say so once per handle. a full
 * device is the one io failure a user can act on, and it otherwise reaches them as a bare io error
 * from whichever operation happened to be running -- which is how a filled disk gets mistaken for a
 * bug in the engine. the free-space figure comes from the same statvfs the caller would have to run
 * by hand to tell the two apart */
static void bm_note_write_failure(block_manager_t *bm)
{
    const int err = errno ? errno : EIO;
    /* the first failure is the one that explains the rest, so only it is reported */
    int expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&bm->flush_error, &expected, err,
                                                 memory_order_release, memory_order_acquire))
        return;

    if (tdb_errno_to_result(err) == TDB_ERR_NO_SPACE)
    {
        uint64_t available = 0;
        if (tdb_get_available_disk_space(bm->file_path, &available) != 0) available = 0;
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "out of space writing %s, %llu bytes available", bm->file_path,
                      (unsigned long long)available);
    }
    else
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "write failed on %s, %s", bm->file_path, strerror(err));
    }
}

block_manager_block_t *block_manager_block_create(const uint64_t size, const void *data)
{
    if (size > UINT32_MAX)
    {
        return NULL;
    }

    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = size;
    block->inline_data = 0;

    block->data = malloc(size);
    if (!block->data)
    {
        free(block);
        return NULL;
    }

    /* copy only if size > 0 and data is not NULL */
    if (size > 0 && data != NULL)
    {
        memcpy(block->data, data, size);
    }
    return block;
}

block_manager_block_t *block_manager_block_create_from_buffer(const uint64_t size, void *data)
{
    if (size > UINT32_MAX)
    {
        return NULL;
    }

    block_manager_block_t *block = malloc(sizeof(block_manager_block_t));
    if (!block) return NULL;

    block->size = size;
    block->data = data;
    block->inline_data = 0;
    return block;
}

/* buffered-append tunables */
#define BM_BUF_SPIN          128  /* spin iterations before parking on a cond var */
#define BM_BUF_FLUSH_PARK_US 500  /* flush-thread park timeout, a missed-signal safety net */
#define BM_BUF_WAIT_PARK_US  2000 /* appender durability-wait park timeout */

/* the park timeout only exists to catch a wake that was somehow missed; bm_wake_flush is the real
 * signal and is ordered against the appender's completion flag so it cannot be lost. holding the
 * short timeout while nothing is arriving therefore buys nothing and costs a wakeup every half
 * millisecond, which is most of an idle database's CPU. consecutive empty parks back the timeout
 * off toward the ceiling, and any drained run resets it */
#define BM_BUF_FLUSH_PARK_MAX_US 250000 /* idle ceiling, a quarter second */
#define BM_BUF_FLUSH_PARK_GROWTH 2      /* multiplier applied per consecutive empty park */

/* a rotating WAL opens a fresh buffered handle every generation; without pooling that mallocs and
 * first-touches (page-faults) a new ring plus done-ring each time, on the rotation critical path. a
 * small free-list hands a retired, already-resident buffer pair to the next open instead. a
 * released done-ring is all-zero (the flush thread cleared every flag as it drained before close),
 * so it is reusable as-is. bounded -- overflow is freed. */
#define BM_BUF_POOL_MAX 8

typedef struct
{
    uint8_t *ring;
    _Atomic unsigned char *done_ring;
    uint64_t ring_size;
} bm_buf_pooled_t;

static bm_buf_pooled_t bm_buf_pool[BM_BUF_POOL_MAX];

static int bm_buf_pool_count = 0;

static pthread_mutex_t bm_buf_pool_mtx = PTHREAD_MUTEX_INITIALIZER;

/* pop a pooled buffer pair of exactly ring_size bytes into the ring and done_ring out-params,
 * returning 1, or 0 if the pool holds none of that size. */
int bm_buf_pool_acquire(uint64_t ring_size, uint8_t **ring, _Atomic unsigned char **done_ring)
{
    int got = 0;
    pthread_mutex_lock(&bm_buf_pool_mtx);
    for (int i = bm_buf_pool_count - 1; i >= 0; i--)
    {
        if (bm_buf_pool[i].ring_size == ring_size)
        {
            *ring = bm_buf_pool[i].ring;
            *done_ring = bm_buf_pool[i].done_ring;
            bm_buf_pool[i] = bm_buf_pool[--bm_buf_pool_count];
            got = 1;
            break;
        }
    }
    pthread_mutex_unlock(&bm_buf_pool_mtx);
    return got;
}

/* return a clean (all-zero done_ring) buffer pair to the pool, or free it if the pool is full. */
void bm_buf_pool_release(uint8_t *ring, _Atomic unsigned char *done_ring, uint64_t ring_size)
{
    pthread_mutex_lock(&bm_buf_pool_mtx);
    if (bm_buf_pool_count < BM_BUF_POOL_MAX)
    {
        bm_buf_pool[bm_buf_pool_count].ring = ring;
        bm_buf_pool[bm_buf_pool_count].done_ring = done_ring;
        bm_buf_pool[bm_buf_pool_count].ring_size = ring_size;
        bm_buf_pool_count++;
        pthread_mutex_unlock(&bm_buf_pool_mtx);
        return;
    }
    pthread_mutex_unlock(&bm_buf_pool_mtx);
    free(ring);
    free(done_ring);
}

/**
 * bm_ring_copy
 * copy n bytes of src into the staging ring at file offset off, wrapping at the ring boundary.
 * @param ring the staging ring buffer
 * @param R the ring capacity in bytes
 * @param off the file offset whose ring slot (off % R) receives the copy
 * @param src the bytes to copy in
 * @param n the number of bytes to copy
 */
static inline void bm_ring_copy(uint8_t *ring, uint64_t R, uint64_t off, const void *src, size_t n)
{
    uint64_t pos = off % R;
    if (pos + n <= R)
    {
        memcpy(ring + pos, src, n);
    }
    else
    {
        size_t part1 = (size_t)(R - pos);
        memcpy(ring + pos, src, part1);
        memcpy(ring, (const uint8_t *)src + part1, n - part1);
    }
}

/**
 * bm_ring_read_u32
 * read a record's little-endian uint32 size field from the ring at file offset off, wrapping at the
 * ring boundary. a plain (non-atomic) read -- the caller only reaches here after acquire-loading
 * done_ring[off], which synchronizes-with the appender's release-store after it copied the record.
 * @param ring the staging ring buffer
 * @param R the ring capacity in bytes
 * @param off the file offset of the size field to read
 * @return the decoded size field
 */
static inline uint32_t bm_ring_read_u32(const uint8_t *ring, uint64_t R, uint64_t off)
{
    uint64_t pos = off % R;
    uint8_t b[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pos + BLOCK_MANAGER_SIZE_FIELD_SIZE <= R)
    {
        memcpy(b, ring + pos, BLOCK_MANAGER_SIZE_FIELD_SIZE);
    }
    else
    {
        size_t p1 = (size_t)(R - pos);
        memcpy(b, ring + pos, p1);
        memcpy(b + p1, ring, (size_t)(BLOCK_MANAGER_SIZE_FIELD_SIZE - p1));
    }
    return decode_uint32_le_compat(b);
}

/**
 * bm_done
 * report whether the record starting at file offset off has been fully copied into the ring, by
 * acquire-loading its completion flag in done_ring.
 * @param bm the block manager
 * @param off the record's start file offset
 * @return non-zero if the record is fully copied, 0 otherwise
 */
static inline int bm_done(block_manager_t *bm, uint64_t off)
{
    return atomic_load_explicit(&bm->done_ring[off % bm->ring_size], memory_order_acquire) != 0;
}

/* account one completed write against this handle's class, so bytes and time can be attributed to
 * the kind of file rather than pooled across the database */
static void bm_note_io(const block_manager_t *bm, const uint64_t bytes, const uint64_t started_us)
{
    if (!bm->io_stat) return;
    tdb_io_note(bm->io_stat, bytes, tdb_monotonic_us() - started_us);
}

/**
 * bm_flush_write_run
 * pwrite the contiguous completed run at the flush frontier, handling a ring wrap as two writes;
 * returns 0 on success and -1 with errno set on an io error
 * @param bm the buffered block manager
 * @param fl the flushed frontier the run starts at
 * @param sz the run length in bytes
 */
static int bm_flush_write_run(block_manager_t *bm, uint64_t fl, uint64_t sz)
{
    const uint64_t R = bm->ring_size;
    const uint64_t pos = fl % R;
    const uint64_t started_us = tdb_monotonic_us();
    if (pos + sz <= R)
    {
        const int rc = pwrite_all(bm->fd, (const void *)(bm->ring + pos), (size_t)sz, (off_t)fl);
        bm_note_io(bm, sz, started_us);
        return rc;
    }

    const uint64_t part1 = R - pos;
    int rc = pwrite_all(bm->fd, (const void *)(bm->ring + pos), (size_t)part1, (off_t)fl);
    if (rc == 0)
        rc = pwrite_all(bm->fd, (const void *)bm->ring, (size_t)(sz - part1), (off_t)(fl + part1));
    bm_note_io(bm, sz, started_us);
    return rc;
}

/**
 * bm_flush_drain
 * drain the contiguous completed run at the flush frontier to the fd and advance the durability
 * watermarks, waking backpressured appenders; returns 1 when a run was written, 0 when nothing was
 * ready at the frontier, and -1 on an io error with flush_error set
 * @param bm the buffered block manager
 */
static int bm_flush_drain(block_manager_t *bm)
{
    const uint64_t R = bm->ring_size;
    const uint64_t fl = atomic_load_explicit(&bm->buf_flushed, memory_order_relaxed);
    const uint64_t reserved = atomic_load_explicit(&bm->current_file_size, memory_order_acquire);

    /* find the end of the contiguous completed run [fl, p), clearing each record's done flag while
     * passing over it. clearing here (before the pwrite) is safe because a slot is not reusable
     * until buf_flushed advances past it below, which no appender observes until the release-store,
     * and the flush thread is the only reader of the done flags. this folds the clearing into the
     * single advance walk rather than a separate pass. */
    uint64_t p = fl;
    while (p < reserved && bm_done(bm, p))
    {
        const uint32_t rs = bm_ring_read_u32(bm->ring, R, p);
        atomic_store_explicit(&bm->done_ring[p % R], 0, memory_order_relaxed);
        p += BLOCK_MANAGER_BLOCK_HEADER_SIZE + (uint64_t)rs + BLOCK_MANAGER_FOOTER_SIZE;
    }
    if (p <= fl) return 0;

    if (bm_flush_write_run(bm, fl, p - fl) != 0)
    {
        bm_note_write_failure(bm);
        return -1;
    }
    if (bm_sync_after_write(bm) != 0)
    {
        bm_note_write_failure(bm);
        return -1;
    }
    atomic_store_explicit(&bm->buf_flushed, p, memory_order_release);

    /* always broadcast per drain-batch -- a lock-free waiter-count gate races the waiter's
     * increment and drops wakeups, stalling backpressured appenders for a full cond timeout */
    pthread_mutex_lock(&bm->buf_mtx);
    pthread_cond_broadcast(&bm->buf_durable_cv);
    pthread_mutex_unlock(&bm->buf_mtx);
    return 1;
}

/**
 * bm_flush_park
 * park the flush thread until the frontier record completes or the manager stops, spinning briefly
 * first and then waiting on the work cond var with a timeout as a missed-signal net
 * @param bm the buffered block manager
 * @param park_us in/out -- microseconds this thread has parked, accumulated across calls for the
 *                stall statistics
 */
static void bm_flush_park(block_manager_t *bm, long *park_us)
{
    const uint64_t fl = atomic_load_explicit(&bm->buf_flushed, memory_order_relaxed);
    for (int s = 0; s < BM_BUF_SPIN; s++)
    {
        if (fl < atomic_load_explicit(&bm->current_file_size, memory_order_acquire) &&
            bm_done(bm, fl))
            return;
        bm_cpu_relax();
    }

    pthread_mutex_lock(&bm->buf_mtx);
    atomic_store_explicit(&bm->flush_sleeping, 1, memory_order_seq_cst);
    const uint64_t res2 = atomic_load_explicit(&bm->current_file_size, memory_order_acquire);
    if (!(fl < res2 && bm_done(bm, fl)) &&
        !(atomic_load_explicit(&bm->flush_stop, memory_order_acquire) && fl == res2))
    {
        struct timespec ts;
        bm_deadline(&ts, *park_us);
        pthread_cond_timedwait(&bm->buf_work_cv, &bm->buf_mtx, &ts);
        if (*park_us < BM_BUF_FLUSH_PARK_MAX_US) *park_us *= BM_BUF_FLUSH_PARK_GROWTH;
    }
    atomic_store_explicit(&bm->flush_sleeping, 0, memory_order_seq_cst);
    pthread_mutex_unlock(&bm->buf_mtx);
}

/* the single writer for a buffered block manager, draining completed runs from the ring to the fd
 * and parking when idle; appenders never wait on each other, they just set their done flag, so
 * there is no in-order release convoy under thread oversubscription and only this thread touches
 * the fd
 * @param arg the block manager, passed as void* per the pthread start-routine signature
 * @return always NULL; exits when flush_stop is set and the ring is drained, or on a flush error
 */
void *bm_flush_thread(void *arg)
{
    block_manager_t *bm = (block_manager_t *)arg;
    long park_us = BM_BUF_FLUSH_PARK_US;
    for (;;)
    {
        /* exit on any flagged error -- this thread's own or one the oversized-record path set after
         * a failed direct write; otherwise a gap left at the frontier would stall the join at close
         */
        if (atomic_load_explicit(&bm->flush_error, memory_order_acquire)) break;

        const int drained = bm_flush_drain(bm);
        if (drained < 0) break;
        if (drained > 0)
        {
            park_us = BM_BUF_FLUSH_PARK_US; /* work arrived, go back to reacting immediately */
            continue;
        }

        /* nothing completed at the frontier, so exit if stopped and fully drained, else wait */
        const uint64_t fl = atomic_load_explicit(&bm->buf_flushed, memory_order_relaxed);
        const uint64_t reserved =
            atomic_load_explicit(&bm->current_file_size, memory_order_acquire);
        if (atomic_load_explicit(&bm->flush_stop, memory_order_acquire) && fl == reserved) break;
        bm_flush_park(bm, &park_us);
    }

    pthread_mutex_lock(&bm->buf_mtx);
    pthread_cond_broadcast(&bm->buf_durable_cv);
    pthread_mutex_unlock(&bm->buf_mtx);
    return NULL;
}

/**
 * bm_wait_flushed
 * block until the flush thread has advanced buf_flushed to at least need. serves both durability (a
 * committer waiting for its record to reach the fd) and ring backpressure (an appender waiting for
 * a slot to free). spins briefly, then parks on buf_durable_cv with a timeout as a missed-signal
 * net.
 * @param bm the block manager
 * @param need the flushed offset to wait for
 * @return 0 once buf_flushed >= need, -1 if the flush thread reported an I/O error
 */
int bm_wait_flushed(block_manager_t *bm, uint64_t need)
{
    if (atomic_load_explicit(&bm->buf_flushed, memory_order_acquire) >= need) return 0;

    for (int s = 0; s < BM_BUF_SPIN; s++)
    {
        if (atomic_load_explicit(&bm->buf_flushed, memory_order_acquire) >= need) return 0;
        if (atomic_load_explicit(&bm->flush_error, memory_order_acquire)) return -1;
        bm_cpu_relax();
    }
    pthread_mutex_lock(&bm->buf_mtx);
    atomic_fetch_add_explicit(&bm->durable_waiters, 1, memory_order_acq_rel);
    while (atomic_load_explicit(&bm->buf_flushed, memory_order_acquire) < need &&
           !atomic_load_explicit(&bm->flush_error, memory_order_acquire))
    {
        struct timespec ts;
        bm_deadline(&ts, BM_BUF_WAIT_PARK_US);
        pthread_cond_timedwait(&bm->buf_durable_cv, &bm->buf_mtx, &ts);
    }
    atomic_fetch_sub_explicit(&bm->durable_waiters, 1, memory_order_acq_rel);
    pthread_mutex_unlock(&bm->buf_mtx);
    return atomic_load_explicit(&bm->flush_error, memory_order_acquire) ? -1 : 0;
}

/**
 * bm_wake_flush
 * signal the flush thread if it is parked, so it promptly picks up newly released work. the
 * seq_cst load of flush_sleeping is StoreLoad-ordered against the appender's done_ring release so a
 * wake is never lost against the flush thread's park decision.
 * @param bm the block manager
 */
static inline void bm_wake_flush(block_manager_t *bm)
{
    if (atomic_load_explicit(&bm->flush_sleeping, memory_order_seq_cst))
    {
        pthread_mutex_lock(&bm->buf_mtx);
        pthread_cond_signal(&bm->buf_work_cv);
        pthread_mutex_unlock(&bm->buf_mtx);
    }
}

/**
 * bm_buffered_append
 * append path for a buffered block manager. reserves a file offset lock-free (current_file_size
 * fetch-add), waits for ring space if the slot is still unflushed (backpressure), copies the framed
 * block into the ring in parallel with other appenders, and sets its done_ring flag -- it does not
 * pwrite, the flush thread does. a record larger than the whole ring takes the oversized path,
 * becoming the flush frontier and writing itself straight to the file.
 * @param bm the block manager
 * @param data the payload to frame and append
 * @param size the payload size in bytes
 * @param wake non-zero to signal the flush thread after staging, which a batch defers to its last
 * record so one batch costs one signal rather than one per record
 * @return the reserved file offset the record was written at, or -1 on a flush I/O error
 */
static int64_t bm_buffered_append(block_manager_t *bm, const void *data, const uint32_t size,
                                  int wake)
{
    const size_t total = BLOCK_MANAGER_BLOCK_HEADER_SIZE + (size_t)size + BLOCK_MANAGER_FOOTER_SIZE;
    const uint64_t R = bm->ring_size;
    const uint32_t checksum = compute_checksum(data, size);

    const uint64_t off = atomic_fetch_add(&bm->current_file_size, total);
    const uint64_t end = off + total;

    /* extend the on-disk extent here rather than on the flush thread, so the write it later issues
     * lands inside an allocated region instead of growing the file. an extending write takes the
     * inode's write lock exclusively and journals the new size, which puts the log's small append
     * behind whatever else is using the filesystem's journal */
    maybe_extend_allocation(bm, end);

    unsigned char header[BLOCK_MANAGER_BLOCK_HEADER_SIZE];
    unsigned char footer[BLOCK_MANAGER_FOOTER_SIZE];
    bm_encode_frame(header, footer, size, checksum);

    /* a record larger than the whole ring cannot be staged -- it would wrap onto itself. wait to
     * become the flush frontier (buf_flushed == off means every prior record is written and the
     * flush thread is parked at off), pwrite the framed record straight to the file, then publish
     * the advanced flushed watermark directly. backpressure holds every later appender until
     * publication, so none reuses a ring slot this span aliases. rare -- only oversized commit
     * batches.
     */
    if (total > R)
    {
        if (bm_wait_flushed(bm, off) != 0) return -1;

        struct iovec iov[BLOCK_MANAGER_IOVECS_PER_BLOCK];
        iov[0].iov_base = header;
        iov[0].iov_len = BLOCK_MANAGER_BLOCK_HEADER_SIZE;
        iov[1].iov_base = (void *)(uintptr_t)data;
        iov[1].iov_len = size;
        iov[2].iov_base = footer;
        iov[2].iov_len = BLOCK_MANAGER_FOOTER_SIZE;
        int rc = tdb_pwritev_safe(bm->fd, iov, BLOCK_MANAGER_IOVECS_PER_BLOCK, (off_t)off) ==
                         (ssize_t)total
                     ? 0
                     : -1;
        if (rc == 0 && bm_sync_after_write(bm) != 0) rc = -1;
        if (rc != 0)
            bm_note_write_failure(bm);
        else
            atomic_store_explicit(&bm->buf_flushed, end, memory_order_release);
        bm_wake_flush(bm);
        pthread_mutex_lock(&bm->buf_mtx);
        pthread_cond_broadcast(&bm->buf_durable_cv);
        pthread_mutex_unlock(&bm->buf_mtx);
        return rc != 0 ? -1 : (int64_t)off;
    }

    /* backpressure prevents clobbering unflushed data -- this ring slot last held bytes
     * [off-R, end-R), so wait until they are flushed. a no-op on the first pass (end <= R). */
    if (end > R && bm_wait_flushed(bm, end - R) != 0) return -1;

    bm_ring_copy(bm->ring, R, off, header, BLOCK_MANAGER_BLOCK_HEADER_SIZE);
    bm_ring_copy(bm->ring, R, off + BLOCK_MANAGER_BLOCK_HEADER_SIZE, data, size);
    bm_ring_copy(bm->ring, R, off + BLOCK_MANAGER_BLOCK_HEADER_SIZE + size, footer,
                 BLOCK_MANAGER_FOOTER_SIZE);

    /* publish completion -- release-ordered so the flush thread, on seeing the flag, sees the whole
     * framed record. no waiting on other appenders; the flush thread advances over the contiguous
     * run of set flags itself. seq_cst pairs with the flush thread's sleeping-flag StoreLoad. */
    atomic_store_explicit(&bm->done_ring[off % R], (unsigned char)1, memory_order_seq_cst);
    if (wake) bm_wake_flush(bm);
    return (int64_t)off;
}

/**
 * bm_append_block
 * append one framed block [size][checksum][data][size][magic] at the atomically
 * reserved tail offset via a single pwritev. shared by block_write and write_raw
 * so the on-disk encoding lives in one place. data must be non-NULL and size
 * non-zero -- the caller validates (a zero size_field reads back as EOF).
 * @param bm the block manager
 * @param data the payload to frame and append
 * @param size the payload size in bytes
 * @return the offset written at, or -1 on failure
 */
static int64_t bm_append_block(block_manager_t *bm, const void *data, const uint32_t size)
{
    if (bm->buffered) return bm_buffered_append(bm, data, size, 1);

    const size_t total_size =
        BLOCK_MANAGER_BLOCK_HEADER_SIZE + (size_t)size + BLOCK_MANAGER_FOOTER_SIZE;
    const uint32_t checksum = compute_checksum(data, size);

    /* atomically reserve space, then extend preallocation so the pwrite stays in-place */
    const int64_t offset = (int64_t)atomic_fetch_add(&bm->current_file_size, total_size);
    maybe_extend_allocation(bm, (uint64_t)offset + total_size);

    unsigned char header[BLOCK_MANAGER_BLOCK_HEADER_SIZE];
    unsigned char footer[BLOCK_MANAGER_FOOTER_SIZE];
    bm_encode_frame(header, footer, size, checksum);

    /* header + data + footer in a single pwritev -- zero copy from data */
    struct iovec iov[BLOCK_MANAGER_IOVECS_PER_BLOCK];
    iov[0].iov_base = header;
    iov[0].iov_len = BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    iov[1].iov_base = (void *)(uintptr_t)data;
    iov[1].iov_len = size;
    iov[2].iov_base = footer;
    iov[2].iov_len = BLOCK_MANAGER_FOOTER_SIZE;

#ifdef TDB_FAULT_INJECTION
    if (block_manager_fault_intercept_barrier()) block_manager_fault_freeze(); /* never returns */
#endif
    const uint64_t started_us = tdb_monotonic_us();
    const ssize_t wrote =
        tdb_pwritev_safe(bm->fd, iov, BLOCK_MANAGER_IOVECS_PER_BLOCK, (off_t)offset);
    bm_note_io(bm, total_size, started_us);
    if (BM_UNLIKELY(wrote != (ssize_t)total_size)) return -1;

    /* with O_DSYNC the pwrite already synced; otherwise fall back to fdatasync */
    if (bm_sync_after_write(bm) != 0) return -1;

    return offset;
}

int64_t block_manager_block_write(block_manager_t *bm, block_manager_block_t *block)
{
    if (BM_UNLIKELY(!bm || !block)) return -1;

    /* block size is stored as uint32_t, thus enforced 4GB limit */
    if (BM_UNLIKELY(block->size > UINT32_MAX)) return -1;

    /* a zero-size block encodes size_field == 0, which every reader treats as EOF;
     * reject it so it can never truncate iteration (matches write_raw) */
    if (BM_UNLIKELY(block->size == 0)) return -1;

    /* guard size_t overflow of the framed total on 32-bit platforms */
    if (block->size > SIZE_MAX - BLOCK_MANAGER_BLOCK_HEADER_SIZE - BLOCK_MANAGER_FOOTER_SIZE)
        return -1;

    return bm_append_block(bm, block->data, (uint32_t)block->size);
}

int64_t block_manager_write_raw(block_manager_t *bm, const void *data, const uint32_t size)
{
    if (BM_UNLIKELY(!bm || !data || size == 0)) return -1;
    return bm_append_block(bm, data, size);
}

int64_t block_manager_block_write_durable(block_manager_t *bm, block_manager_block_t *block)
{
    const int64_t offset = block_manager_block_write(bm, block);
    if (offset < 0) return offset;

    /* staging returns once the bytes are in the ring, which is this process's memory -- wait for
     * the flush thread to carry the frontier past this record before reporting the append complete.
     * a no-op on the direct path, where the append already went through to the file */
    const uint64_t end = (uint64_t)offset + block_manager_framed_size((uint32_t)block->size);
    return block_manager_wait_durable(bm, end) == 0 ? offset : -1;
}

/* maximum iovecs per pwritev call, POSIX minimum is 16, Linux uses 1024 */
#ifndef BM_IOV_MAX
#define BM_IOV_MAX 1024
#endif

/**
 * bm_batch_total_size
 * sum the framed size of a batch, marking each null slot absent in offsets and counting the valid
 * blocks; returns the total framed bytes, or SIZE_MAX on an oversized block or a size overflow
 * @param blocks the batch, null entries permitted
 * @param count the number of entries
 * @param offsets per-entry output, set to -1 for a null entry here
 * @param valid_count out for the number of non-null blocks
 * @return total framed bytes, or SIZE_MAX on error
 */
static size_t bm_batch_total_size(block_manager_block_t **blocks, size_t count, int64_t *offsets,
                                  size_t *valid_count)
{
    size_t total = 0;
    size_t valid = 0;
    for (size_t i = 0; i < count; i++)
    {
        if (!blocks[i])
        {
            offsets[i] = -1;
            continue;
        }
        if (blocks[i]->size > UINT32_MAX) return SIZE_MAX;

        const size_t framed =
            BLOCK_MANAGER_BLOCK_HEADER_SIZE + blocks[i]->size + BLOCK_MANAGER_FOOTER_SIZE;
        if (framed > SIZE_MAX - total)
            return SIZE_MAX; /* guard the 32-bit running-total overflow */
        total += framed;
        valid++;
    }
    *valid_count = valid;
    return total;
}

/**
 * bm_batch_build_frames
 * frame every non-null block into meta_buf and build its three iovecs (header, data, footer),
 * assigning each block its file offset from base_offset; returns the number of iovecs produced
 * @param blocks the batch
 * @param count the number of entries
 * @param base_offset the file offset the batch was reserved at
 * @param meta_buf contiguous storage for the per-block header and footer bytes
 * @param iov the iovec array to fill, three per non-null block
 * @param offsets per-entry output receiving each block's assigned offset
 * @return the number of iovecs written into iov
 */
static size_t bm_batch_build_frames(block_manager_block_t **blocks, size_t count,
                                    int64_t base_offset, unsigned char *meta_buf, struct iovec *iov,
                                    int64_t *offsets)
{
    const size_t frame_meta = BLOCK_MANAGER_BLOCK_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE;
    int64_t current_offset = base_offset;
    size_t iov_idx = 0;
    size_t meta_idx = 0;

    for (size_t i = 0; i < count; i++)
    {
        if (!blocks[i]) continue;

        block_manager_block_t *block = blocks[i];
        offsets[i] = current_offset;

        unsigned char *hdr = meta_buf + meta_idx * frame_meta;
        unsigned char *ftr = hdr + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
        bm_encode_frame(hdr, ftr, (uint32_t)block->size,
                        compute_checksum(block->data, block->size));

        iov[iov_idx].iov_base = hdr;
        iov[iov_idx].iov_len = BLOCK_MANAGER_BLOCK_HEADER_SIZE;
        iov[iov_idx + 1].iov_base = block->data;
        iov[iov_idx + 1].iov_len = block->size;
        iov[iov_idx + 2].iov_base = ftr;
        iov[iov_idx + 2].iov_len = BLOCK_MANAGER_FOOTER_SIZE;

        iov_idx += BLOCK_MANAGER_IOVECS_PER_BLOCK;
        meta_idx++;
        current_offset += (int64_t)(frame_meta + block->size);
    }
    return iov_idx;
}

/**
 * bm_batch_writev
 * pwritev the built iovecs to the fd in BM_IOV_MAX-sized chunks, starting at base_offset; returns 0
 * on success and -1 on a short write
 * @param bm the block manager
 * @param iov the iovec array
 * @param iov_count the number of iovecs
 * @param base_offset the file offset the batch starts at
 */
static int bm_batch_writev(block_manager_t *bm, struct iovec *iov, size_t iov_count,
                           int64_t base_offset)
{
    size_t iov_done = 0;
    off_t write_offset = (off_t)base_offset;

    while (iov_done < iov_count)
    {
        int chunk = (int)(iov_count - iov_done);
        if (chunk > BM_IOV_MAX) chunk = BM_IOV_MAX;

        ssize_t expected = 0;
        for (int j = 0; j < chunk; j++) expected += (ssize_t)iov[iov_done + (size_t)j].iov_len;

#ifdef TDB_FAULT_INJECTION
        if (block_manager_fault_intercept_barrier())
            block_manager_fault_freeze(); /* never returns */
#endif
        const ssize_t written = tdb_pwritev_safe(bm->fd, iov + iov_done, chunk, write_offset);
        if (written != expected) return -1;

        write_offset += written;
        iov_done += (size_t)chunk;
    }
    return 0;
}

int block_manager_block_write_batch(block_manager_t *bm, block_manager_block_t **blocks,
                                    const size_t count, int64_t *offsets)
{
    if (BM_UNLIKELY(!bm || !blocks || count == 0 || !offsets)) return -1;

    /* in buffered mode the flush thread owns every pwrite, so a batch cannot reserve offsets and
     * write them itself -- it would interleave with the thread draining the ring and leave the
     * flushed frontier unable to advance past what it wrote. stage each record instead and let the
     * flush thread coalesce the contiguous run, which is the same single large write this path
     * would have issued */
    if (bm->buffered)
    {
        size_t staged = 0;
        for (size_t i = 0; i < count; i++)
        {
            if (!blocks[i])
            {
                offsets[i] = -1;
                continue;
            }
            if (blocks[i]->size > UINT32_MAX) return -1;
            const int64_t off =
                bm_buffered_append(bm, blocks[i]->data, (uint32_t)blocks[i]->size, 0);
            if (off < 0) return -1;
            offsets[i] = off;
            staged++;
        }
        /* one signal for the whole batch rather than one per record; the flush thread coalesces the
         * staged run into the single large write this path would otherwise have issued itself */
        if (staged > 0) bm_wake_flush(bm);
        return (int)staged;
    }

    size_t valid_count = 0;
    const size_t total_batch_size = bm_batch_total_size(blocks, count, offsets, &valid_count);
    if (total_batch_size == SIZE_MAX) return -1;
    if (total_batch_size == 0) return 0;

    /* reserve the whole batch's space atomically, then extend preallocation to cover it */
    const int64_t base_offset = (int64_t)atomic_fetch_add(&bm->current_file_size, total_batch_size);
    maybe_extend_allocation(bm, (uint64_t)base_offset + total_batch_size);

    /* one allocation backs both the per-block header/footer bytes and the iovec array */
    const size_t meta_size =
        valid_count * (BLOCK_MANAGER_BLOCK_HEADER_SIZE + BLOCK_MANAGER_FOOTER_SIZE);
    const size_t iov_cap = valid_count * BLOCK_MANAGER_IOVECS_PER_BLOCK;
    unsigned char *alloc = malloc(meta_size + iov_cap * sizeof(struct iovec));
    if (!alloc) return -1;
    struct iovec *iov = (struct iovec *)(alloc + meta_size);

    const size_t iov_idx = bm_batch_build_frames(blocks, count, base_offset, alloc, iov, offsets);
    const int write_rc = bm_batch_writev(bm, iov, iov_idx, base_offset);
    free(alloc);
    if (write_rc != 0)
    {
        for (size_t i = 0; i < count; i++) offsets[i] = -1;
        return -1;
    }

    if (bm_sync_after_write(bm) != 0) return -1;

    return (int)valid_count;
}

int block_manager_write_at(block_manager_t *bm, const int64_t offset, const uint8_t *data,
                           const size_t size)
{
    if (!bm || !data || size == 0 || offset < 0) return -1;

    /* this only patches existing data -- a write past the tracked extent would
     * grow the file without advancing current_file_size, desyncing the two */
    if ((uint64_t)offset + size > atomic_load(&bm->current_file_size)) return -1;

    if (pwrite_all(bm->fd, data, size, offset) != 0)
    {
        return -1;
    }

    if (bm_sync_after_write(bm) != 0) return -1;

    return 0;
}

int block_manager_update_checksum(block_manager_t *bm, const int64_t block_offset)
{
    if (!bm || block_offset < 0) return -1;

    /* read block size from header */
    unsigned char size_buf[BLOCK_MANAGER_SIZE_FIELD_SIZE];
    if (pread(bm->fd, size_buf, BLOCK_MANAGER_SIZE_FIELD_SIZE, block_offset) !=
        BLOCK_MANAGER_SIZE_FIELD_SIZE)
    {
        return -1;
    }

    const uint32_t block_size = decode_uint32_le_compat(size_buf);
    if (block_size == 0) return -1;

    /* thread-local buffer avoids page faults from fresh malloc pages */
    uint8_t *data = bm_get_read_buf(block_size);
    if (!data) return -1;

    const off_t data_offset = block_offset + BLOCK_MANAGER_BLOCK_HEADER_SIZE;
    if (pread(bm->fd, data, block_size, data_offset) != (ssize_t)block_size)
    {
        return -1;
    }

    const uint32_t new_checksum = compute_checksum(data, block_size);

    unsigned char checksum_buf[BLOCK_MANAGER_CHECKSUM_LENGTH];
    encode_uint32_le_compat(checksum_buf, new_checksum);

    const off_t checksum_offset = block_offset + BLOCK_MANAGER_SIZE_FIELD_SIZE;
    if (pwrite_all(bm->fd, checksum_buf, BLOCK_MANAGER_CHECKSUM_LENGTH, checksum_offset) != 0)
    {
        return -1;
    }

    if (bm_sync_after_write(bm) != 0) return -1;

    return 0;
}

void block_manager_block_free(block_manager_block_t *block)
{
    if (!block) return;

    if (!block->inline_data && block->data) free(block->data);
    free(block);
}

int block_manager_wait_durable(block_manager_t *bm, const uint64_t offset)
{
    if (!bm) return -1;
    if (!bm->buffered) return 0; /* direct path is already durable per its sync mode */
    return bm_wait_flushed(bm, offset);
}
