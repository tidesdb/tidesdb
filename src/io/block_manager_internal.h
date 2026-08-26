/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __BLOCK_MANAGER_INTERNAL_H__
#define __BLOCK_MANAGER_INTERNAL_H__
/* shared internal surface for the block_manager translation units -- the on-disk framing constants,
 * the small hot helpers every unit inlines, and the prototypes for helpers one unit defines and
 * another calls. nothing here is part of the public api. */
#include "io/block_manager.h"
#include "xxhash.h"
#ifdef TDB_FAULT_INJECTION
#include "io/block_manager_fault.h" /* the pwrite_all crash-recovery test hook */
#endif

#define BM_UNLIKELY(x) TDB_UNLIKELY(x)
#define BM_LIKELY(x)   TDB_LIKELY(x)

/* thread-local reusable pread buffer initial capacity, to avoid page faults on every block read */
#define BM_READ_BUF_INITIAL_SIZE (128 * 1024)

/* payload bytes fetched together with the block header in the first pread when the caller names no
 * size. a block whose payload fits inside it is read in one syscall; a larger one pays a second
 * pread for the remainder. it is deliberately small rather than generous, because the blocks that
 * dominate by count -- internal nodes, footers, manifest records -- are small, and a larger hint
 * makes every one of them copy bytes it will not read to save a syscall on the rarer large block. a
 * caller that already knows its payload size passes it instead and gets one syscall at any size,
 * which is what the value log and the btree node read do; this value only governs the callers that
 * cannot know. */
#define BM_READ_HINT_BYTES (4u * 1024u)

/* a block at or below this size is read without consulting the memory budget, covering every data
 * block and the common small footer block so the hot read path is just integer compares. blocks
 * larger than this (a multi-hundred-MB bloom filter on a huge bottom-level sstable) are rare and
 * only there is the budget tested, itself a relaxed atomic load rather than a syscall. */
#define BM_LARGE_BLOCK_BUDGET_CHECK_THRESHOLD (256u * 1024u * 1024u)

/* nanosecond conversion factors for the cond-var deadline math */
#define BM_NS_PER_US  1000L
#define BM_NS_PER_SEC 1000000000L

/* buffered-append staging ring sizing, shared because core sizes the ring at open and write fills
 * it. the default is the ring a buffered open reserves; the floor is the smallest ring allowed,
 * with larger single records taking the oversized direct path instead */
#define BM_BUF_DEFAULT_RING (8ull * 1024 * 1024)
#define BM_BUF_MIN_RING     (1ull * 1024 * 1024)

/* memory-safety budget for a single block read in bytes, pushed down from the tidesdb layer via
 * block_manager_set_max_safe_block_bytes and refreshed by the reaper. 0 means no budget configured,
 * so the size-vs-EOF check still applies but no memory-based refusal happens. defined in
 * block_manager_util.c. */
extern _Atomic(uint64_t) bm_max_safe_block_bytes;

/**
 * compute_checksum
 * compute a block's checksum, the low 32 bits of XXH3. the field on disk is four bytes, and XXH3
 * fills it several times faster than XXH32 does on a 64-bit host -- which matters because this runs
 * over every byte read back, not just every byte written, so a scan streaming separated values pays
 * it per value. truncating a 64-bit hash keeps the collision behaviour of the wider function over
 * the bits that are kept
 */
static inline uint32_t compute_checksum(const void *data, const size_t size)
{
    return (uint32_t)XXH3_64bits(data, size);
}

/**
 * verify_checksum
 * verify size bytes of data against expected_checksum, returning 0 on a match and -1 otherwise
 */
static inline int verify_checksum(const void *data, const size_t size,
                                  const uint32_t expected_checksum)
{
    return (compute_checksum(data, size) == expected_checksum) ? 0 : -1;
}

/**
 * bm_encode_frame
 * encode a block's framing, the header as [size][checksum] and the footer as [size][magic], so the
 * on-disk block layout is defined in exactly one place across every write path
 */
static inline void bm_encode_frame(unsigned char *header, unsigned char *footer, uint32_t size,
                                   uint32_t checksum)
{
    encode_uint32_le_compat(header, size);
    encode_uint32_le_compat(header + BLOCK_MANAGER_SIZE_FIELD_SIZE, checksum);
    encode_uint32_le_compat(footer, size);
    encode_uint32_le_compat(footer + BLOCK_MANAGER_CHECKSUM_LENGTH, BLOCK_MANAGER_FOOTER_MAGIC);
}

/**
 * odsync_available
 * whether O_DSYNC is available on this platform, so an opened-with-O_DSYNC write is already durable
 */
static inline int odsync_available(void)
{
    return O_DSYNC != 0;
}

/**
 * is_sync_full
 * whether this block manager fsyncs every write; the flag is cached atomically so a runtime
 * sync-mode change cannot race the read on the write path
 */
static inline int is_sync_full(const block_manager_t *bm)
{
    return atomic_load_explicit(&bm->sync_full_cached, memory_order_relaxed);
}

/**
 * pwrite_all
 * write exactly nbyte bytes at offset, retrying short writes and EINTR, returning 0 on success and
 * -1 on error with errno set; a bare pwrite treats a short write as a hard error, but a large
 * write_raw can legitimately come up short under a signal
 */
static inline int pwrite_all(int fd, const void *buf, size_t nbyte, off_t offset)
{
#ifdef TDB_FAULT_INJECTION
    const int fault_mode = block_manager_fault_intercept(&nbyte);
    if (fault_mode == 2) block_manager_fault_freeze(); /* crashed already, never returns */
#endif
    size_t total = 0;
    while (total < nbyte)
    {
        const ssize_t written =
            pwrite(fd, (const uint8_t *)buf + total, nbyte - total, offset + (off_t)total);
        if (BM_UNLIKELY(written < 0))
        {
            if (errno == EINTR) continue;
            return -1;
        }
        if (BM_UNLIKELY(written == 0))
        {
            errno = EIO;
            return -1;
        }
        total += (size_t)written;
    }
#ifdef TDB_FAULT_INJECTION
    if (fault_mode == 1) block_manager_fault_freeze(); /* torn write done, freeze; never returns */
#endif
    return 0;
}

/**
 * bm_sync_after_write
 * make a just-written range durable when the block manager fsyncs every write, skipping the
 * fdatasync when O_DSYNC already made the write durable; returns 0 on success and -1 on error
 */
static inline int bm_sync_after_write(block_manager_t *bm)
{
    if (is_sync_full(bm) && !odsync_available()) return fdatasync(bm->fd) == 0 ? 0 : -1;
    return 0;
}

/**
 * bm_sync_after_truncate
 * make a truncation durable when the block manager fsyncs every write; unlike a write this always
 * fdatasyncs under sync-full because O_DSYNC does not cover ftruncate. returns 0 or -1 on error
 */
static inline int bm_sync_after_truncate(block_manager_t *bm)
{
    if (is_sync_full(bm)) return fdatasync(bm->fd) == 0 ? 0 : -1;
    return 0;
}

/**
 * bm_cpu_relax
 * emit a cpu pause/yield hint inside a spin loop so a hyperthread sibling makes progress and the
 * spin draws less power; a no-op on architectures without such a hint
 */
static inline void bm_cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ __volatile__("yield");
#endif
}

/**
 * bm_deadline
 * fill ts with an absolute CLOCK_REALTIME deadline us microseconds from now, for cond_timedwait
 */
static inline void bm_deadline(struct timespec *ts, long us)
{
    clock_gettime(CLOCK_REALTIME, ts);
    ts->tv_nsec += us * BM_NS_PER_US;
    if (ts->tv_nsec >= BM_NS_PER_SEC)
    {
        ts->tv_sec += ts->tv_nsec / BM_NS_PER_SEC;
        ts->tv_nsec %= BM_NS_PER_SEC;
    }
}

/* ===== helpers one translation unit defines and another calls ===== */

/* util -- the calling thread's reusable read buffer, grown to at least needed bytes (see the
 * definition in block_manager_util.c); realloc preserves existing bytes across a grow */
uint8_t *bm_get_read_buf(size_t needed);

/* core -- write the file header at offset 0, returning 0 on success and -1 otherwise */
int write_header(int fd);

/* core -- read the tracked file size, returning 0 on success and -1 otherwise */
int get_file_size(int fd, uint64_t *size);

/* core -- reopen the backing fd, honoring the sync mode, returning 0 on success and -1 otherwise */
int reopen_fd(block_manager_t *bm);

/* core -- truncate the file back to just the header and reset the in-memory watermarks */
int truncate_to_header(block_manager_t *bm);

/* core -- extend the on-disk preallocation when a new reservation nears the current extent */
void maybe_extend_allocation(block_manager_t *bm, uint64_t reservation_end);

/* write -- acquire a pooled staging ring for buffered append, or allocate one on a pool miss */
int bm_buf_pool_acquire(uint64_t ring_size, uint8_t **ring, _Atomic unsigned char **done_ring);

/* write -- return a staging ring and its completion flags to the pool, or free them on overflow */
void bm_buf_pool_release(uint8_t *ring, _Atomic unsigned char *done_ring, uint64_t ring_size);

/* write -- the single flush thread that owns every pwrite in buffered append mode */
void *bm_flush_thread(void *arg);

/* write -- block until the flush thread has written up to need, so a caller escalating to fsync can
 * first make sure the bytes it means to sync have left the staging ring */
int bm_wait_flushed(block_manager_t *bm, uint64_t need);

/* cursor -- read one block at offset into the thread-local buffer, verifying its checksum;
 * check_budget consults the per-read memory budget for outsized blocks */
uint8_t *bm_read_block_tls(int fd, uint64_t offset, uint64_t extent_limit, int check_budget,
                           uint32_t payload_hint, uint32_t *out_size);

#endif /* __BLOCK_MANAGER_INTERNAL_H__ */