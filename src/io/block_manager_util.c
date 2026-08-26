/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "block_manager_internal.h"

_Atomic(uint64_t) bm_max_safe_block_bytes = 0;

/**
 *
 *  * * * * * * * * * *
 * FILE FORMAT        *
 *  * * * * * * * * * *
 *
 *  * * * * * * * * * *
 * HEADER             *
 *  * * * * * * * * * *
 * magic (3 bytes) 0x544442 "TDB" -- see BLOCK_MANAGER_MAGIC
 * version (1 byte) -- see BLOCK_MANAGER_VERSION
 * padding (4 bytes) reserved
 *
 *  * * * * * * * * * *
 * BLOCKS             *
 *  * * * * * * * * * *
 * block_size (4 bytes) -- size of data (uint32_t, supports up to 4GB)
 * checksum (4 bytes) -- the low 32 bits of XXH3 over data, see compute_checksum
 * data (variable size) -- actual block data
 * footer_size (4 bytes) -- duplicate of block_size for validation
 * footer_magic (4 bytes) -- 0x42445442 "BTDB" for fast validation
 *
 *  * * * * * * * * * *
 * CONCURRENCY MODEL *
 *  * * * * * * * * * *
 * single file descriptor shared by all operations
 * pread/pwrite for lock-free reads (readers don't block readers or writers)
 * atomic offset allocation for lock-free writes
 * writers don't block writers, concurrent writes to different offsets
 * readers never block, they can read while writes happen
 */

static pthread_key_t bm_tls_key;

static pthread_once_t bm_tls_once = PTHREAD_ONCE_INIT;

/**
 * bm_tls_read_buf_t
 * per-thread reusable read buffer (see bm_get_read_buf)
 * @param buf the buffer, grown on demand and freed on thread exit
 * @param capacity allocated size of buf in bytes
 */
typedef struct
{
    uint8_t *buf;
    size_t capacity;
} bm_tls_read_buf_t;

void block_manager_set_max_safe_block_bytes(uint64_t bytes)
{
    atomic_store_explicit(&bm_max_safe_block_bytes, bytes, memory_order_relaxed);
}

/**
 * bm_tls_destructor
 * frees a thread's read buffer when the thread exits
 * @param ptr the thread-local bm_tls_read_buf_t
 */
static void bm_tls_destructor(void *ptr)
{
    if (ptr)
    {
        bm_tls_read_buf_t *tls = (bm_tls_read_buf_t *)ptr;
        free(tls->buf);
        free(tls);
    }
}

/**
 * bm_tls_init_key
 * one-time creation of the thread-local read-buffer key
 */
static void bm_tls_init_key(void)
{
    pthread_key_create(&bm_tls_key, bm_tls_destructor);
}

/**
 * bm_get_read_buf
 * returns the calling thread's reusable read buffer, growing it (capacity doubling)
 * to hold at least needed bytes. avoids a fresh malloc and its page faults on every
 * read. the grow uses realloc, so bytes already in the buffer are preserved -- callers
 * rely on this to keep an already-read header across a grow for the payload remainder.
 * @param needed minimum buffer size in bytes
 * @return the buffer, or NULL on allocation failure
 */
uint8_t *bm_get_read_buf(const size_t needed)
{
    pthread_once(&bm_tls_once, bm_tls_init_key);

    bm_tls_read_buf_t *tls = (bm_tls_read_buf_t *)pthread_getspecific(bm_tls_key);
    if (!tls)
    {
        tls = (bm_tls_read_buf_t *)calloc(1, sizeof(bm_tls_read_buf_t));
        if (!tls) return NULL;
        pthread_setspecific(bm_tls_key, tls);
    }

    if (BM_LIKELY(needed <= tls->capacity)) return tls->buf;

    size_t new_size = tls->capacity ? tls->capacity : BM_READ_BUF_INITIAL_SIZE;
    while (new_size < needed) new_size *= 2;

    uint8_t *new_buf = (uint8_t *)realloc(tls->buf, new_size);
    if (!new_buf) return NULL;

    tls->buf = new_buf;
    tls->capacity = new_size;
    return new_buf;
}

uint32_t block_manager_checksum(const void *data, const size_t size)
{
    return compute_checksum(data, size);
}
