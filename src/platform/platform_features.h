/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_FEATURES_H__
#define __PLATFORM_FEATURES_H__

#if defined(__MINGW32__) || defined(__MINGW64__)
#define TDB_SIZE_FMT     "%llu"
#define TDB_U64_FMT      "%llu"
#define TDB_SIZE_CAST(x) ((unsigned long long)(x))
#define TDB_U64_CAST(x)  ((unsigned long long)(x))
#else
#define TDB_SIZE_FMT     "%zu"
#define TDB_U64_FMT      "%" PRIu64
#define TDB_SIZE_CAST(x) ((size_t)(x))
#define TDB_U64_CAST(x)  ((uint64_t)(x))
#endif

/* cross-platform atomic alignment */
#if defined(_MSC_VER)
#define ATOMIC_ALIGN(n) __declspec(align(n))
#elif defined(__GNUC__) || defined(__clang__)
#define ATOMIC_ALIGN(n) __attribute__((aligned(n)))
#else
#define ATOMIC_ALIGN(n)
#endif

/* cross-platform unused attribute for static functions */
#if defined(__GNUC__) || defined(__clang__)
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

/* cross-platform thread-local storage */
#if defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define THREAD_LOCAL __thread
#else
#define THREAD_LOCAL /* fallback -- no thread-local support */
#endif

/* cross-platform prefetch hints for cache optimization */
#if defined(__GNUC__) || defined(__clang__)
/* __builtin_prefetch(addr, rw, locality)
 * rw -- 0 = read, 1 = write
 * locality-- 0 = no temporal locality, 3 = high temporal locality */
#define PREFETCH_READ(addr)  __builtin_prefetch((addr), 0, 3)
#define PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)
#elif defined(_MSC_VER)
#include <intrin.h>
#define PREFETCH_READ(addr)  _mm_prefetch((const char *)(addr), _MM_HINT_T0)
#define PREFETCH_WRITE(addr) _mm_prefetch((const char *)(addr), _MM_HINT_T0)
#else
/* no prefetch support -- define as no-op */
#define PREFETCH_READ(addr)  ((void)0)
#define PREFETCH_WRITE(addr) ((void)0)
#endif

/* cross-platform count trailing zeros for 64-bit integers */
#if defined(__GNUC__) || defined(__clang__)
#define TDB_CTZ64(x) __builtin_ctzll(x)
#elif defined(_MSC_VER)
/*
 * tdb_ctz64_msvc
 * counts trailing zeros in a 64-bit integer (MSVC version)
 * @param x the value to count trailing zeros in
 * @return number of trailing zero bits (0-63), or 64 if x is 0
 */
static inline int tdb_ctz64_msvc(uint64_t x)
{
    unsigned long index;
#if defined(_WIN64)
    if (_BitScanForward64(&index, x))
    {
        return (int)index;
    }
#else
    /* 32-bit MSVC-- check low and high 32-bit halves */
    if (_BitScanForward(&index, (unsigned long)x))
    {
        return (int)index;
    }
    if (_BitScanForward(&index, (unsigned long)(x >> 32)))
    {
        return (int)(index + 32);
    }
#endif
    return 64; /* all zeros */
}
#define TDB_CTZ64(x) tdb_ctz64_msvc(x)
#else
/* portable fallback using de Bruijn sequence */
/*
 * tdb_ctz64_portable
 * counts trailing zeros in a 64-bit integer (portable version)
 * @param x the value to count trailing zeros in
 * @return number of trailing zero bits (0-63), or 64 if x is 0
 */
static inline int tdb_ctz64_portable(uint64_t x)
{
    if (x == 0) return 64;
    static const int debruijn_table[64] = {
        0,  1,  2,  53, 3,  7,  54, 27, 4,  38, 41, 8,  34, 55, 48, 28, 62, 5,  39, 46, 44, 42,
        22, 9,  24, 35, 59, 56, 49, 18, 29, 11, 63, 52, 6,  26, 37, 40, 33, 47, 61, 45, 43, 21,
        23, 58, 17, 10, 51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12};
    return debruijn_table[((x & -x) * 0x022FDD63CC95386DULL) >> 58];
}
#define TDB_CTZ64(x) tdb_ctz64_portable(x)
#endif

/* cross-platform thread ID for unique file naming */
#if defined(_WIN32)
#include <windows.h>
#define TDB_THREAD_ID() ((unsigned long)GetCurrentThreadId())
#else
#include <pthread.h>
#define TDB_THREAD_ID() ((unsigned long)pthread_self())
#endif

/* cross-platform process ID */
#if defined(_WIN32)
#include <process.h>
#define TDB_GETPID() _getpid()
#else
#include <unistd.h>
#define TDB_GETPID() getpid()
#endif

#endif /* __PLATFORM_FEATURES_H__ */
