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

/* cross-platform printf-style checking for a variadic function that forwards its format onward.
 * it earns two things at once -- the call sites get their arguments checked against the format, and
 * the forwarding call inside stops being an unchecked non-literal format, which is what a compiler
 * otherwise has to warn about because it cannot see where the string came from */
#if defined(__MINGW32__) || defined(__MINGW64__)
/* mingw reads plain printf as the msvcrt one, which has no %zu, and would reject the formats this
 * codebase writes -- correctly for that runtime, but it is not the runtime in use. building to c11
 * turns mingw's own ansi stdio on, so the archetype naming it is the one that describes what
 * actually formats these strings */
#define TDB_PRINTF_FMT(fmt_index, first_arg) \
    __attribute__((format(gnu_printf, fmt_index, first_arg)))
#elif defined(__GNUC__) || defined(__clang__)
#define TDB_PRINTF_FMT(fmt_index, first_arg) __attribute__((format(printf, fmt_index, first_arg)))
#else
#define TDB_PRINTF_FMT(fmt_index, first_arg)
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

/* cross-platform count leading zeros for 64-bit integers. every variant defines a zero input as 64,
 * since the compiler builtin leaves it undefined and a caller asking how many leading bits two
 * equal words share should get the whole word rather than undefined behaviour */
#if defined(__GNUC__) || defined(__clang__)
#define TDB_CLZ64(x) ((x) == 0 ? 64 : __builtin_clzll(x))
#elif defined(_MSC_VER)
/*
 * tdb_clz64_msvc
 * counts leading zeros in a 64-bit integer (MSVC version)
 * @param x the value to count leading zeros in
 * @return number of leading zero bits (0-63), or 64 if x is 0
 */
static inline int tdb_clz64_msvc(uint64_t x)
{
    unsigned long index;
#if defined(_WIN64)
    if (_BitScanReverse64(&index, x))
    {
        return 63 - (int)index;
    }
#else
    /* 32-bit MSVC -- check the high half first, then the low */
    if (_BitScanReverse(&index, (unsigned long)(x >> 32)))
    {
        return 31 - (int)index;
    }
    if (_BitScanReverse(&index, (unsigned long)x))
    {
        return 63 - (int)index;
    }
#endif
    return 64; /* all zeros */
}
#define TDB_CLZ64(x) tdb_clz64_msvc(x)
#else
/*
 * tdb_clz64_portable
 * counts leading zeros in a 64-bit integer (portable version), halving the window each step
 * @param x the value to count leading zeros in
 * @return number of leading zero bits (0-63), or 64 if x is 0
 */
static inline int tdb_clz64_portable(uint64_t x)
{
    if (x == 0) return 64;
    int n = 0;
    if ((x >> 32) == 0)
    {
        n += 32;
        x <<= 32;
    }
    if ((x >> 48) == 0)
    {
        n += 16;
        x <<= 16;
    }
    if ((x >> 56) == 0)
    {
        n += 8;
        x <<= 8;
    }
    if ((x >> 60) == 0)
    {
        n += 4;
        x <<= 4;
    }
    if ((x >> 62) == 0)
    {
        n += 2;
        x <<= 2;
    }
    if ((x >> 63) == 0) n += 1;
    return n;
}
#define TDB_CLZ64(x) tdb_clz64_portable(x)
#endif

/* cross-platform population count for 64-bit integers */
#if defined(__GNUC__) || defined(__clang__)
#define TDB_POPCOUNT64(x) __builtin_popcountll(x)
#else
/*
 * tdb_popcount64_portable
 * counts the set bits in a 64-bit integer by summing them in parallel, pairs then nibbles then
 * bytes, which is also what MSVC is given since its intrinsic needs a cpu feature check
 * @param x the value to count the set bits of
 * @return the number of set bits, 0 to 64
 */
static inline int tdb_popcount64_portable(uint64_t x)
{
    x = x - ((x >> 1) & UINT64_C(0x5555555555555555));
    x = (x & UINT64_C(0x3333333333333333)) + ((x >> 2) & UINT64_C(0x3333333333333333));
    x = (x + (x >> 4)) & UINT64_C(0x0F0F0F0F0F0F0F0F);
    return (int)((x * UINT64_C(0x0101010101010101)) >> 56);
}
#define TDB_POPCOUNT64(x) tdb_popcount64_portable(x)
#endif

/* whether a condition variable can be pinned to the monotonic clock with
 * pthread_condattr_setclock, the posix clock selection option. where it can, a timed wait cannot be
 * stretched by a wall clock step -- an ntp correction, or a hypervisor resuming a guest it had
 * suspended -- which otherwise parks every waiter until an absolute time that has moved away from
 * them. macos does not carry the option, so there a condvar and its deadlines stay on the realtime
 * clock and at least agree with each other */
#if defined(__linux__) || defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__) || defined(__sun)
#define TDB_COND_CLOCK_SELECTABLE 1
#else
#define TDB_COND_CLOCK_SELECTABLE 0
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
