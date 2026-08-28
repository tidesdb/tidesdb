/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_WINDOWS_PRELUDE_H__
#define __PLATFORM_WINDOWS_PRELUDE_H__

#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#include <windows.h>

/* ===== the posix types msvc has none of its own =====
 *
 * first in the file, ahead of everything that names one. this header is first among the windows
 * headers for exactly this reason, and the io below is written against these three, so declaring
 * them further down leaves the io block naming types that do not exist yet. mingw takes none of
 * this -- its own headers supply all three -- so the order only ever fails on msvc, and it fails on
 * the first function that returns an ssize_t.
 *
 * the _DEFINED guards are msvc's own, so a later system header that declares one of these agrees
 * with what is here rather than clashing with it. max_align_t has no such guard, being C11 rather
 * than a msvc type, so it carries one of ours */
#if defined(_MSC_VER)
#ifndef _OFF_T_DEFINED
#define _OFF_T_DEFINED
typedef __int64 off_t;
#endif

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef __int64 ssize_t;
#endif

#ifndef _MODE_T_DEFINED
#define _MODE_T_DEFINED
typedef int mode_t;
#endif

/* the strictest alignment any scalar type needs, which C11 puts in stddef.h and msvc declares only
 * for c++. the union names the three candidates for the widest, and asking its alignment gives the
 * same answer the type would */
#ifndef TDB_MAX_ALIGN_T_DEFINED
#define TDB_MAX_ALIGN_T_DEFINED
typedef union
{
    long double ld;
    void *p;
    long long ll;
} max_align_t;
#endif
#endif

/* ===== shared Win32 file io =====
 *
 * pread, pwrite, fsync and fdatasync are pure Win32 -- overlapped ReadFile/WriteFile and
 * FlushFileBuffers -- with nothing that differs between the toolchains, so they live here once
 * rather than once per toolchain. they were duplicated for a while, and the copies drifted: the
 * mingw fsync returned -1 without setting errno, so a caller reading errno after a failed sync got
 * whatever was there before. this is the version that sets it.
 *
 * placed after the includes above and after the type block, which together are everything they
 * need. the type block is the half that is easy to forget, since only msvc reads it and only the
 * signatures here name what it declares. */

/* fsync for windows */
/*
 * fsync
 * @param fd the file descriptor to sync
 * @return 0 on success, -1 on failure
 */
static inline int fsync(int fd)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return -1;
    }
    if (!FlushFileBuffers(h))
    {
        errno = GetLastError();
        return -1;
    }
    return 0;
}

/* fdatasync for MSVC, same as fsync (windows doesn't distinguish) */
/*
 * fdatasync
 * @param fd the file descriptor to sync
 * @return 0 on success, -1 on failure
 */
static inline int fdatasync(int fd)
{
    return fsync(fd);
}

/* pread/pwrite for MSVC using OVERLAPPED
 */
/*
 * pread
 * reads data from a file descriptor at a specific offset
 * @param fd the file descriptor to read from
 * @param buf the buffer to read into
 * @param count the number of bytes to read
 * @param offset the offset to read from
 * @return the number of bytes read, or -1 on error
 */
static inline ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    if (count == 0)
    {
        return 0; /* reading 0 bytes is valid, returns 0 */
    }

    if (!buf)
    {
        errno = EINVAL;
        return -1;
    }

    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return -1;
    }

    OVERLAPPED overlapped;
    ZeroMemory(&overlapped, sizeof(OVERLAPPED));

    LARGE_INTEGER li;
    li.QuadPart = offset;
    overlapped.Offset = li.LowPart;
    overlapped.OffsetHigh = li.HighPart;

    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (overlapped.hEvent == NULL)
    {
        errno = GetLastError();
        return -1;
    }

    DWORD bytes_read = 0;
    BOOL result = ReadFile(h, buf, (DWORD)count, &bytes_read, &overlapped);

    if (!result)
    {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
            if (!GetOverlappedResult(h, &overlapped, &bytes_read, TRUE))
            {
                CloseHandle(overlapped.hEvent);
                errno = GetLastError();
                return -1;
            }
        }
        else
        {
            CloseHandle(overlapped.hEvent);
            errno = err;
            return -1;
        }
    }

    CloseHandle(overlapped.hEvent);
    return (ssize_t)bytes_read;
}

/*
 * pwrite
 * writes data to a file descriptor at a specific offset
 * @param fd the file descriptor to write to
 * @param buf the buffer to write from
 * @param count the number of bytes to write
 * @param offset the offset to write at
 * @return the number of bytes written, or -1 on error
 */
static inline ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    if (count == 0)
    {
        return 0; /* writing 0 bytes is valid, returns 0 */
    }

    if (!buf)
    {
        errno = EINVAL;
        return -1;
    }

    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return -1;
    }

    OVERLAPPED overlapped;
    ZeroMemory(&overlapped, sizeof(OVERLAPPED));

    LARGE_INTEGER li;
    li.QuadPart = offset;
    overlapped.Offset = li.LowPart;
    overlapped.OffsetHigh = li.HighPart;

    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (overlapped.hEvent == NULL)
    {
        errno = GetLastError();
        return -1;
    }

    DWORD bytes_written = 0;
    BOOL result = WriteFile(h, buf, (DWORD)count, &bytes_written, &overlapped);

    if (!result)
    {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING)
        {
            if (!GetOverlappedResult(h, &overlapped, &bytes_written, TRUE))
            {
                CloseHandle(overlapped.hEvent);
                errno = GetLastError();
                return -1;
            }
        }
        else
        {
            CloseHandle(overlapped.hEvent);
            errno = err;
            return -1;
        }
    }

    CloseHandle(overlapped.hEvent);
    return (ssize_t)bytes_written;
}

#if defined(_MSC_VER)
#pragma warning(disable : 4996) /* disable deprecated warning for windows */
#pragma warning(disable : 4029) /* declared formal parameter list different from definition */
#pragma warning(disable : 4211) /* nonstandard extension used-- redefined extern to static */
#endif

#if defined(__MINGW32__) || defined(__MINGW64__)
/* mingw provides POSIX-like headers */
#include <dirent.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>

/* mingw mkdir only takes one argument, create a wrapper for POSIX compatibility */
#define mkdir(path, mode) _mkdir(path)
#else
/* msvc uses the native Win32 threading backend defined further below (search for "native Win32
 * threading backend"), so it needs no pthreads-win32 library. time.h provides struct timespec and
 * struct tm. */
#include <time.h>

/* struct timeval (used by gettimeofday) lives in winsock. windows.h pulls winsock in normally but
 * not under WIN32_LEAN_AND_MEAN (e.g. the mariadb build). only define it ourselves when winsock is
 * not in the translation unit-- newer SDK winsock.h guards the file with _WINSOCKAPI_ and does not
 * set the inner _TIMEVAL_DEFINED, so a bare _TIMEVAL_DEFINED check would redefine it when winsock
 * is present. */
#if !defined(_TIMEVAL_DEFINED) && !defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
#define _TIMEVAL_DEFINED
struct timeval
{
    long tv_sec;
    long tv_usec;
};
#endif
#endif

#if defined(_MSC_VER)
/* ftruncate for windows */
/*
 * ftruncate
 * @param fd the file descriptor to truncate
 * @param length the new length of the file
 * @return 0 on success, -1 on failure
 */
static inline int ftruncate(int fd, off_t length)
{
    return _chsize_s(fd, length);
}

/**
 * _tidesdb_open_wrapper_3
 * the windows substitute for posix open, opening shared-for-read-and-write and in binary mode so a
 * byte written is the byte stored
 * @param path the path to open
 * @param flags the flags to use
 * @param mode the mode to use, consulted only when O_CREAT is set
 * @return the file descriptor on success, -1 on failure
 */
static inline int _tidesdb_open_wrapper_3(const char *path, int flags, mode_t mode)
{
    return _sopen(path, flags | _O_BINARY | _O_SEQUENTIAL, _SH_DENYNO, mode);
}

/* every open in this codebase passes a mode, so the macro forwards to the three-argument form
 * alone. dispatching on the argument count would need token pasting, which the code rules exclude,
 * so a two-argument open fails to compile here rather than silently losing its mode -- pass 0 for
 * the mode when the flags do not include O_CREAT */
#define open(...) _tidesdb_open_wrapper_3(__VA_ARGS__)

/* C11 atomics support */
#if defined(__MINGW32__) || defined(__GNUC__)
/* mingw and GCC have proper C11 stdatomic.h support */
#include <stdatomic.h>
#elif _MSC_VER < 1930
/* MSVC < 2022 doesn't have stdatomic.h -- use Windows Interlocked functions */
typedef volatile LONG atomic_int;
typedef volatile LONGLONG atomic_size_t;
typedef volatile LONGLONG atomic_uint64_t;
#define _Atomic(T) volatile T

#ifdef _WIN64
/* 64-bit atomic store */
/*
 * atomic_store_explicit
 * @param ptr the pointer to store the value at
 * @param val the value to store
 * @param order the memory order (unused)
 */
#define atomic_store_explicit(ptr, val, order)                                             \
    do                                                                                     \
    {                                                                                      \
        if (sizeof(*(ptr)) == sizeof(void *))                                              \
        {                                                                                  \
            InterlockedExchangePointer((PVOID volatile *)(ptr), (PVOID)(uintptr_t)(val));  \
        }                                                                                  \
        else if (sizeof(*(ptr)) == 8)                                                      \
        {                                                                                  \
            InterlockedExchange64((LONGLONG volatile *)(ptr), (LONGLONG)(uintptr_t)(val)); \
        }                                                                                  \
        else if (sizeof(*(ptr)) == 4)                                                      \
        {                                                                                  \
            InterlockedExchange((LONG volatile *)(ptr), (LONG)(uintptr_t)(val));           \
        }                                                                                  \
        else                                                                               \
        {                                                                                  \
            *(ptr) = (val);                                                                \
        }                                                                                  \
    } while (0)
#else
/* 32-bit atomic store */
/*
 * atomic_store_explicit
 * @param ptr the pointer to store the value at
 * @param val the value to store
 * @param order the memory order (unused)
 */
#define atomic_store_explicit(ptr, val, order)                                            \
    do                                                                                    \
    {                                                                                     \
        if (sizeof(*(ptr)) == sizeof(void *))                                             \
        {                                                                                 \
            InterlockedExchangePointer((PVOID volatile *)(ptr), (PVOID)(uintptr_t)(val)); \
        }                                                                                 \
        else if (sizeof(*(ptr)) == 8)                                                     \
        {                                                                                 \
            /* 64-bit value on a 32-bit target cast straight to LONGLONG, not via         \
             * uintptr_t (4 bytes here) which would truncate the input */                 \
            InterlockedExchange64((LONGLONG volatile *)(ptr), (LONGLONG)(val));           \
        }                                                                                 \
        else if (sizeof(*(ptr)) == 4)                                                     \
        {                                                                                 \
            InterlockedExchange((LONG volatile *)(ptr), (LONG)(uintptr_t)(val));          \
        }                                                                                 \
        else                                                                              \
        {                                                                                 \
            *(ptr) = (val);                                                               \
        }                                                                                 \
    } while (0)
#endif

/* atomic load */
/*
 * _atomic_load_ptr
 * @param ptr the pointer to load the value from
 * @return the value loaded from the pointer
 */
static inline void *_atomic_load_ptr(volatile void *const *ptr)
{
    return (void *)InterlockedCompareExchangePointer((PVOID volatile *)ptr, NULL, NULL);
}

/* atomic load -- available on both _WIN64 and 32-bit (InterlockedCompareExchange64
 * is provided on 32-bit Windows too, so 64-bit atomics work on a 32-bit target) */
/*
 * _atomic_load_i64
 * @param ptr the pointer to load the value from
 * @return the value loaded from the pointer
 */
static inline LONGLONG _atomic_load_i64(volatile LONGLONG *ptr)
{
    return InterlockedCompareExchange64((LONGLONG volatile *)ptr, 0, 0);
}

/* atomic load */
/*
 * _atomic_load_i32
 * @param ptr the pointer to load the value from
 * @return the value loaded from the pointer
 */
static inline LONG _atomic_load_i32(volatile LONG *ptr)
{
    return InterlockedCompareExchange((LONG volatile *)ptr, 0, 0);
}

/* atomic load */
/*
 * _atomic_load_u8
 * @param ptr the pointer to load the value from
 * @return the value loaded from the pointer
 */
static inline unsigned char _atomic_load_u8(volatile unsigned char *ptr)
{
    return *ptr; /* byte reads are atomic on x86/x64 */
}

#ifdef _WIN64
/* atomic load */
/*
 * atomic_load_explicit
 * @param ptr the pointer to load the value from
 * @param order the memory order (unused)
 * @return the value loaded from the pointer
 */
#define atomic_load_explicit(ptr, order)                                                     \
    (sizeof(*(ptr)) == sizeof(void *) ? _atomic_load_ptr((volatile void *const *)(ptr))      \
     : sizeof(*(ptr)) == 8 ? (void *)(uintptr_t)_atomic_load_i64((volatile LONGLONG *)(ptr)) \
     : sizeof(*(ptr)) == 4 ? (void *)(uintptr_t)_atomic_load_i32((volatile LONG *)(ptr))     \
                           : (void *)(uintptr_t)_atomic_load_u8((volatile unsigned char *)(ptr)))
#else
/* atomic load */
/*
 * atomic_load_explicit
 * @param ptr the pointer to load the value from
 * @param order the memory order (unused)
 * @return the value loaded from the pointer
 */
/* NOTE (32-bit MSVC < 2022) this path returns unsigned long long, not void*, so a
 * 64-bit atomic (sizeof==8, e.g. atomic_uint64_t / atomic_size_t) is loaded at full
 * width -- routing it through (void*)(uintptr_t) as the _WIN64 path does would truncate
 * to 32 bits here. Pointer and 32-bit values widen losslessly. A caller assigning the
 * result to a pointer gets an integer->pointer conversion (cast as needed).
 * This whole 32-bit MSVC<2022 atomics path must be compiled and tested on the target. */
#define atomic_load_explicit(ptr, order)                                                      \
    (sizeof(*(ptr)) == sizeof(void *)                                                         \
         ? (unsigned long long)(uintptr_t)_atomic_load_ptr((volatile void *const *)(ptr))     \
     : sizeof(*(ptr)) == 8 ? (unsigned long long)_atomic_load_i64((volatile LONGLONG *)(ptr)) \
     : sizeof(*(ptr)) == 4                                                                    \
         ? (unsigned long long)(uintptr_t)_atomic_load_i32((volatile LONG *)(ptr))            \
         : (unsigned long long)_atomic_load_u8((volatile unsigned char *)(ptr)))
#endif

/* atomic exchange */
#ifdef _WIN64
/* atomic exchange */
/*
 * atomic_exchange_explicit
 * @param ptr the pointer to exchange the value at
 * @param val the value to exchange
 * @param order the memory order (unused)
 * @return the value exchanged from the pointer
 */
#define atomic_exchange_explicit(ptr, val, order)                                       \
    (sizeof(*(ptr)) == sizeof(void *)                                                   \
         ? InterlockedExchangePointer((PVOID volatile *)(ptr), (PVOID)(uintptr_t)(val)) \
     : sizeof(*(ptr)) == 8                                                              \
         ? (void *)(uintptr_t)InterlockedExchange64((LONGLONG volatile *)(ptr),         \
                                                    (LONGLONG)(uintptr_t)(val))         \
         : (void *)(uintptr_t)InterlockedExchange((LONG volatile *)(ptr), (LONG)(uintptr_t)(val)))
#else
/* atomic exchange */
/*
 * atomic_exchange_explicit
 * @param ptr the pointer to exchange the value at
 * @param val the value to exchange
 * @param order the memory order (unused)
 * @return the value exchanged from the pointer
 */
/* NOTE (32-bit MSVC < 2022) returns unsigned long long for the same reason as
 * atomic_load_explicit above -- the 8-byte arm must not truncate. Verify on target. */
#define atomic_exchange_explicit(ptr, val, order)                                                  \
    (sizeof(*(ptr)) == sizeof(void *) ? (unsigned long long)(uintptr_t)InterlockedExchangePointer( \
                                            (PVOID volatile *)(ptr), (PVOID)(uintptr_t)(val))      \
     : sizeof(*(ptr)) == 8                                                                         \
         ? (unsigned long long)InterlockedExchange64((LONGLONG volatile *)(ptr), (LONGLONG)(val))  \
         : (unsigned long long)(uintptr_t)InterlockedExchange((LONG volatile *)(ptr),              \
                                                              (LONG)(uintptr_t)(val)))
#endif

#ifdef _WIN64
/* atomic fetch add */
/*
 * atomic_fetch_add
 * @param ptr the pointer to add the value to
 * @param val the value to add
 * @return the value before the addition
 */
#define atomic_fetch_add(ptr, val) \
    InterlockedExchangeAdd64((LONGLONG volatile *)(ptr), (LONGLONG)(val))
#else
/* atomic fetch add */
/*
 * atomic_fetch_add
 * @param ptr the pointer to add the value to
 * @param val the value to add
 * @return the value before the addition
 */
/* 32-bit dispatch on width so an 8-byte counter (atomic_uint64_t / atomic_size_t)
 * uses the 64-bit intrinsic instead of truncating to LONG. Returns unsigned long long. */
#define atomic_fetch_add(ptr, val)                                                    \
    (sizeof(*(ptr)) == 8 ? (unsigned long long)InterlockedExchangeAdd64(              \
                               (LONGLONG volatile *)(ptr), (LONGLONG)(val))           \
                         : (unsigned long long)(unsigned long)InterlockedExchangeAdd( \
                               (LONG volatile *)(ptr), (LONG)(val)))
#endif

/* atomic store */
/*
 * atomic_store
 * @param ptr the pointer to store the value at
 * @param val the value to store
 */
#define atomic_store(ptr, val) atomic_store_explicit(ptr, val, memory_order_seq_cst)
/* atomic load */
/*
 * atomic_load
 * @param ptr the pointer to load the value from
 * @return the value loaded from the pointer
 */
#define atomic_load(ptr)       atomic_load_explicit(ptr, memory_order_seq_cst)
#define memory_order_relaxed   0
#define memory_order_acquire   1
#define memory_order_release   2
#define memory_order_seq_cst   3

/* atomic compare exchange for pointers (MSVC compatibility) */
/*
 * atomic_compare_exchange_strong_ptr
 * @param ptr pointer to atomic pointer
 * @param expected pointer to expected value
 * @param desired new value to store
 * @return 1 if successful, 0 if failed
 */
static inline int atomic_compare_exchange_strong_ptr(void *volatile *ptr, void **expected,
                                                     void *desired)
{
    void *old =
        InterlockedCompareExchangePointer((PVOID volatile *)ptr, (PVOID)desired, (PVOID)*expected);
    if (old == *expected)
    {
        return 1;
    }
    *expected = old;
    return 0;
}

#endif /* _MSC_VER < 1930 */

/* access flags are normally defined in unistd.h, which unavailable under MSVC
 *
 * instead, define the flags as documented at
 * https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/access-waccess */
#ifndef F_OK
#define F_OK 00
#endif
#ifndef W_OK
#define W_OK 02
#endif
#ifndef R_OK
#define R_OK 04
#endif
#endif

#ifndef O_RDWR
#define O_RDWR _O_RDWR
#endif
#ifndef O_CREAT
#define O_CREAT _O_CREAT
#endif
#ifndef O_RDONLY
#define O_RDONLY _O_RDONLY
#endif
#ifndef O_WRONLY
#define O_WRONLY _O_WRONLY
#endif
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
#ifndef O_SEQUENTIAL
#define O_SEQUENTIAL _O_SEQUENTIAL
#endif

#ifndef M_LN2
#define M_LN2 0.69314718055994530942 /* log_e 2 */
#endif

#endif /* __PLATFORM_WINDOWS_PRELUDE_H__ */
