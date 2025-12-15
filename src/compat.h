/**
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
#ifndef __COMPAT_H__
#define __COMPAT_H__

/* compat header for multi-platform support (Windows, POSIX, posix includes macOS) */
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>

/* fallback for SIZE_MAX, just in case */
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

/* cross-platform strdup abstraction */
#if defined(_MSC_VER)
#define tdb_strdup(s) _strdup(s)
#else
#define tdb_strdup(s) strdup(s)
#endif

/* cross-platform localtime abstraction */
#if defined(_WIN32)
/* (MSVC and MinGW) use localtime_s with reversed parameter order */
#define tdb_localtime(timer, result) localtime_s((result), (timer))
#else
/* POSIX uses localtime_r */
#define tdb_localtime(timer, result) localtime_r((timer), (result))
#endif

/* https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stat-functions?view=msvc-170
 * https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/fstat-fstat32-fstat64-fstati64-fstat32i64-fstat64i32?view=msvc-170
 * to handle the compiler differences
 */
#if defined(_WIN32)
#include <sys/stat.h>
#include <sys/types.h>

#if defined(_MSC_VER)
#define STAT_STRUCT _stat64
#define STAT_FUNC   _stat64
#define FSTAT_FUNC  _fstat64
#else
#define STAT_STRUCT stat
#define STAT_FUNC   stat
#define FSTAT_FUNC  fstat
#endif

#else /* posix */
#include <sys/stat.h>
#include <sys/statvfs.h>
#define STAT_STRUCT stat
#define STAT_FUNC   stat
#define FSTAT_FUNC  fstat
#endif

#if !defined(_MSC_VER) || _MSC_VER >= 1930
#include <stdatomic.h>
typedef atomic_size_t atomic_size_t;
typedef atomic_uint_fast64_t atomic_uint64_t;
#endif

#if defined(__MINGW32__) || defined(__MINGW64__)
#define TDB_SIZE_FMT     "%llu"
#define TDB_U64_FMT      "%llu"
#define TDB_SIZE_CAST(x) ((unsigned long long)(x))
#define TDB_U64_CAST(x)  ((unsigned long long)(x))
#else
#define TDB_SIZE_FMT     "%zu"
#define TDB_U64_FMT      "%llu"
#define TDB_SIZE_CAST(x) ((size_t)(x))
#define TDB_U64_CAST(x)  ((unsigned long long)(x))
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
#define THREAD_LOCAL /* fallback: no thread-local support */
#endif

/* cross-platform prefetch hints for cache optimization */
#if defined(__GNUC__) || defined(__clang__)
/* __builtin_prefetch(addr, rw, locality)
 * rw: 0 = read, 1 = write
 * locality: 0 = no temporal locality, 3 = high temporal locality */
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

#ifdef _WIN32
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>

#if defined(_MSC_VER)
#pragma warning(disable : 4996) /* disable deprecated warning for windows */
#pragma warning(disable : 4029) /* declared formal parameter list different from definition */
#pragma warning(disable : 4211) /* nonstandard extension used: redefined extern to static */
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
/* msvc needs pthreads-win32 library */
#include "pthread.h"
#endif

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

/* open for windows */
/*
 * open
 * @param path the path to open
 * @param flags the flags to use
 * @param mode the mode to use (only used if O_CREAT is set)
 * @return the file descriptor on success, -1 on failure
 */
static inline int _tidesdb_open_wrapper_3(const char *path, int flags, mode_t mode)
{
    return _open(path, flags | _O_BINARY | _O_SEQUENTIAL, mode);
}

/* open for windows */
/*
 * open
 * @param path the path to open
 * @param flags the flags to use
 * @return the file descriptor on success, -1 on failure
 */
static inline int _tidesdb_open_wrapper_2(const char *path, int flags)
{
    return _open(path, flags | _O_BINARY, 0);
}
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

#ifdef _WIN64
/* atomic load */
/*
 * _atomic_load_i64
 * @param ptr the pointer to load the value from
 * @return the value loaded from the pointer
 */
static inline LONGLONG _atomic_load_i64(volatile LONGLONG *ptr)
{
    return InterlockedCompareExchange64((LONGLONG volatile *)ptr, 0, 0);
}
#endif

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
#define atomic_load_explicit(ptr, order)                                                            \
    (sizeof(*(ptr)) == sizeof(void *) ? _atomic_load_ptr((volatile void *const *)(ptr))             \
     : sizeof(*(ptr)) == 4            ? (void *)(uintptr_t)_atomic_load_i32((volatile LONG *)(ptr)) \
                           : (void *)(uintptr_t)_atomic_load_u8((volatile unsigned char *)(ptr)))
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
#define atomic_exchange_explicit(ptr, val, order)                                       \
    (sizeof(*(ptr)) == sizeof(void *)                                                   \
         ? InterlockedExchangePointer((PVOID volatile *)(ptr), (PVOID)(uintptr_t)(val)) \
         : (void *)(uintptr_t)InterlockedExchange((LONG volatile *)(ptr), (LONG)(uintptr_t)(val)))
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
#define atomic_fetch_add(ptr, val) InterlockedExchangeAdd((LONG volatile *)(ptr), (LONG)(val))
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

#if defined(_MSC_VER)
#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1

struct timezone
{
    int tz_minuteswest;
    int tz_dsttime;
};

struct dirent
{
    char d_name[MAX_PATH];
};

typedef struct
{
    HANDLE hFind;
    WIN32_FIND_DATA findFileData;
    struct dirent dirent;
} DIR;

/* mkdir */
/*
 * mkdir
 * @param path the path to create the directory at
 * @param mode the mode to create the directory with (unused on windows)
 * @return 0 on success, -1 on failure
 */
static inline int mkdir(const char *path, mode_t mode)
{
    (void)mode; /* unused on windows */
    return _mkdir(path);
}

/* opendir */
/*
 * opendir
 * @param name the name of the directory to open
 * @return a pointer to the directory stream, or NULL on failure
 */
static inline DIR *opendir(const char *name)
{
    DIR *dir = (DIR *)malloc(sizeof(DIR));
    if (dir == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", name);
    dir->hFind = FindFirstFile(search_path, &dir->findFileData);
    if (dir->hFind == INVALID_HANDLE_VALUE)
    {
        free(dir);
        return NULL;
    }
    return dir;
}

/* readdir */
/*
 * readdir
 * @param dir the directory stream to read from
 * @return a pointer to the next directory entry, or NULL on failure
 */
static inline struct dirent *readdir(DIR *dir)
{
    if (dir == NULL || dir->hFind == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }
    if (dir->findFileData.cFileName[0] == '\0')
    {
        if (!FindNextFile(dir->hFind, &dir->findFileData))
        {
            return NULL;
        }
    }
    strncpy(dir->dirent.d_name, dir->findFileData.cFileName, MAX_PATH);
    dir->findFileData.cFileName[0] = '\0'; /* reset */
    return &dir->dirent;
}

/* closedir */
/*
 * closedir
 * @param dir the directory stream to close
 * @return 0 on success, -1 on failure
 */
static inline int closedir(DIR *dir)
{
    if (dir == NULL)
    {
        return -1;
    }
    if (dir->hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(dir->hFind);
    }
    free(dir);
    return 0;
}

typedef struct
{
    HANDLE handle;
} sem_t;

/* sem_init */
/*
 * sem_init
 * @param sem the semaphore to initialize
 * @param pshared whether the semaphore is shared between processes (unused on windows)
 * @param value the initial value of the semaphore
 * @return 0 on success, -1 on failure
 */
static inline int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    (void)pshared;
    sem->handle = CreateSemaphore(NULL, value, LONG_MAX, NULL);
    if (sem->handle == NULL)
    {
        errno = GetLastError();
        return -1;
    }
    return 0;
}

/* sem_destroy */
/*
 * sem_destroy
 * @param sem the semaphore to destroy
 * @return 0 on success, -1 on failure
 */
static inline int sem_destroy(sem_t *sem)
{
    if (sem->handle != NULL)
    {
        CloseHandle(sem->handle);
        sem->handle = NULL;
    }
    return 0;
}

/* sem_wait */
/*
 * sem_wait
 * @param sem the semaphore to wait on
 * @return 0 on success, -1 on failure
 */
static inline int sem_wait(sem_t *sem)
{
    DWORD result = WaitForSingleObject(sem->handle, INFINITE);
    return (result == WAIT_OBJECT_0) ? 0 : -1;
}

/* sem_post */
/*
 * sem_post
 * @param sem the semaphore to post
 * @return 0 on success, -1 on failure
 */
static inline int sem_post(sem_t *sem)
{
    return ReleaseSemaphore(sem->handle, 1, NULL) ? 0 : -1;
}

/* file operations macros for cross-platform compatibility */
#ifndef S_ISDIR
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#endif
#define sleep(seconds)       Sleep((seconds)*1000)
#define usleep(microseconds) Sleep((microseconds) / 1000) /* usleep for Windows */
#define access               _access
#define ftell                _ftelli64
#define fseek                _fseeki64

/* fopen wrapper for windows */
/*
 * tdb_fopen
 * @param filename the filename to open
 * @param mode the mode to open the file in
 * @return a pointer to the opened file, or NULL on failure
 */
static inline FILE *tdb_fopen(const char *filename, const char *mode)
{
    FILE *fp = NULL;
    errno_t err = fopen_s(&fp, filename, mode);
    if (err != 0) return NULL;
    return fp;
}
#define fopen tdb_fopen

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

/* clock_gettime for MSVC */
/*
 * clock_gettime
 * @param clk_id the clock ID (unused)
 * @param tp the timespec struct to fill
 * @return 0 on success, -1 on failure
 */
static inline int clock_gettime(int clk_id, struct timespec *tp)
{
    (void)clk_id;
    FILETIME ft;
    ULARGE_INTEGER ui;

    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;

    /* convert 100-nanosecond intervals to seconds and nanoseconds */
    tp->tv_sec = (long)((ui.QuadPart - 116444736000000000ULL) / 10000000ULL);
    tp->tv_nsec = (long)((ui.QuadPart % 10000000ULL) * 100);

    return 0;
}

/* gettimeofday for MSVC */
/*
 * gettimeofday
 * @param tp the timeval struct to fill
 * @param tzp the timezone struct (unused)
 * @return 0 on success, -1 on failure
 */
static inline int gettimeofday(struct timeval *tp, struct timezone *tzp)
{
    (void)tzp;
    FILETIME ft;
    ULARGE_INTEGER ui;

    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;

    /* convert to microseconds */
    tp->tv_sec = (long)((ui.QuadPart - 116444736000000000ULL) / 10000000ULL);
    tp->tv_usec = (long)((ui.QuadPart % 10000000ULL) / 10);

    return 0;
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
    if (!buf || count == 0)
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
    overlapped.hEvent = NULL;

    DWORD bytes_read = 0;
    if (!ReadFile(h, buf, (DWORD)count, &bytes_read, &overlapped))
    {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING)
        {
            errno = err;
            return -1;
        }
    }

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
    if (!buf || count == 0)
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
    overlapped.hEvent = NULL;

    DWORD bytes_written = 0;
    if (!WriteFile(h, buf, (DWORD)count, &bytes_written, &overlapped))
    {
        DWORD err = GetLastError();

        if (err != ERROR_IO_PENDING)
        {
            errno = err;
            return -1;
        }
    }

    return (ssize_t)bytes_written;
}
#endif /* _MSC_VER */

/* fileno for all Windows (MSVC and MinGW) */
/*
 * tdb_fileno
 * portable file descriptor extraction from FILE*
 * @param stream the FILE* to get descriptor from
 * @return file descriptor, or -1 on failure
 */
static inline int tdb_fileno(FILE *stream)
{
    if (!stream) return -1;
    return _fileno(stream);
}

#if defined(__MINGW32__) || defined(__MINGW64__)
/* mingw provides semaphore.h for POSIX semaphores */
#include <semaphore.h>

/* mingw doesn't provide pread/pwrite/fdatasync, so we implement them */
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
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return -1;
    }

    OVERLAPPED overlapped = {0};
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

    DWORD bytes_read;
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
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return -1;
    }

    OVERLAPPED overlapped = {0};
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

    DWORD bytes_written;
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

/*
 * fsync
 * synchronizes file data to disk
 * @param fd the file descriptor to synchronize
 * @return 0 if successful, -1 otherwise
 */
static inline int fsync(int fd)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    return FlushFileBuffers(h) ? 0 : -1;
}

/*
 * fdatasync
 * synchronizes file data to disk
 * @param fd the file descriptor to synchronize
 * @return 0 if successful, -1 otherwise
 */
static inline int fdatasync(int fd)
{
    return fsync(fd);
}
#endif /* __MINGW32__ || __MINGW64__ */

#elif defined(__APPLE__)
#include <dirent.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

/* Grand Central Dispatch (dispatch/dispatch.h) is only available on macOS 10.6+
 * For older macOS versions (e.g., 10.5 PPC64), use POSIX semaphores instead */
#include <AvailabilityMacros.h>
#if MAC_OS_X_VERSION_MIN_REQUIRED >= 1060
#define TDB_USE_DISPATCH_SEMAPHORE 1
#include <dispatch/dispatch.h>
#else
#define TDB_USE_DISPATCH_SEMAPHORE 0
#include <semaphore.h>
#endif

/* pread and pwrite are available natively on macOS via unistd.h */
/* no additional implementation needed using system pread/pwrite */

/**
 * tdb_fileno
 * portable file descriptor extraction from FILE*
 * @param stream the FILE* to get descriptor from
 * @return file descriptor, or -1 on failure
 */
static inline int tdb_fileno(FILE *stream)
{
    if (!stream) return -1;
    return fileno(stream);
}

/*
 * fdatasync
 * synchronizes file data to disk
 * @param fd the file descriptor to synchronize
 * @return 0 if successful, -1 otherwise
 */
static inline int fdatasync(int fd)
{
#ifdef F_FULLFSYNC
    /* macOS requires F_FULLFSYNC to actually flush to disk */
    if (fcntl(fd, F_FULLFSYNC) == -1)
    {
        /* fall back to fsync if F_FULLFSYNC fails */
        return fsync(fd);
    }
    return 0;
#else
    /* fall back to fsync if F_FULLFSYNC not available */
    return fsync(fd);
#endif
}

#if TDB_USE_DISPATCH_SEMAPHORE
/* semaphore compatibility for macOS 10.6+ using Grand Central Dispatch
 * macOS deprecated POSIX semaphores (sem_init, sem_destroy, etc.)
 * use dispatch_semaphore instead */
typedef dispatch_semaphore_t sem_t;

/*
 * sem_init
 * initializes a semaphore
 * @param sem the semaphore to initialize
 * @param pshared whether the semaphore is shared between processes
 * @param value the initial value of the semaphore
 * @return 0 if successful, -1 otherwise
 */
static inline int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    (void)pshared; /* unused on macOS */
    *sem = dispatch_semaphore_create(value);
    return (*sem == NULL) ? -1 : 0;
}

/*
 * sem_destroy
 * destroys a semaphore
 * @param sem the semaphore to destroy
 * @return 0 if successful, -1 otherwise
 */
static inline int sem_destroy(sem_t *sem)
{
    if (*sem)
    {
        dispatch_release(*sem);
        *sem = NULL;
    }
    return 0;
}

/*
 * sem_wait
 * waits on a semaphore
 * @param sem the semaphore to wait on
 * @return 0 if successful, -1 otherwise
 */
static inline int sem_wait(sem_t *sem)
{
    return (dispatch_semaphore_wait(*sem, DISPATCH_TIME_FOREVER) == 0) ? 0 : -1;
}

/*
 * sem_post
 * posts a semaphore
 * @param sem the semaphore to post
 * @return 0 if successful, -1 otherwise
 */
static inline int sem_post(sem_t *sem)
{
    dispatch_semaphore_signal(*sem);
    return 0;
}
#else
/* for macOS < 10.6 (e.g., 10.5 PPC64), use POSIX semaphores
 * note: POSIX semaphores are deprecated on modern macOS but work on older versions */
/* sem_t, sem_init, sem_destroy, sem_wait, sem_post are provided by semaphore.h */
#endif

#else /* posix systems */
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/**
 * tdb_fileno
 * portable file descriptor extraction from FILE*
 * @param stream the FILE* to get descriptor from
 * @return file descriptor, or -1 on failure
 */
static inline int tdb_fileno(FILE *stream)
{
    if (!stream) return -1;
    return fileno(stream);
}

/* sysinfo is Linux-specific, BSD uses sysctl */
#if defined(__linux__)
#include <sys/sysinfo.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/sysctl.h>
#include <sys/types.h>
#elif defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <uvm/uvm_extern.h>
#endif

/* pread, pwrite, and fdatasync are available natively on POSIX systems via unistd.h */
/* no additional implementation needed using system pread/pwrite/fdatasync */

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
typedef pthread_mutex_t crit_section_t;
typedef pthread_rwlock_t rwlock_t;
#endif

/* atomic compare exchange for pointers (all platforms with C11 atomics) */
#if !defined(_MSC_VER) || _MSC_VER >= 1930
/*
 * atomic_compare_exchange_strong_ptr
 * @param ptr pointer to atomic pointer
 * @param expected pointer to expected value
 * @param desired new value to store
 * @return 1 if successful, 0 if failed
 */
static inline int atomic_compare_exchange_strong_ptr(_Atomic(void *) *ptr, void **expected,
                                                     void *desired)
{
    return atomic_compare_exchange_strong(ptr, expected, desired);
}
#endif

/*
 * get_available_memory
 * gets available system memory in bytes
 * @return available memory in bytes, or 0 on failure
 */
static inline size_t get_available_memory(void)
{
#ifdef _WIN32
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status))
    {
        return (size_t)status.ullAvailPhys;
    }
    return 0;
#elif defined(__APPLE__)
    vm_size_t page_size;
    mach_port_t mach_port;
    mach_msg_type_number_t count;

    mach_port = mach_host_self();

    /* use 32-bit vm statistics on PPC 32-bit regardless of OS version
     * host_statistics64 is not available on PPC 32-bit even on 10.6+ */
#if defined(__ppc__) || defined(__ppc)
    /* PPC 32-bit always uses 32-bit vm statistics */
    vm_statistics_data_t vm_stats;
    count = HOST_VM_INFO_COUNT;
    if (host_page_size(mach_port, &page_size) == KERN_SUCCESS &&
        host_statistics(mach_port, HOST_VM_INFO, (host_info_t)&vm_stats, &count) == KERN_SUCCESS)
    {
        return (size_t)(vm_stats.free_count * page_size);
    }
#else
    /* try 64-bit first (macOS 10.6+ on x86/x86_64/ARM), fall back to 32-bit */
    vm_statistics64_data_t vm_stats64;
    count = sizeof(vm_stats64) / sizeof(natural_t);
    if (host_page_size(mach_port, &page_size) == KERN_SUCCESS &&
        host_statistics64(mach_port, HOST_VM_INFO, (host_info64_t)&vm_stats64, &count) ==
            KERN_SUCCESS)
    {
        return (size_t)(vm_stats64.free_count * page_size);
    }
    else
    {
        /* fallback to 32-bit for older systems or Rosetta edge cases */
        vm_statistics_data_t vm_stats;
        count = HOST_VM_INFO_COUNT;
        if (host_page_size(mach_port, &page_size) == KERN_SUCCESS &&
            host_statistics(mach_port, HOST_VM_INFO, (host_info_t)&vm_stats, &count) ==
                KERN_SUCCESS)
        {
            return (size_t)(vm_stats.free_count * page_size);
        }
    }
#endif
    return 0;
#elif defined(__linux__)
    /* linux-specific sysinfo */
    struct sysinfo si;
    if (sysinfo(&si) == 0)
    {
        return (size_t)si.freeram * (size_t)si.mem_unit;
    }
    return 0;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    /* BSD systems use sysctl.. */
    unsigned long free_pages = 0;
    unsigned long page_size = 0;
    size_t len = sizeof(free_pages);

#if defined(__FreeBSD__) || defined(__DragonFly__)
    if (sysctlbyname("vm.stats.vm.v_free_count", &free_pages, &len, NULL, 0) == 0)
    {
        len = sizeof(page_size);
        if (sysctlbyname("vm.stats.vm.v_page_size", &page_size, &len, NULL, 0) == 0)
        {
            return (size_t)(free_pages * page_size);
        }
    }
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    int mib[2];
    struct uvmexp uvmexp;
    len = sizeof(uvmexp);

    mib[0] = CTL_VM;
    mib[1] = VM_UVMEXP;
    if (sysctl(mib, 2, &uvmexp, &len, NULL, 0) == 0)
    {
        return (size_t)((uint64_t)uvmexp.free * (uint64_t)uvmexp.pagesize);
    }
#endif
    return 0;
#else
    /* illumos/solaris and other POSIX systems */
    long pages = sysconf(_SC_AVPHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0)
    {
        return (size_t)(pages * page_size);
    }
    return 0;
#endif
}

/*
 * get_total_memory
 * gets total system memory in bytes
 * @return total memory in bytes, or 0 on failure
 */
static inline size_t get_total_memory(void)
{
#ifdef _WIN32
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status))
    {
        return (size_t)status.ullTotalPhys;
    }
    return 0;
#elif defined(__APPLE__)
    int mib[2];
    int64_t physical_memory;
    size_t length;

    mib[0] = CTL_HW;
    mib[1] = HW_MEMSIZE;
    length = sizeof(int64_t);
    if (sysctl(mib, 2, &physical_memory, &length, NULL, 0) == 0)
    {
        return (size_t)physical_memory;
    }
    return 0;
#elif defined(__linux__)
    struct sysinfo si;
    if (sysinfo(&si) == 0)
    {
        return (size_t)si.totalram * (size_t)si.mem_unit;
    }
    return 0;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
    int mib[2];
    size_t physical_memory;
    size_t len;

    mib[0] = CTL_HW;
#if defined(__OpenBSD__)
    mib[1] = HW_PHYSMEM64;
    int64_t physmem64;
    len = sizeof(physmem64);
    if (sysctl(mib, 2, &physmem64, &len, NULL, 0) == 0)
    {
        return (size_t)physmem64;
    }
#else
    mib[1] = HW_PHYSMEM;
    len = sizeof(physical_memory);
    if (sysctl(mib, 2, &physical_memory, &len, NULL, 0) == 0)
    {
        return physical_memory;
    }
#endif
    return 0;
#else
    /* illumos/solaris and other POSIX systems */
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0)
    {
        return (size_t)(pages * page_size);
    }
    return 0;
#endif
}

/*
 * get_file_mod_time
 * gets the modified time of a file
 * @param path the path of the file
 * @return the modified time of the file, or -1 on failure
 */
static inline time_t get_file_mod_time(const char *path)
{
    struct STAT_STRUCT file_stat;

    if (STAT_FUNC(path, &file_stat) != 0)
    {
        return -1;
    }

    return (time_t)file_stat.st_mtime;
}

/* cross-platform little-endian serialization functions */

/*
 * encode_uint16_le_compat
 * encodes a uint16_t value in little-endian format
 * @param buf buffer to store encoded value
 * @param val value to encode
 */
static inline void encode_uint16_le_compat(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
}

/*
 * decode_uint16_le_compat
 * decodes a uint16_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline uint16_t decode_uint16_le_compat(const uint8_t *buf)
{
    return ((uint16_t)buf[0]) | ((uint16_t)buf[1] << 8);
}

/*
 * encode_uint32_le_compat
 * encodes a uint32_t value in little-endian format
 * @param buf buffer to store encoded value
 * @param val value to encode
 */
static inline void encode_uint32_le_compat(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

/*
 * decode_uint32_le_compat
 * decodes a uint32_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline uint32_t decode_uint32_le_compat(const uint8_t *buf)
{
    return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

/*
 * encode_uint64_le_compat
 * encodes a uint64_t value in little-endian format
 * @param buf buffer to store encoded value
 * @param val value to encode
 */
static inline void encode_uint64_le_compat(uint8_t *buf, uint64_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
    buf[4] = (uint8_t)((val >> 32) & 0xFF);
    buf[5] = (uint8_t)((val >> 40) & 0xFF);
    buf[6] = (uint8_t)((val >> 48) & 0xFF);
    buf[7] = (uint8_t)((val >> 56) & 0xFF);
}

/*
 * encode_uint32_le
 * encodes a uint32_t value in little-endian format
 * @param buf buffer to store encoded value
 * @param val value to encode
 */
static inline void encode_uint32_le(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

/*
 * decode_uint32_le
 * decodes a uint32_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline uint32_t decode_uint32_le(const uint8_t *buf)
{
    return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

/*
 * encode_int64_le
 * encodes an int64_t value in little-endian format
 * @param buf buffer to store encoded value
 * @param val value to encode
 */
static inline void encode_int64_le(uint8_t *buf, int64_t val)
{
    uint64_t uval = (uint64_t)val;
    buf[0] = (uint8_t)(uval & 0xFF);
    buf[1] = (uint8_t)((uval >> 8) & 0xFF);
    buf[2] = (uint8_t)((uval >> 16) & 0xFF);
    buf[3] = (uint8_t)((uval >> 24) & 0xFF);
    buf[4] = (uint8_t)((uval >> 32) & 0xFF);
    buf[5] = (uint8_t)((uval >> 40) & 0xFF);
    buf[6] = (uint8_t)((uval >> 48) & 0xFF);
    buf[7] = (uint8_t)((uval >> 56) & 0xFF);
}

/*
 * decode_int64_le
 * decodes an int64_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline int64_t decode_int64_le(const uint8_t *buf)
{
    uint64_t uval = ((uint64_t)buf[0]) | ((uint64_t)buf[1] << 8) | ((uint64_t)buf[2] << 16) |
                    ((uint64_t)buf[3] << 24) | ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
                    ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
    return (int64_t)uval;
}

/*
 * encode_uint64_le
 * encodes a uint64_t value in little-endian format
 * @param buf buffer to store encoded value
 * @param val value to encode
 */
static inline void encode_uint64_le(uint8_t *buf, uint64_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
    buf[4] = (uint8_t)((val >> 32) & 0xFF);
    buf[5] = (uint8_t)((val >> 40) & 0xFF);
    buf[6] = (uint8_t)((val >> 48) & 0xFF);
    buf[7] = (uint8_t)((val >> 56) & 0xFF);
}

/*
 * decode_uint64_le
 * decodes a uint64_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline uint64_t decode_uint64_le(const uint8_t *buf)
{
    return ((uint64_t)buf[0]) | ((uint64_t)buf[1] << 8) | ((uint64_t)buf[2] << 16) |
           ((uint64_t)buf[3] << 24) | ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
}

/*
 * decode_fixed_32
 * decodes a uint32_t value in little-endian format
 * @param data buffer containing encoded value
 * @return decoded value
 */
static inline uint32_t decode_fixed_32(const char *data)
{
    return ((uint32_t)(uint8_t)data[0]) | ((uint32_t)(uint8_t)data[1] << 8) |
           ((uint32_t)(uint8_t)data[2] << 16) | ((uint32_t)(uint8_t)data[3] << 24);
}

/*
 * decode_uint64_le_compat
 * decodes a uint64_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline uint64_t decode_uint64_le_compat(const uint8_t *buf)
{
    return ((uint64_t)buf[0]) | ((uint64_t)buf[1] << 8) | ((uint64_t)buf[2] << 16) |
           ((uint64_t)buf[3] << 24) | ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
}

/**
 * encode_int64_le_compat
 * encodes a int64_t value in little-endian format
 * @param buf output buffer (must be at least 8 bytes)
 * @param val value to encode
 */
static inline void encode_int64_le_compat(uint8_t *buf, int64_t val)
{
    uint64_t uval = (uint64_t)val;
    buf[0] = (uint8_t)(uval);
    buf[1] = (uint8_t)(uval >> 8);
    buf[2] = (uint8_t)(uval >> 16);
    buf[3] = (uint8_t)(uval >> 24);
    buf[4] = (uint8_t)(uval >> 32);
    buf[5] = (uint8_t)(uval >> 40);
    buf[6] = (uint8_t)(uval >> 48);
    buf[7] = (uint8_t)(uval >> 56);
}

/**
 * decode_int64_le_compat
 * decodes a int64_t value in little-endian format
 * @param buf buffer containing encoded value
 * @return decoded value
 */
static inline int64_t decode_int64_le_compat(const uint8_t *buf)
{
    uint64_t uval = ((uint64_t)buf[0]) | ((uint64_t)buf[1] << 8) | ((uint64_t)buf[2] << 16) |
                    ((uint64_t)buf[3] << 24) | ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
                    ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
    return (int64_t)uval;
}

/* varint encoding/decoding for compact serialization */
static inline uint8_t *encode_varint32(uint8_t *ptr, uint32_t value)
{
    while (value >= 0x80)
    {
        *ptr++ = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    *ptr++ = (uint8_t)value;
    return ptr;
}

static inline uint8_t *encode_varint64(uint8_t *ptr, uint64_t value)
{
    while (value >= 0x80)
    {
        *ptr++ = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    *ptr++ = (uint8_t)value;
    return ptr;
}

static inline const uint8_t *decode_varint32(const uint8_t *ptr, uint32_t *value)
{
    uint32_t result = 0;
    int shift = 0;
    while (*ptr & 0x80)
    {
        /* prevent shift overflow on corrupted data */
        if (shift >= 32)
        {
            *value = 0;
            return ptr;
        }
        result |= (uint32_t)(*ptr & 0x7F) << shift;
        shift += 7;
        ptr++;
    }
    /* final byte check */
    if (shift >= 32)
    {
        *value = 0;
        return ptr;
    }
    result |= (uint32_t)(*ptr) << shift;
    *value = result;
    return ptr + 1;
}

static inline const uint8_t *decode_varint64(const uint8_t *ptr, uint64_t *value)
{
    uint64_t result = 0;
    int shift = 0;
    while (*ptr & 0x80)
    {
        /* prevent shift overflow on corrupted data */
        if (shift >= 64)
        {
            *value = 0;
            return ptr;
        }
        result |= (uint64_t)(*ptr & 0x7F) << shift;
        shift += 7;
        ptr++;
    }
    /* final byte check */
    if (shift >= 64)
    {
        *value = 0;
        return ptr;
    }
    result |= (uint64_t)(*ptr) << shift;
    *value = result;
    return ptr + 1;
}

/* length-prefixed KV serialization helpers */

/*
 * serialize_kv_varint
 * serialize key-value pair with varint length prefixes
 * format: varint(key_size) + key + varint(value_size) + value
 * @param ptr output buffer (must have enough space)
 * @param key key data
 * @param key_size key size
 * @param value value data (can be NULL if value_size is 0)
 * @param value_size value size
 * @return pointer to end of written data
 */
static inline uint8_t *serialize_kv_varint(uint8_t *ptr, const uint8_t *key, uint32_t key_size,
                                           const uint8_t *value, uint32_t value_size)
{
    /* write key size and key */
    ptr = encode_varint32(ptr, key_size);
    memcpy(ptr, key, key_size);
    ptr += key_size;

    /* write value size and value */
    ptr = encode_varint32(ptr, value_size);
    if (value_size > 0 && value)
    {
        memcpy(ptr, value, value_size);
        ptr += value_size;
    }

    return ptr;
}

/*
 * serialize_kv_varint_ex
 * serialize key-value pair with flags and varint length prefixes (for SSTables)
 * format: flags(1) + varint(key_size) + key + varint(value_size) + value + varint(ttl)
 * @param ptr output buffer (must have enough space)
 * @param flags flags byte (e.g., tombstone marker)
 * @param key key data
 * @param key_size key size
 * @param value value data (can be NULL if value_size is 0)
 * @param value_size value size
 * @param ttl time-to-live (0 = no expiration)
 * @return pointer to end of written data
 */
static inline uint8_t *serialize_kv_varint_ex(uint8_t *ptr, uint8_t flags, const uint8_t *key,
                                              uint32_t key_size, const uint8_t *value,
                                              uint32_t value_size, int64_t ttl)
{
    /* write flags */
    *ptr++ = flags;

    /* write key size and key */
    ptr = encode_varint32(ptr, key_size);
    memcpy(ptr, key, key_size);
    ptr += key_size;

    /* write value size and value */
    ptr = encode_varint32(ptr, value_size);
    if (value_size > 0 && value)
    {
        memcpy(ptr, value, value_size);
        ptr += value_size;
    }

    /* write ttl */
    ptr = encode_varint64(ptr, (uint64_t)ttl);

    return ptr;
}

/*
 * serialize_kv_varint_full
 * serialize key-value pair with all metadata (for WAL)
 * format: flags(1) + varint(key_size) + key + varint(value_size) + value + varint(ttl) +
 * varint(seq)
 * @param ptr output buffer (must have enough space)
 * @param flags flags byte
 * @param key key data
 * @param key_size key size
 * @param value value data (can be NULL if value_size is 0)
 * @param value_size value size
 * @param ttl time-to-live
 * @param seq sequence number
 * @return pointer to end of written data
 */
static inline uint8_t *serialize_kv_varint_full(uint8_t *ptr, uint8_t flags, const uint8_t *key,
                                                uint32_t key_size, const uint8_t *value,
                                                uint32_t value_size, int64_t ttl, uint64_t seq)
{
    /* write flags */
    *ptr++ = flags;

    /* write key size and key */
    ptr = encode_varint32(ptr, key_size);
    memcpy(ptr, key, key_size);
    ptr += key_size;

    /* write value size and value */
    ptr = encode_varint32(ptr, value_size);
    if (value_size > 0 && value)
    {
        memcpy(ptr, value, value_size);
        ptr += value_size;
    }

    /* write ttl and seq */
    ptr = encode_varint64(ptr, (uint64_t)ttl);
    ptr = encode_varint64(ptr, seq);

    return ptr;
}

/*
 * deserialize_kv_varint
 * deserialize key-value pair with varint length prefixes
 * @param ptr input buffer
 * @param end end of input buffer (for bounds checking)
 * @param key_size output key size
 * @param value_size output value size
 * @param key_out output pointer to key data (points into input buffer)
 * @param value_out output pointer to value data (points into input buffer)
 * @return pointer to next entry, or NULL on error
 */
static inline const uint8_t *deserialize_kv_varint(const uint8_t *ptr, const uint8_t *end,
                                                   uint32_t *key_size, uint32_t *value_size,
                                                   const uint8_t **key_out,
                                                   const uint8_t **value_out)
{
    /* read key size */
    if (ptr >= end) return NULL;
    ptr = decode_varint32(ptr, key_size);
    if (ptr + *key_size > end) return NULL;

    /* read key */
    *key_out = ptr;
    ptr += *key_size;

    /* read value size */
    if (ptr >= end) return NULL;
    ptr = decode_varint32(ptr, value_size);
    if (ptr + *value_size > end) return NULL;

    /* read value */
    *value_out = ptr;
    ptr += *value_size;

    return ptr;
}

/*
 * deserialize_kv_varint_ex
 * deserialize key-value pair with flags and varint length prefixes (for SSTables)
 * @param ptr input buffer
 * @param end end of input buffer (for bounds checking)
 * @param flags output flags byte
 * @param key_size output key size
 * @param value_size output value size
 * @param key_out output pointer to key data (points into input buffer)
 * @param value_out output pointer to value data (points into input buffer)
 * @param ttl output time-to-live
 * @return pointer to next entry, or NULL on error
 */
static inline const uint8_t *deserialize_kv_varint_ex(const uint8_t *ptr, const uint8_t *end,
                                                      uint8_t *flags, uint32_t *key_size,
                                                      uint32_t *value_size, const uint8_t **key_out,
                                                      const uint8_t **value_out, int64_t *ttl)
{
    /* read flags */
    if (ptr >= end) return NULL;
    *flags = *ptr++;

    /* read key size */
    if (ptr >= end) return NULL;
    ptr = decode_varint32(ptr, key_size);
    if (ptr + *key_size > end) return NULL;

    /* read key */
    *key_out = ptr;
    ptr += *key_size;

    /* read value size */
    if (ptr >= end) return NULL;
    ptr = decode_varint32(ptr, value_size);
    if (ptr + *value_size > end) return NULL;

    /* read value */
    *value_out = ptr;
    ptr += *value_size;

    /* read ttl */
    if (ptr >= end) return NULL;
    uint64_t ttl_u64;
    ptr = decode_varint64(ptr, &ttl_u64);
    *ttl = (int64_t)ttl_u64;

    return ptr;
}

/*
 * deserialize_kv_varint_full
 * deserialize key-value pair with all metadata (for WAL)
 * @param ptr input buffer
 * @param end end of input buffer (for bounds checking)
 * @param flags output flags byte
 * @param key_size output key size
 * @param value_size output value size
 * @param key_out output pointer to key data (points into input buffer)
 * @param value_out output pointer to value data (points into input buffer)
 * @param ttl output time-to-live
 * @param seq output sequence number
 * @return pointer to next entry, or NULL on error
 */
static inline const uint8_t *deserialize_kv_varint_full(const uint8_t *ptr, const uint8_t *end,
                                                        uint8_t *flags, uint32_t *key_size,
                                                        uint32_t *value_size,
                                                        const uint8_t **key_out,
                                                        const uint8_t **value_out, int64_t *ttl,
                                                        uint64_t *seq)
{
    /* read flags */
    if (ptr >= end) return NULL;
    *flags = *ptr++;

    /* read key size */
    if (ptr >= end) return NULL;
    ptr = decode_varint32(ptr, key_size);
    if (ptr + *key_size > end) return NULL;

    /* read key */
    *key_out = ptr;
    ptr += *key_size;

    /* read value size */
    if (ptr >= end) return NULL;
    ptr = decode_varint32(ptr, value_size);
    if (ptr + *value_size > end) return NULL;

    /* read value */
    *value_out = ptr;
    ptr += *value_size;

    /* read ttl and seq */
    if (ptr >= end) return NULL;
    uint64_t ttl_u64;
    ptr = decode_varint64(ptr, &ttl_u64);
    *ttl = (int64_t)ttl_u64;

    if (ptr >= end) return NULL;
    ptr = decode_varint64(ptr, seq);

    return ptr;
}

/*
 * set_file_sequential_hint
 * hints to the OS that file access will be sequential for read-ahead optimization
 * @param fd the file descriptor
 * @return 0 on success, -1 on failure (non-critical, can be ignored)
 */
static inline int set_file_sequential_hint(int fd)
{
#ifdef __linux__
    return posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#elif defined(__APPLE__)
    return fcntl(fd, F_RDAHEAD, 1);
#elif defined(_WIN32)
    /* _O_SEQUENTIAL flag set at open time via compat.h wrapper */
    (void)fd; /* unused on Windows */
    return 0;
#else
    (void)fd; /* unused on other platforms */
    return 0;
#endif
}

/**
 * tdb_get_available_disk_space
 * get available disk space for a given path
 * @param path the path to check
 * @param available pointer to store available bytes
 * @return 0 on success, -1 on failure
 */
static inline int tdb_get_available_disk_space(const char *path, uint64_t *available)
{
    if (!path || !available) return -1;

#if defined(_WIN32)
    ULARGE_INTEGER free_bytes;
    if (GetDiskFreeSpaceExA(path, &free_bytes, NULL, NULL))
    {
        *available = (uint64_t)free_bytes.QuadPart;
        return 0;
    }
    return -1;
#else
    struct statvfs stat;
    if (statvfs(path, &stat) == 0)
    {
        *available = (uint64_t)stat.f_bavail * (uint64_t)stat.f_frsize;
        return 0;
    }
    return -1;
#endif
}

/* cpu pause for spin-wait loops */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#ifdef _MSC_VER
#include <intrin.h>
#define cpu_pause() _mm_pause()
#else
#define cpu_pause() __builtin_ia32_pause()
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#ifdef _MSC_VER
#include <intrin.h>
#define cpu_pause() __yield()
#else
#define cpu_pause() __asm__ __volatile__("yield" ::: "memory")
#endif
#elif defined(__arm__) || defined(_M_ARM)
#ifdef _MSC_VER
#include <intrin.h>
#define cpu_pause() __yield()
#else
#define cpu_pause() __asm__ __volatile__("yield" ::: "memory")
#endif
#else
#define cpu_pause() ((void)0)
#endif

/* cpu yield for longer waits - gives up time slice to scheduler */
#ifdef _WIN32
#include <windows.h>
#define cpu_yield() SwitchToThread()
#else
#include <sched.h>
#define cpu_yield() sched_yield()
#endif

/*
 * tdb_unlink
 * portable file deletion
 * @param path the file path to delete
 * @return 0 on success, -1 on failure
 */
static inline int tdb_unlink(const char *path)
{
    if (!path) return -1;
#ifdef _WIN32
    /* clear read-only attribute that might prevent deletion */
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    return _unlink(path);
#else
    return unlink(path);
#endif
}

/**
 * is_directory_empty
 * checks if a directory is empty (contains only . and ..)
 * @param path the directory path to check
 * @return 1 if empty, 0 if not empty or error
 */
static inline int is_directory_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return 0;

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        count++;
        break; /* found at least one entry */
    }

    closedir(dir);
    return count == 0;
}

/**
 * remove_directory_once
 * single pass of recursive directory removal
 * @param path the directory path to remove
 * @return 0 on success, -1 on failure
 */
static inline int remove_directory_once(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return -1;

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        size_t len = strlen(path) + strlen(PATH_SEPARATOR) + strlen(entry->d_name) + 1;
        char *full_path = malloc(len);
        if (!full_path)
        {
            result = -1;
            continue;
        }

        snprintf(full_path, len, "%s%s%s", path, PATH_SEPARATOR, entry->d_name);

        struct STAT_STRUCT st;
        if (STAT_FUNC(full_path, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                /* recursive call for subdirectory */
                if (remove_directory_once(full_path) != 0) result = -1;
            }
            else
            {
#ifdef _WIN32
                /* clear read-only and other attributes that might prevent deletion */
                SetFileAttributesA(full_path, FILE_ATTRIBUTE_NORMAL);
                if (_unlink(full_path) != 0) result = -1;
#else
                if (unlink(full_path) != 0) result = -1;
#endif
            }
        }

        free(full_path);
    }

    closedir(dir);

    /* try to remove the directory itself */
#ifdef _WIN32
    if (_rmdir(path) != 0) result = -1;
#else
    if (rmdir(path) != 0) result = -1;
#endif

    return result;
}

/**
 * remove_directory
 * recursively removes a directory and all its contents with retry logic
 * retries if directory is not empty after deletion attempt (handles file locking)
 * @param path the directory path to remove
 * @return 0 on success, -1 on failure
 */
static inline int remove_directory(const char *path)
{
    /* check if directory exists */
    DIR *dir = opendir(path);
    if (!dir) return 0; /* already gone, success */
    closedir(dir);

    /* try up to 16 times with fixed 128ms delay */
    for (int attempt = 0; attempt < 16; attempt++)
    {
        /* attempt removal */
        (void)remove_directory_once(path);

        /* check if directory is gone or empty */
        dir = opendir(path);
        if (!dir)
        {
            /* directory successfully removed */
            return 0;
        }

        /* directory still exists, check if empty */
        if (is_directory_empty(path))
        {
            closedir(dir);
            /* empty but not removed, try rmdir directly */
#ifdef _WIN32
            if (_rmdir(path) == 0) return 0;
#else
            if (rmdir(path) == 0) return 0;
#endif
        }
        else
        {
            closedir(dir);
        }

        /* directory not empty or removal failed, wait and retry */
        if (attempt < 15)
        {
#ifdef _WIN32
            Sleep(128);
#else
            usleep(128000);
#endif
        }
    }

    /* final check */
    dir = opendir(path);
    if (!dir) return 0; /* success */
    closedir(dir);
    return -1; /* failed after all retries */
}

/**
 * tdb_sync_directory
 * syncs a directory to ensure directory entries (new files/subdirs) are persisted
 * on POSIX systems, directory entries must be explicitly synced after mkdir/file creation
 * on Windows, directory entries are immediately durable, so this is a no-op
 * @param dir_path path to the directory to sync
 * @return 0 on success, -1 on error (errors are non-fatal, just logged)
 */
static inline int tdb_sync_directory(const char *dir_path)
{
#ifdef _WIN32
    /* Windows -- directory entries are immediately durable, no sync needed */
    (void)dir_path;
    return 0;
#else
    /* POSIX -- must fsync directory to persist directory entries */
    int fd = open(dir_path, O_RDONLY);
    if (fd < 0)
    {
        /* non-fatal -- directory might not support fsync (e.g., some network filesystems) */
        return -1;
    }
    int result = fsync(fd);
    close(fd);
    return result;
#endif
}

/**
 * atomic_rename_file
 * atomically renames a file from old_path to new_path
 * on POSIX systems, rename() is atomic and replaces existing files
 * on windows, rename() fails if target exists, so we remove it first
 * @param old_path the current path of the file
 * @param new_path the new path for the file
 * @return 0 on success, -1 on failure
 */
static inline int atomic_rename_file(const char *old_path, const char *new_path)
{
    if (!old_path || !new_path) return -1;

#ifdef _WIN32
    /* use MoveFileEx with MOVEFILE_REPLACE_EXISTING for atomic rename on Windows
     * this is truly atomic and replaces the target file if it exists */
    if (!MoveFileEx(old_path, new_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        errno = GetLastError();
        return -1;
    }
    return 0;
#else
    /* POSIX rename() is atomic and replaces existing files */
    return rename(old_path, new_path);
#endif
}

/**
 * tdb_get_cpu_count
 * gets the number of available CPU cores
 * @return number of CPU cores, or 4 as fallback
 */
static inline int tdb_get_cpu_count(void)
{
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return (int)sysinfo.dwNumberOfProcessors;
#elif defined(__APPLE__)
    int count;
    size_t count_len = sizeof(count);
    if (sysctlbyname("hw.logicalcpu", &count, &count_len, NULL, 0) == 0)
    {
        return count;
    }
    return 4; /* fallback */
#else
    /* POSIX systems (Linux, BSD, etc.) */
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count > 0)
    {
        return (int)count;
    }
    return 4; /* fallback */
#endif
}

#endif /* __COMPAT_H__ */