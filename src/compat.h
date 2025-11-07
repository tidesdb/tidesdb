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
#ifndef __COMPAT_H__
#define __COMPAT_H__

/* compat header for multi-platform support (Windows, POSIX, posix includes macOS) */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
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

#ifdef _WIN32
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>

/* mingw provides most POSIX compatibility, so only apply msvc-specific fixes */
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

static inline int ftruncate(int fd, off_t length)
{
    return _chsize_s(fd, length);
}

static inline int _tidesdb_open_wrapper_3(const char *path, int flags, mode_t mode)
{
    return _open(path, flags | _O_BINARY, mode);
}
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
/* MSVC < 2022 doesn't have stdatomic.h - use Windows Interlocked functions */
typedef volatile LONG atomic_int;
typedef volatile LONGLONG atomic_size_t;
typedef volatile LONGLONG atomic_uint64_t;
#define _Atomic(T) volatile T

#ifdef _WIN64
/* 64-bit atomic store */
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

static inline void *_atomic_load_ptr(volatile void *const *ptr)
{
    return (void *)InterlockedCompareExchangePointer((PVOID volatile *)ptr, NULL, NULL);
}

#ifdef _WIN64
static inline LONGLONG _atomic_load_i64(volatile LONGLONG *ptr)
{
    return InterlockedCompareExchange64((LONGLONG volatile *)ptr, 0, 0);
}
#endif

static inline LONG _atomic_load_i32(volatile LONG *ptr)
{
    return InterlockedCompareExchange((LONG volatile *)ptr, 0, 0);
}

static inline unsigned char _atomic_load_u8(volatile unsigned char *ptr)
{
    return *ptr; /* byte reads are atomic on x86/x64 */
}

#ifdef _WIN64
#define atomic_load_explicit(ptr, order)                                                     \
    (sizeof(*(ptr)) == sizeof(void *) ? _atomic_load_ptr((volatile void *const *)(ptr))      \
     : sizeof(*(ptr)) == 8 ? (void *)(uintptr_t)_atomic_load_i64((volatile LONGLONG *)(ptr)) \
     : sizeof(*(ptr)) == 4 ? (void *)(uintptr_t)_atomic_load_i32((volatile LONG *)(ptr))     \
                           : (void *)(uintptr_t)_atomic_load_u8((volatile unsigned char *)(ptr)))
#else
#define atomic_load_explicit(ptr, order)                                                            \
    (sizeof(*(ptr)) == sizeof(void *) ? _atomic_load_ptr((volatile void *const *)(ptr))             \
     : sizeof(*(ptr)) == 4            ? (void *)(uintptr_t)_atomic_load_i32((volatile LONG *)(ptr)) \
                           : (void *)(uintptr_t)_atomic_load_u8((volatile unsigned char *)(ptr)))
#endif

/* Atomic exchange */
#ifdef _WIN64
#define atomic_exchange_explicit(ptr, val, order)                                       \
    (sizeof(*(ptr)) == sizeof(void *)                                                   \
         ? InterlockedExchangePointer((PVOID volatile *)(ptr), (PVOID)(uintptr_t)(val)) \
     : sizeof(*(ptr)) == 8                                                              \
         ? (void *)(uintptr_t)InterlockedExchange64((LONGLONG volatile *)(ptr),         \
                                                    (LONGLONG)(uintptr_t)(val))         \
         : (void *)(uintptr_t)InterlockedExchange((LONG volatile *)(ptr), (LONG)(uintptr_t)(val)))
#else
#define atomic_exchange_explicit(ptr, val, order)                                       \
    (sizeof(*(ptr)) == sizeof(void *)                                                   \
         ? InterlockedExchangePointer((PVOID volatile *)(ptr), (PVOID)(uintptr_t)(val)) \
         : (void *)(uintptr_t)InterlockedExchange((LONG volatile *)(ptr), (LONG)(uintptr_t)(val)))
#endif

#ifdef _WIN64
#define atomic_fetch_add(ptr, val) \
    InterlockedExchangeAdd64((LONGLONG volatile *)(ptr), (LONGLONG)(val))
#else
#define atomic_fetch_add(ptr, val) InterlockedExchangeAdd((LONG volatile *)(ptr), (LONG)(val))
#endif

#define atomic_store(ptr, val) atomic_store_explicit(ptr, val, memory_order_seq_cst)
#define atomic_load(ptr)       atomic_load_explicit(ptr, memory_order_seq_cst)
#define memory_order_relaxed   0
#define memory_order_acquire   1
#define memory_order_release   2
#define memory_order_seq_cst   3
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

#ifndef M_LN2
#define M_LN2 0.69314718055994530942 /* log_e 2 */
#endif

#if defined(_MSC_VER)
#define CLOCK_REALTIME 0

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

static inline int mkdir(const char *path, mode_t mode)
{
    (void)mode; /* unused on Windows */
    return _mkdir(path);
}

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

static inline int sem_destroy(sem_t *sem)
{
    if (sem->handle != NULL)
    {
        CloseHandle(sem->handle);
        sem->handle = NULL;
    }
    return 0;
}

static inline int sem_wait(sem_t *sem)
{
    DWORD result = WaitForSingleObject(sem->handle, INFINITE);
    return (result == WAIT_OBJECT_0) ? 0 : -1;
}

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
static inline int fdatasync(int fd)
{
    return fsync(fd);
}

/* clock_gettime for MSVC */
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

#if defined(__MINGW32__) || defined(__MINGW64__)
/* mingw provides semaphore.h for POSIX semaphores */
#include <semaphore.h>

/* mingw doesn't provide pread/pwrite/fdatasync, so we implement them */
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

static inline int fsync(int fd)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    return FlushFileBuffers(h) ? 0 : -1;
}

static inline int fdatasync(int fd)
{
    return fsync(fd);
}
#endif /* __MINGW32__ || __MINGW64__ */

#elif defined(__APPLE__)
#include <dirent.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

/* pread and pwrite are available natively on macOS via unistd.h */
/* no additional implementation needed using system pread/pwrite */

/* fdatasync for macOS, use F_FULLFSYNC for proper data sync */
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

/* semaphore compatibility for macOS using Grand Central Dispatch
 * macOS deprecated POSIX semaphores (sem_init, sem_destroy, etc.)
 * use dispatch_semaphore instead */
typedef dispatch_semaphore_t sem_t;

static inline int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    (void)pshared; /* unused on macOS */
    *sem = dispatch_semaphore_create(value);
    return (*sem == NULL) ? -1 : 0;
}

static inline int sem_destroy(sem_t *sem)
{
    if (*sem)
    {
        dispatch_release(*sem);
        *sem = NULL;
    }
    return 0;
}

static inline int sem_wait(sem_t *sem)
{
    return (dispatch_semaphore_wait(*sem, DISPATCH_TIME_FOREVER) == 0) ? 0 : -1;
}

static inline int sem_post(sem_t *sem)
{
    dispatch_semaphore_signal(*sem);
    return 0;
}

#else /* posix systems */
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <unistd.h>

/* pread, pwrite, and fdatasync are available natively on POSIX systems via unistd.h */
/* no additional implementation needed using system pread/pwrite/fdatasync */

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
typedef pthread_mutex_t crit_section_t;
typedef pthread_rwlock_t rwlock_t;
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
    vm_statistics64_data_t vm_stats;

    mach_port = mach_host_self();
    count = sizeof(vm_stats) / sizeof(natural_t);
    if (host_page_size(mach_port, &page_size) == KERN_SUCCESS &&
        host_statistics64(mach_port, HOST_VM_INFO, (host_info64_t)&vm_stats, &count) ==
            KERN_SUCCESS)
    {
        return (size_t)(vm_stats.free_count * page_size);
    }
    return 0;
#else
    /* linux and other POSIX systems */
    struct sysinfo si;
    if (sysinfo(&si) == 0)
    {
        return (size_t)si.freeram * (size_t)si.mem_unit;
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
#else
    /* Linux and other POSIX systems */
    struct sysinfo si;
    if (sysinfo(&si) == 0)
    {
        return (size_t)si.totalram * (size_t)si.mem_unit;
    }
    return 0;
#endif
}

#endif /* __COMPAT_H__ */