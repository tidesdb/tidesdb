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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>

#pragma warning(disable : 4996) /* disable deprecated warning for Windows */

#include "pthread.h" /* pthreads-win32 library (https://github.com/tidesdb/tidesdb/issues/241) */

#define truncate                                                                                                                                            \
    _chsize /* https://github.com/tidesdb/tidesdb/issues/241#:~:text=back%20and%20added%3A-,%23define%20truncate%20%20%20%20%20%20%20_chsize,-to%20compat.h \
             */

/* access flags are normally defined in unistd.h, which unavailable under
 * windows.
 *
 * instead, define the flags as documented at
 * https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/access-waccess */
#define F_OK 00
#define W_OK 02
#define R_OK 04

/* fcntl.h flags for Windows - use _O_* equivalents */
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

typedef int64_t ssize_t; /* ssize_t is not defined in Windows */

#define M_LN2 0.69314718055994530942 /* log_e 2 */

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

/* https://github.com/tidesdb/tidesdb/issues/241#:~:text=if%20(mkdir(directory)%20%3D%3D%20%2D1)%20//%20%2C%200777%20and%20if%20(mkdir(cf_path)%20%3D%3D%20%2D1)%20//%20%2C%200777%20i%20get%20the%20following%3A
 */
static inline int mkdir(const char *path, mode_t mode)
{
    (void)mode; /* unused on Windows */
    return _mkdir(path);
}

DIR *opendir(const char *name)
{
    DIR *dir = malloc(sizeof(DIR));
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

struct dirent *readdir(DIR *dir)
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

int closedir(DIR *dir)
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

/* semaphore functions for Windows */
typedef HANDLE sem_t;

int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    *sem = CreateSemaphore(NULL, value, LONG_MAX, NULL);
    if (*sem == NULL)
    {
        errno = GetLastError();
        return -1;
    }
    return 0;
}

/* file operations macros for cross-platform compatibility */
#define S_ISDIR(m)           (((m)&S_IFMT) == S_IFDIR)
#define sleep(seconds)       Sleep((seconds)*1000)
#define usleep(microseconds) Sleep((microseconds) / 1000) /* usleep for Windows */
#define access               _access
#define ftell                _ftelli64
#define fseek                _fseeki64

int fsync(int fd)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    return FlushFileBuffers(h) ? 0 : -1;
}

/* fdatasync for Windows, same as fsync (Windows doesn't distinguish) */
int fdatasync(int fd)
{
    return fsync(fd);
}

/* gettimeofday function for win */
int gettimeofday(struct timeval *tp, struct timezone *tzp)
{
    FILETIME ft;
    unsigned __int64 tmpres = 0;
    static int tzflag;

    if (NULL != tp)
    {
        GetSystemTimeAsFileTime(&ft);

        tmpres |= ft.dwHighDateTime;
        tmpres <<= 32;
        tmpres |= ft.dwLowDateTime;

        /* convert into microseconds */
        tmpres /= 10;

        /* converting file time to unix epoch */
        tmpres -= 11644473600000000ULL;

        tp->tv_sec = (long)(tmpres / 1000000UL);
        tp->tv_usec = (long)(tmpres % 1000000UL);
    }

    if (NULL != tzp)
    {
        if (!tzflag)
        {
            _tzset();
            tzflag++;
        }
        tzp->tz_minuteswest = _timezone / 60;
        tzp->tz_dsttime = _daylight;
    }

    return 0;
}

/* pread and pwrite for Windows */
ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return -1;
    }

    OVERLAPPED overlapped = {0};
    overlapped.Offset = (DWORD)offset;
    overlapped.OffsetHigh = (DWORD)(offset >> 32);

    DWORD bytes_read;
    if (!ReadFile(h, buf, (DWORD)count, &bytes_read, &overlapped))
    {
        errno = GetLastError();
        return -1;
    }

    return (ssize_t)bytes_read;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        errno = EBADF;
        return -1;
    }

    OVERLAPPED overlapped = {0};
    overlapped.Offset = (DWORD)offset;
    overlapped.OffsetHigh = (DWORD)(offset >> 32);

    DWORD bytes_written;
    if (!WriteFile(h, buf, (DWORD)count, &bytes_written, &overlapped))
    {
        errno = GetLastError();
        return -1;
    }

    return (ssize_t)bytes_written;
}

#elif defined(__APPLE__)
#include <dirent.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

/* pread and pwrite are available natively on macOS via unistd.h */
/* no additional implementation needed - using system pread/pwrite */

/* fdatasync for macOS - use F_FULLFSYNC for proper data sync */
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
/* no additional implementation needed - using system pread/pwrite/fdatasync */

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
typedef pthread_mutex_t crit_section_t;
typedef pthread_rwlock_t rwlock_t;
#endif

#endif /* __COMPAT_H__ */