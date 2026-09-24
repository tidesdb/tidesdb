/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_LOCK_H__
#define __PLATFORM_LOCK_H__

/* cross-platform file locking abstraction for database directory lock */
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <windows.h>

/*
 * tdb_open_lock_file
 * opens a lock file (windows version -- lock acquired separately)
 * @param path the path to the lock file
 * @param lock_result output -- TDB_LOCK_SUCCESS on successful open (lock not yet acquired)
 * @return file descriptor on success (>= 0), -1 on error
 */
static inline int tdb_open_lock_file(const char *path, int *lock_result)
{
    int fd = _open(path, _O_RDWR | _O_CREAT | _O_BINARY, 0644);
    if (fd < 0)
    {
        *lock_result = TDB_LOCK_ERROR;
        return -1;
    }
    *lock_result = TDB_LOCK_SUCCESS; /* caller will call tdb_file_lock_exclusive */
    return fd;
}

/*
 * tdb_file_lock_exclusive
 * acquires an exclusive lock on a file (non-blocking)
 * @param fd the file descriptor to lock
 * @param max_retries maximum retries for transient errors (i.e., signal interrupts)
 * @return TDB_LOCK_SUCCESS on success,
 *         TDB_LOCK_HELD if lock is held by another process,
 *         TDB_LOCK_ERROR on irrecoverable error
 */
static inline int tdb_file_lock_exclusive(int fd, int max_retries)
{
    (void)max_retries; /* windows with LOCKFILE_FAIL_IMMEDIATELY has no retryable errs */

    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) return TDB_LOCK_ERROR;

    OVERLAPPED ov = {0};
    if (LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov))
    {
        return TDB_LOCK_SUCCESS;
    }

    /* with LOCKFILE_FAIL_IMMEDIATELY, ERROR_LOCK_VIOLATION means lock is held
     **** https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex */
    DWORD err = GetLastError();
    if (err == ERROR_LOCK_VIOLATION)
    {
        return TDB_LOCK_HELD;
    }
    return TDB_LOCK_ERROR;
}

/*
 * tdb_file_close
 * closes a lock-file descriptor, on whichever handle type the platform opened it as
 * @param fd the descriptor
 * @return 0 on success, -1 on error
 */
static inline int tdb_file_close(const int fd)
{
#ifdef _WIN32
    return _close(fd);
#else
    return close(fd);
#endif
}

/*
 * tdb_file_unlock
 * releases a lock on a file
 * @param fd the file descriptor to unlock
 * @return 0 on success, -1 on error
 */
static inline int tdb_file_unlock(int fd)
{
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;

    OVERLAPPED ov = {0};
    if (!UnlockFileEx(h, 0, 1, 0, &ov))
    {
        return -1;
    }
    return 0;
}
#else
#include <errno.h>
#include <fcntl.h>

/* the lock has to belong to the open file description, not to the process. a second open of the
 * directory from the same process then gets a description of its own and is refused by the lock
 * itself, and closing some other descriptor on the file cannot release it. posix fcntl locks fail
 * both, since they belong to the process -- a process may re-lock what it already holds, and any
 * close on the file drops every lock it has there, including one taken through a different
 * descriptor. linux 3.15+ and illumos have fcntl F_OFD_SETLK, which has the right owner and is used
 * where it exists. macOS and the BSDs do not, and use flock, whose locks belong to the description
 * as well. either way a child forked without exec shares the description and holds the lock with
 * its parent until it closes the descriptor, which O_CLOEXEC does for it on exec
 * https://lwn.net/Articles/640404/ */
#if defined(F_OFD_SETLK)
#define TDB_USE_FLOCK 0
#else
#define TDB_USE_FLOCK 1
#include <sys/file.h>
#endif

/**
 * tdb_open_lock_file
 * open the lock file, creating it if absent, without locking it
 * @param path the path to the lock file
 * @param lock_result set to TDB_LOCK_SUCCESS on success or TDB_LOCK_ERROR on failure
 * @return the descriptor on success, -1 on failure
 */
static inline int tdb_open_lock_file(const char *path, int *lock_result)
{
    const int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    *lock_result = fd < 0 ? TDB_LOCK_ERROR : TDB_LOCK_SUCCESS;
    return fd;
}

/**
 * tdb_file_lock_try
 * one non-blocking attempt at the exclusive lock on the whole file
 * @param fd the open lock-file descriptor
 * @return 0 when the lock was taken, -1 with errno set otherwise
 */
static inline int tdb_file_lock_try(const int fd)
{
#if TDB_USE_FLOCK
    return flock(fd, LOCK_EX | LOCK_NB);
#else
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    return fcntl(fd, F_OFD_SETLK, &fl);
#endif
}

/**
 * tdb_file_lock_exclusive
 * take the exclusive lock on fd without blocking, retrying EINTR up to max_retries
 * @param fd the open lock-file descriptor
 * @param max_retries EINTR retry budget, defaulted when not positive
 * @return TDB_LOCK_SUCCESS, TDB_LOCK_HELD when another description holds it, in this process or
 *         another, or TDB_LOCK_ERROR
 */
static inline int tdb_file_lock_exclusive(const int fd, int max_retries)
{
    if (max_retries <= 0) max_retries = TDB_LOCK_DEFAULT_RETRIES;
    for (int attempt = 0; attempt <= max_retries; attempt++)
    {
        if (tdb_file_lock_try(fd) == 0) return TDB_LOCK_SUCCESS;
        const int err = errno;
        if (err == EWOULDBLOCK || err == EAGAIN || err == EACCES) return TDB_LOCK_HELD;
        if (err != EINTR) return TDB_LOCK_ERROR;
    }
    return TDB_LOCK_ERROR;
}

/**
 * tdb_file_close
 * close a lock-file descriptor, which also releases a lock taken through it
 * @param fd the descriptor
 * @return 0 on success, -1 on error
 */
static inline int tdb_file_close(const int fd)
{
    return close(fd);
}

/**
 * tdb_file_unlock
 * release the lock taken through fd
 * @param fd the locked descriptor
 * @return 0 on success, -1 on error
 */
static inline int tdb_file_unlock(const int fd)
{
#if TDB_USE_FLOCK
    return flock(fd, LOCK_UN);
#else
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    return fcntl(fd, F_OFD_SETLK, &fl);
#endif
}
#endif

#endif /* __PLATFORM_LOCK_H__ */
