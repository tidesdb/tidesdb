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

/* linux 3.15+ has F_OFD_SETLK, open file description locks, which are per-fd and release when the
 * descriptor closes rather than when any descriptor on the file closes; those are preferred where
 * they exist, with fcntl() F_SETLK as the fallback.
 * https://lwn.net/Articles/640404/ and https://apenwarr.ca/log/20101213
 *
 * macOS and the BSDs get fcntl() F_SETLK, whose per-process locks are not inherited across fork(),
 * so a child correctly fails to acquire a lock the parent holds. flock() is not used here because
 * its locks do survive fork(), which lets a child inherit the lock and then deadlock against itself
 * when it opens a second descriptor on the same file.
 * https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/flock.2.html
 */
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)
#define TDB_USE_FLOCK       0
#define TDB_USE_FCNTL_SETLK 1
#include <sys/file.h>
#elif !defined(F_OFD_SETLK)
#define TDB_USE_FLOCK       1
#define TDB_USE_FCNTL_SETLK 0
#include <sys/file.h>
#else
#define TDB_USE_FLOCK       0
#define TDB_USE_FCNTL_SETLK 0
#endif

/*
 * tdb_open_lock_file
 * opens a lock file for locking (lock acquired separately via tdb_file_lock_exclusive)
 * @param path the path to the lock file
 * @param lock_result output -- TDB_LOCK_SUCCESS, TDB_LOCK_HELD, or TDB_LOCK_ERROR
 * @return file descriptor on success (>= 0), -1 on error
 */
static inline int tdb_open_lock_file(const char *path, int *lock_result)
{
    /* open the lock file */
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (fd < 0)
    {
        *lock_result = TDB_LOCK_ERROR;
        return -1;
    }

#if TDB_USE_FCNTL_SETLK
    /* fcntl() F_SETLK allows same-process re-locking, so check PID file first.
     * read PID before acquiring lock to detect same-process double-open. */
    char pid_buf[32] = {0};
    ssize_t n = pread(fd, pid_buf, sizeof(pid_buf) - 1, 0);
    if (n > 0)
    {
        pid_t file_pid = (pid_t)atol(pid_buf);
        if (file_pid == getpid())
        {
            /* same process already holds lock */
            close(fd);
            *lock_result = TDB_LOCK_HELD;
            return -1;
        }
    }
#endif

    *lock_result = TDB_LOCK_SUCCESS;
    return fd;
}

#if TDB_USE_FCNTL_SETLK
/*
 * tdb_file_lock_write_pid
 * writes the current PID to the lock file after acquiring the lock
 * @param fd the file descriptor of the lock file
 */
static inline void tdb_file_lock_write_pid(const int fd)
{
    char our_pid[32];
    int len = snprintf(our_pid, sizeof(our_pid), "%d\n", (int)getpid());
    if (ftruncate(fd, 0) == 0)
    {
        (void)pwrite(fd, our_pid, len, 0);
    }
}

/*
 * tdb_file_lock_clear_pid
 * clears the PID from the lock file before releasing the lock
 * @param fd the file descriptor of the lock file
 */
static inline void tdb_file_lock_clear_pid(const int fd)
{
    (void)ftruncate(fd, 0);
}
#endif

/*
 * tdb_file_lock_exclusive
 * acquires an exclusive lock on a file (non-blocking)
 * uses fcntl() F_SETLK on macOS/BSD (locks not inherited across fork)
 * uses flock() on older systems without F_OFD_SETLK
 * uses F_OFD_SETLK on linux 3.15+ for per-fd locking
 * @param fd the file descriptor to lock
 * @param max_retries maximum retries for EINTR (signal interrupts)
 * @return TDB_LOCK_SUCCESS on success,
 *         TDB_LOCK_HELD if lock is held by another process,
 *         TDB_LOCK_ERROR on irrecoverable error
 */
/* exclusive-lock backends, one per locking primitive, guarded so exactly one compiles */
#if TDB_USE_FCNTL_SETLK
static inline int tdb_file_lock_exclusive_impl(const int fd, const int max_retries)
{
    int retries = 0;
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;

    while (retries <= max_retries)
    {
        if (fcntl(fd, F_SETLK, &fl) == 0)
        {
            /* write the pid to the lock file for same-process detection */
            tdb_file_lock_write_pid(fd);
            return TDB_LOCK_SUCCESS;
        }

        int err = errno;

#if EWOULDBLOCK == EAGAIN
        if (err == EWOULDBLOCK || err == EACCES)
#else
        if (err == EWOULDBLOCK || err == EAGAIN || err == EACCES)
#endif
        {
            return TDB_LOCK_HELD;
        }
        if (err == EINTR)
        {
            retries++;
            continue;
        }
        return TDB_LOCK_ERROR;
    }
    return TDB_LOCK_ERROR;
}
#elif TDB_USE_FLOCK
static inline int tdb_file_lock_exclusive_impl(const int fd, const int max_retries)
{
    int retries = 0;
    while (retries <= max_retries)
    {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0)
        {
            return TDB_LOCK_SUCCESS;
        }

        int err = errno;

#if EWOULDBLOCK == EAGAIN
        if (err == EWOULDBLOCK || err == EACCES)
#else
        if (err == EWOULDBLOCK || err == EAGAIN || err == EACCES)
#endif
        {
            return TDB_LOCK_HELD;
        }
        if (err == EINTR)
        {
            retries++;
            continue;
        }
        return TDB_LOCK_ERROR;
    }
    return TDB_LOCK_ERROR;
}
#else
static inline int tdb_file_lock_exclusive_impl(const int fd, const int max_retries)
{
    int retries = 0;
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0; /* ignored for OFD locks */

    while (retries <= max_retries)
    {
        if (fcntl(fd, F_OFD_SETLK, &fl) == 0)
        {
            return TDB_LOCK_SUCCESS;
        }

        int err = errno;

#if EWOULDBLOCK == EAGAIN
        if (err == EWOULDBLOCK || err == EACCES)
#else
        if (err == EWOULDBLOCK || err == EAGAIN || err == EACCES)
#endif
        {
            return TDB_LOCK_HELD;
        }
        if (err == EINTR)
        {
            retries++;
            continue;
        }
        return TDB_LOCK_ERROR;
    }
    return TDB_LOCK_ERROR;
}
#endif

/**
 * tdb_file_lock_exclusive
 * take an exclusive advisory lock on fd, retrying EINTR up to max_retries
 * @param fd the open lock-file descriptor
 * @param max_retries EINTR retry budget, defaulted when not positive
 * @return TDB_LOCK_SUCCESS, TDB_LOCK_HELD if another process holds it, or TDB_LOCK_ERROR
 */
static inline int tdb_file_lock_exclusive(const int fd, int max_retries)
{
    if (max_retries <= 0) max_retries = TDB_LOCK_DEFAULT_RETRIES;
    return tdb_file_lock_exclusive_impl(fd, max_retries);
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
static inline int tdb_file_unlock(const int fd)
{
#if TDB_USE_FCNTL_SETLK
    tdb_file_lock_clear_pid(fd);

    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;

    if (fcntl(fd, F_SETLK, &fl) != 0)
    {
        return -1;
    }
    return 0;
#elif TDB_USE_FLOCK
    if (flock(fd, LOCK_UN) != 0)
    {
        return -1;
    }
    return 0;
#else
    /* linux with F_OFD_SETLK */
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;

    if (fcntl(fd, F_OFD_SETLK, &fl) != 0)
    {
        return -1;
    }
    return 0;
#endif
}
#endif

#endif /* __PLATFORM_LOCK_H__ */
