/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_APPLE_H__
#define __PLATFORM_APPLE_H__

#include <dirent.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>

/* Grand Central Dispatch (dispatch/dispatch.h) is only available on macOS 10.6+; older versions
 * (10.5 PPC64, say) fall back to POSIX semaphores */
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
 * tdb_fopen
 * portable file opening wrapper
 * @param filename the filename to open
 * @param mode the mode to open the file in
 * @return a pointer to the opened file, or NULL on failure
 */
static inline FILE *tdb_fopen(const char *filename, const char *mode)
{
    return fopen(filename, mode);
}

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
 * note-- POSIX semaphores are deprecated on modern macOS but work on older versions */
/* sem_t, sem_init, sem_destroy, sem_wait, sem_post are provided by semaphore.h */
#endif

#endif /* __PLATFORM_APPLE_H__ */
