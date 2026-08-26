/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_POSIX_H__
#define __PLATFORM_POSIX_H__

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * tdb_fopen
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

#endif /* __PLATFORM_POSIX_H__ */
