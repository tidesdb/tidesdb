/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_DETECT_H__
#define __PLATFORM_DETECT_H__

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

#ifndef _WIN32
#include <signal.h>
#endif

#ifdef _WIN32
/* require Windows Vista+ APIs (SetFileInformationByHandle, FILE_ALLOCATION_INFO,
 * FILE_END_OF_FILE_INFO) used by tdb_preallocate_extent. defined before any
 * windows.h include below so the right structure declarations are visible. */
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#if !defined(WINVER) || WINVER < 0x0600
#undef WINVER
#define WINVER 0x0600
#endif
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

/* cross-platform line buffering -- Windows doesn't support _IOLBF properly with NULL buffer */
#if defined(_MSC_VER)
#define tdb_setlinebuf(stream) setvbuf((stream), NULL, _IONBF, 0)
#else
#define tdb_setlinebuf(stream) setvbuf((stream), NULL, _IOLBF, 0)
#endif

/* branch prediction hints for hot paths */
#if defined(__GNUC__) || defined(__clang__)
#define TDB_LIKELY(x)   __builtin_expect(!!(x), 1)
#define TDB_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define TDB_LIKELY(x)   (x)
#define TDB_UNLIKELY(x) (x)
#endif

/* cross-platform fabs abstraction. every platform maps to the same standard fabs, so this is a
 * single unconditional definition rather than three identical conditional arms. */
#include <math.h>
#define tdb_fabs(x) fabs(x)

/* cross-platform fsync abstraction */
#if defined(_WIN32)
#include <io.h>
#define tdb_fsync(fd) _commit(fd)
#else
#include <unistd.h>
#define tdb_fsync(fd) fsync(fd)
#endif

/* file lock error codes */
#define TDB_LOCK_SUCCESS 0 /* lock acquired successfully */
#define TDB_LOCK_HELD    1 /* lock is held by another process (EWOULDBLOCK/EAGAIN) */
#define TDB_LOCK_ERROR   2 /* irrecoverable error */

/* default retry count for EINTR during lock acquisition */
#define TDB_LOCK_DEFAULT_RETRIES 3

#endif /* __PLATFORM_DETECT_H__ */
