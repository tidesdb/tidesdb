/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_TYPES_H__
#define __PLATFORM_TYPES_H__

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

#endif /* __PLATFORM_TYPES_H__ */
