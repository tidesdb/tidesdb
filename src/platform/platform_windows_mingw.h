/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_WINDOWS_MINGW_H__
#define __PLATFORM_WINDOWS_MINGW_H__

/* what mingw needs that msvc does not. the file io the two once each carried a copy of now lives
 * in the prelude, shared, so only the genuinely toolchain-specific pieces are left here */
#if defined(__MINGW32__) || defined(__MINGW64__)

/* mingw provides semaphore.h for POSIX semaphores */
#include <semaphore.h>

/* fopen for MinGW (uses standard fopen, not fopen_s) */
/*
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

#endif /* __MINGW32__ || __MINGW64__ */

#endif /* __PLATFORM_WINDOWS_MINGW_H__ */
