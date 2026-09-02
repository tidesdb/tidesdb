/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_WINDOWS_H__
#define __PLATFORM_WINDOWS_H__

/* the Windows backend, split into balanced pieces -- the prelude with the shared Win32 io and the
 * types the other two are written against, then the MSVC io and threading block, then the MinGW io
 * block.
 *
 * the order is load bearing and the sorting is turned off to hold it. the prelude declares mode_t,
 * off_t and ssize_t, which msvc has no definition of its own for, so it has to be first. sorted
 * alphabetically it comes last, which builds under mingw -- whose own headers supply those types --
 * and fails under msvc on the first function that names one */
/* clang-format off */
#include "platform/platform_windows_prelude.h"
#include "platform/platform_windows_msvc.h"
#include "platform/platform_windows_mingw.h"
/* clang-format on */

#endif /* __PLATFORM_WINDOWS_H__ */
