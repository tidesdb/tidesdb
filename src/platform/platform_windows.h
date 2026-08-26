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

/* the Windows backend, split into balanced pieces -- the MSVC prelude and atomics shim, the big
 * MSVC io and threading block, and the MinGW io block. included in order by the outer _WIN32 arm.
 */
#include "platform/platform_windows_mingw.h"
#include "platform/platform_windows_msvc.h"
#include "platform/platform_windows_prelude.h"

#endif /* __PLATFORM_WINDOWS_H__ */
