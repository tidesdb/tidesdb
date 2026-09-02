/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __COMPAT_H__
#define __COMPAT_H__

/* multi-platform support (Windows MSVC/MinGW, macOS, Linux, the BSDs, SunOS). this umbrella detects
 * the platform and pulls the split pieces in the one order their inter-dependencies require. */

#include "platform/platform_detect.h"
#include "platform/platform_features.h"
#include "platform/platform_lock.h"
#include "platform/platform_types.h"

#ifdef _WIN32
#include "platform/platform_windows.h"
#elif defined(__APPLE__)
#include "platform/platform_apple.h"
#else /* posix systems (Linux, the BSDs, SunOS) */
#include "platform/platform_posix.h"
#endif

#include "platform/platform_fs_sys.h"
#include "platform/platform_runtime.h"
#include "platform/platform_serialize.h"

#endif /* __COMPAT_H__ */
