/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_ERRORS_H__
#define __TIDESDB_BASE_ERRORS_H__

#include "db.h" /* the TDB_SUCCESS and TDB_ERR_* result codes are the public contract, resolved from include/ */

/* internal-only result code, kept out of the public db.h. a transient contention signal (an sstable
 * layout moved mid-scan, or rotation contention on the active-memtable pin) that the engine retries
 * internally and never returns to a public caller. its value sits below the public db.h code range
 * so it can never be mistaken for a caller-visible result. */
#define TDB_ERR_BUSY -99

/* tidesdb_strerror is public and declared in db.h, which this header already includes; it maps the
 * internal TDB_ERR_BUSY above as well as every public code */

#endif /* __TIDESDB_BASE_ERRORS_H__ */
