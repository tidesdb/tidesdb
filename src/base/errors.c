/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "errors.h"

const char *tidesdb_strerror(const int code)
{
    switch (code)
    {
        case TDB_SUCCESS:
            return "success";
        case TDB_ERR_MEMORY:
            return "out of memory";
        case TDB_ERR_INVALID_ARGS:
            return "invalid arguments";
        case TDB_ERR_NOT_FOUND:
            return "not found";
        case TDB_ERR_IO:
            return "io error";
        case TDB_ERR_CORRUPTION:
            return "data corruption";
        case TDB_ERR_EXISTS:
            return "already exists";
        case TDB_ERR_CONFLICT:
            return "transaction conflict";
        case TDB_ERR_TOO_LARGE:
            return "value too large";
        case TDB_ERR_MEMORY_LIMIT:
            return "memory limit exceeded";
        case TDB_ERR_INVALID_DB:
            return "invalid database handle";
        case TDB_ERR_UNKNOWN:
            return "unknown error";
        case TDB_ERR_LOCKED:
            return "resource locked";
        case TDB_ERR_READONLY:
            return "read-only database";
        case TDB_ERR_BUSY:
            return "resource busy, retry";
        case TDB_ERR_TXN_EXPIRED:
            return "transaction expired";
        case TDB_ERR_NO_SPACE:
            return "no space left on device";
        case TDB_ERR_TXN_ABORTED:
            return "transaction aborted by another thread";
        case TDB_ERR_TOO_OLD:
            return "sequence is older than the oldest reconstructable point in time";
        default:
            return "unknown error";
    }
}
