/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/* a stand-in for a storage-engine plugin. it links the library the way the build produced it,
 * statically into this module or as the shared library beside it, and a host loads and unloads it
 * the way a database server loads and unloads a plugin */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define UNLOAD_PLUGIN_EXPORT __declspec(dllexport)
#else
#include <dlfcn.h>
#define UNLOAD_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

#include "db.h"

#define UNLOAD_PLUGIN_FAMILY "t"
#define UNLOAD_PLUGIN_KEY    "k"
#define UNLOAD_PLUGIN_VALUE  "v"
#define UNLOAD_PLUGIN_NO_TTL (-1)

static tidesdb_t *unload_plugin_db;
static tidesdb_column_family_t *unload_plugin_cf;

/* open a database at path and flush one key to a table, so a later read goes through the block
 * manager rather than the memtable */
UNLOAD_PLUGIN_EXPORT int unload_plugin_open(const char *path)
{
    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = (char *)path;
    config.log_level = TDB_LOG_NONE;
    if (tidesdb_open(&config, &unload_plugin_db) != TDB_SUCCESS) return -1;
    tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
    if (tidesdb_create_column_family(unload_plugin_db, UNLOAD_PLUGIN_FAMILY, &cf_config) !=
        TDB_SUCCESS)
        return -1;
    unload_plugin_cf = tidesdb_get_column_family(unload_plugin_db, UNLOAD_PLUGIN_FAMILY);
    tidesdb_txn_t *txn = NULL;
    if (!unload_plugin_cf || tidesdb_txn_begin(unload_plugin_db, &txn) != TDB_SUCCESS) return -1;
    int rc = tidesdb_txn_put(txn, unload_plugin_cf, (const uint8_t *)UNLOAD_PLUGIN_KEY,
                             strlen(UNLOAD_PLUGIN_KEY), (const uint8_t *)UNLOAD_PLUGIN_VALUE,
                             strlen(UNLOAD_PLUGIN_VALUE), UNLOAD_PLUGIN_NO_TTL);
    if (rc == TDB_SUCCESS) rc = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);
    if (rc != TDB_SUCCESS) return -1;
    return tidesdb_flush_memtable(unload_plugin_db) == TDB_SUCCESS ? 0 : -1;
}

/* read the flushed key on the calling thread, which arms the library's per-thread read buffer */
UNLOAD_PLUGIN_EXPORT int unload_plugin_read(void)
{
    tidesdb_txn_t *txn = NULL;
    uint8_t *value = NULL;
    size_t value_size = 0;
    if (tidesdb_txn_begin(unload_plugin_db, &txn) != TDB_SUCCESS) return -1;
    const int rc = tidesdb_txn_get(txn, unload_plugin_cf, (const uint8_t *)UNLOAD_PLUGIN_KEY,
                                   strlen(UNLOAD_PLUGIN_KEY), &value, &value_size);
    tidesdb_free(value);
    tidesdb_txn_free(txn);
    return rc == TDB_SUCCESS ? 0 : -1;
}

UNLOAD_PLUGIN_EXPORT int unload_plugin_close(void)
{
    return tidesdb_close(unload_plugin_db) == TDB_SUCCESS ? 0 : -1;
}

/* the path of the module holding the library's code, this one when it was linked in statically and
 * the shared library otherwise, so the host can ask after the unload whether it is still mapped */
#ifdef _WIN32
/* the module exporting the library, found by name, since a function's address taken here is this
 * module's import thunk rather than the function itself. msvc names the library tidesdb.dll and
 * mingw libtidesdb.dll, and when neither is loaded the library was linked into this module */
static HMODULE unload_plugin_library_module(void)
{
    static const char *const names[] = {"tidesdb.dll", "libtidesdb.dll"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    {
        HMODULE module = GetModuleHandleA(names[i]);
        if (module && GetProcAddress(module, "tidesdb_open")) return module;
    }
    HMODULE self = NULL;
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)(uintptr_t)&unload_plugin_library_module, &self))
        return NULL;
    return self;
}
#endif

UNLOAD_PLUGIN_EXPORT int unload_plugin_library_path(char *buf, size_t cap)
{
#ifdef _WIN32
    HMODULE module = unload_plugin_library_module();
    if (!module) return -1;
    const DWORD n = GetModuleFileNameA(module, buf, (DWORD)cap);
    return n > 0 && n < cap ? 0 : -1;
#else
    const void *code = (const void *)(uintptr_t)&tidesdb_open;
    Dl_info info;
    if (dladdr((void *)(uintptr_t)code, &info) == 0 || !info.dli_fname) return -1;
    const int n = snprintf(buf, cap, "%s", info.dli_fname);
    return n > 0 && (size_t)n < cap ? 0 : -1;
#endif
}
