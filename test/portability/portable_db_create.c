/* writes a database that a build on another platform must be able to reopen and read back, so the
 * on-disk format is checked across architectures rather than only within one build */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define PORTABLE_KEY_COUNT   100
#define PORTABLE_DIR_ENV     "TIDESDB_PORTABLE_DIR"
#define PORTABLE_DIR_DEFAULT "./testdb"

/* the cross-platform jobs run this from the build directory against an artifact unpacked beside
 * it, so the location is given by the environment rather than fixed here */
static const char *portable_dir(void)
{
    const char *dir = getenv(PORTABLE_DIR_ENV);
    return (dir && *dir) ? dir : PORTABLE_DIR_DEFAULT;
}
#define PORTABLE_RETRY_LIMIT    200
#define PORTABLE_RETRY_PAUSE_MS 50

static void portable_pause(void)
{
#ifdef _WIN32
    Sleep(PORTABLE_RETRY_PAUSE_MS);
#else
    usleep(PORTABLE_RETRY_PAUSE_MS * 1000);
#endif
}

/* a background compaction holding the family answers TDB_ERR_LOCKED, which is retryable rather
 * than a failure -- so wait for it rather than asserting the first attempt succeeds */
static int portable_compact(tidesdb_t *db, tidesdb_column_family_t *cf)
{
    for (int attempt = 0; attempt < PORTABLE_RETRY_LIMIT; attempt++)
    {
        const int rc = tidesdb_compact(db, cf);
        if (rc != TDB_ERR_LOCKED) return rc;
        portable_pause();
    }
    return TDB_ERR_LOCKED;
}

int main(void)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = (char *)portable_dir();
    cfg.num_flush_threads = 1;
    cfg.num_compaction_threads = 1;
    cfg.log_level = TDB_LOG_INFO;
    /* small enough that the run rotates and flushes, so the artifact exercises the sstable format
     * and not only the write-ahead log */
    cfg.memtable_write_buffer_size = 4096;

    tidesdb_t *db = NULL;
    if (tidesdb_open(&cfg, &db) != TDB_SUCCESS) return 1;

    tidesdb_column_family_config_t cf_cfg = tidesdb_default_column_family_config();
    cf_cfg.enable_bloom_filter = 1;
    if (tidesdb_create_column_family(db, "test_cf", &cf_cfg) != TDB_SUCCESS) return 1;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    if (!cf) return 1;

    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin(db, &txn) != TDB_SUCCESS) return 1;
    for (int i = 0; i < PORTABLE_KEY_COUNT; i++)
    {
        char key[64], value[128];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(value, sizeof(value), "value_%d", i);
        if (tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key) + 1, (const uint8_t *)value,
                            strlen(value) + 1, 0) != TDB_SUCCESS)
            return 1;
    }
    if (tidesdb_txn_commit(txn) != TDB_SUCCESS) return 1;
    tidesdb_txn_free(txn);

    if (tidesdb_flush_memtable(db) != TDB_SUCCESS) return 1;
    if (portable_compact(db, cf) != TDB_SUCCESS) return 1;

    /* checkpoint rather than trusting close, which cannot report an i/o error */
    if (tidesdb_checkpoint(db) != TDB_SUCCESS) return 1;
    tidesdb_close(db);

    printf("database created with %d keys\n", PORTABLE_KEY_COUNT);
    return 0;
}
