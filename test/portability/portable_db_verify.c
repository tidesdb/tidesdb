/* reopens a database written by another platform's build and reads every key back, so a format or
 * endianness divergence fails here rather than silently */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "db.h"

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

int main(void)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = (char *)portable_dir();
    cfg.num_flush_threads = 1;
    cfg.num_compaction_threads = 1;
    cfg.log_level = TDB_LOG_INFO;

    tidesdb_t *db = NULL;
    if (tidesdb_open(&cfg, &db) != TDB_SUCCESS)
    {
        printf("open failed\n");
        return 1;
    }

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "test_cf");
    if (!cf)
    {
        printf("column family test_cf missing\n");
        return 1;
    }

    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin(db, &txn) != TDB_SUCCESS) return 1;

    int verified = 0;
    for (int i = 0; i < PORTABLE_KEY_COUNT; i++)
    {
        char key[64], expect[128];
        snprintf(key, sizeof(key), "key_%d", i);
        snprintf(expect, sizeof(expect), "value_%d", i);

        uint8_t *value = NULL;
        size_t value_size = 0;
        const int rc =
            tidesdb_txn_get(txn, cf, (const uint8_t *)key, strlen(key) + 1, &value, &value_size);
        if (rc != TDB_SUCCESS || !value)
        {
            printf("key %s missing, rc %d\n", key, rc);
            return 1;
        }
        if (value_size != strlen(expect) + 1 || memcmp(value, expect, value_size) != 0)
        {
            printf("key %s has the wrong value\n", key);
            free(value);
            return 1;
        }
        free(value);
        verified++;
    }

    tidesdb_txn_free(txn);
    tidesdb_close(db);

    if (verified != PORTABLE_KEY_COUNT)
    {
        printf("verified %d of %d keys\n", verified, PORTABLE_KEY_COUNT);
        return 1;
    }
    printf("verified all %d keys\n", verified);
    return 0;
}
