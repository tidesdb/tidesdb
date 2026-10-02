/* loads the shared library the way a plugin host does, reads from a thread so the library leaves a
 * thread-specific destructor armed there, closes and unloads the library, and only then lets the
 * thread exit. the destructor runs at that exit, so a library that was unmapped by the unload
 * takes the process down with it */
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "db.h"

#define UNLOAD_DIR_SUFFIX  "_library_unload_db"
#define UNLOAD_PAUSE_US    1000
#define UNLOAD_PATH_MAX    4096
#define UNLOAD_FAMILY      "t"
#define UNLOAD_KEY         "k"
#define UNLOAD_VALUE       "v"
#define UNLOAD_NO_TTL      (-1)
#define UNLOAD_EXIT_FAILED 1

typedef tidesdb_config_t (*unload_default_config_t)(void);
typedef tidesdb_column_family_config_t (*unload_default_cf_config_t)(void);
typedef int (*unload_open_t)(tidesdb_config_t *, tidesdb_t **);
typedef int (*unload_close_t)(tidesdb_t *);
typedef int (*unload_create_cf_t)(tidesdb_t *, const char *,
                                  const tidesdb_column_family_config_t *);
typedef tidesdb_column_family_t *(*unload_get_cf_t)(tidesdb_t *, const char *);
typedef int (*unload_begin_t)(tidesdb_t *, tidesdb_txn_t **);
typedef int (*unload_put_t)(tidesdb_txn_t *, tidesdb_column_family_t *, const uint8_t *, size_t,
                            const uint8_t *, size_t, int64_t);
typedef int (*unload_commit_t)(tidesdb_txn_t *);
typedef void (*unload_txn_free_t)(tidesdb_txn_t *);
typedef int (*unload_get_t)(tidesdb_txn_t *, tidesdb_column_family_t *, const uint8_t *, size_t,
                            uint8_t **, size_t *);
typedef int (*unload_flush_t)(tidesdb_t *);
typedef void (*unload_free_t)(void *);

/**
 * unload_api_t
 * the library entry points the test resolves after loading it
 * @param default_config tidesdb_default_config
 * @param default_cf_config tidesdb_default_column_family_config
 * @param open tidesdb_open
 * @param close tidesdb_close
 * @param create_cf tidesdb_create_column_family
 * @param get_cf tidesdb_get_column_family
 * @param begin tidesdb_txn_begin
 * @param put tidesdb_txn_put
 * @param commit tidesdb_txn_commit
 * @param txn_free tidesdb_txn_free
 * @param get tidesdb_txn_get
 * @param flush tidesdb_flush_memtable
 * @param free tidesdb_free
 */
typedef struct
{
    unload_default_config_t default_config;
    unload_default_cf_config_t default_cf_config;
    unload_open_t open;
    unload_close_t close;
    unload_create_cf_t create_cf;
    unload_get_cf_t get_cf;
    unload_begin_t begin;
    unload_put_t put;
    unload_commit_t commit;
    unload_txn_free_t txn_free;
    unload_get_t get;
    unload_flush_t flush;
    unload_free_t free;
} unload_api_t;

/**
 * unload_reader_t
 * what the reader thread reads and the handshake it holds with the main thread
 * @param api the resolved entry points
 * @param db the open database
 * @param cf the family holding the key
 * @param rc the read's result
 * @param read_done set once the read has returned
 * @param unloaded set once the library has been unloaded
 */
typedef struct
{
    const unload_api_t *api;
    tidesdb_t *db;
    tidesdb_column_family_t *cf;
    int rc;
    atomic_int read_done;
    atomic_int unloaded;
} unload_reader_t;

/**
 * unload_resolve
 * looks up one symbol in the loaded library
 * @param handle the dlopen handle
 * @param name the symbol
 * @return the address, or NULL after printing which symbol is missing
 */
static void *unload_resolve(void *handle, const char *name)
{
    void *sym = dlsym(handle, name);
    if (!sym) fprintf(stderr, "library_unload missing symbol %s\n", name);
    return sym;
}

/**
 * unload_resolve_api
 * fills every entry point the test calls
 * @param handle the dlopen handle
 * @param api the table to fill
 * @return 0 when every symbol resolved, -1 otherwise
 */
static int unload_resolve_api(void *handle, unload_api_t *api)
{
    *(void **)&api->default_config = unload_resolve(handle, "tidesdb_default_config");
    *(void **)&api->default_cf_config =
        unload_resolve(handle, "tidesdb_default_column_family_config");
    *(void **)&api->open = unload_resolve(handle, "tidesdb_open");
    *(void **)&api->close = unload_resolve(handle, "tidesdb_close");
    *(void **)&api->create_cf = unload_resolve(handle, "tidesdb_create_column_family");
    *(void **)&api->get_cf = unload_resolve(handle, "tidesdb_get_column_family");
    *(void **)&api->begin = unload_resolve(handle, "tidesdb_txn_begin");
    *(void **)&api->put = unload_resolve(handle, "tidesdb_txn_put");
    *(void **)&api->commit = unload_resolve(handle, "tidesdb_txn_commit");
    *(void **)&api->txn_free = unload_resolve(handle, "tidesdb_txn_free");
    *(void **)&api->get = unload_resolve(handle, "tidesdb_txn_get");
    *(void **)&api->flush = unload_resolve(handle, "tidesdb_flush_memtable");
    *(void **)&api->free = unload_resolve(handle, "tidesdb_free");
    if (!api->default_config || !api->default_cf_config || !api->open || !api->close ||
        !api->create_cf || !api->get_cf || !api->begin || !api->put || !api->commit ||
        !api->txn_free || !api->get || !api->flush || !api->free)
        return -1;
    return 0;
}

/**
 * unload_reader
 * reads the flushed key, which arms the library's per-thread read buffer, then holds the thread
 * until the library is unloaded so its exit runs the destructor afterwards
 * @param arg the unload_reader_t
 * @return NULL
 */
static void *unload_reader(void *arg)
{
    unload_reader_t *r = (unload_reader_t *)arg;
    tidesdb_txn_t *txn = NULL;
    uint8_t *value = NULL;
    size_t value_size = 0;
    r->rc = r->api->begin(r->db, &txn);
    if (r->rc == TDB_SUCCESS)
    {
        r->rc = r->api->get(txn, r->cf, (const uint8_t *)UNLOAD_KEY, strlen(UNLOAD_KEY), &value,
                            &value_size);
        r->api->free(value);
        r->api->txn_free(txn);
    }
    atomic_store(&r->read_done, 1);
    while (!atomic_load(&r->unloaded)) usleep(UNLOAD_PAUSE_US);
    return NULL;
}

/**
 * unload_seed
 * creates the family and flushes one key to a table, so the reader's get goes through the block
 * manager rather than the memtable
 * @param api the resolved entry points
 * @param db the open database
 * @param cf receives the family
 * @return 0 on success, -1 otherwise
 */
static int unload_seed(const unload_api_t *api, tidesdb_t *db, tidesdb_column_family_t **cf)
{
    tidesdb_column_family_config_t cf_config = api->default_cf_config();
    tidesdb_txn_t *txn = NULL;
    if (api->create_cf(db, UNLOAD_FAMILY, &cf_config) != TDB_SUCCESS) return -1;
    *cf = api->get_cf(db, UNLOAD_FAMILY);
    if (!*cf || api->begin(db, &txn) != TDB_SUCCESS) return -1;
    int rc = api->put(txn, *cf, (const uint8_t *)UNLOAD_KEY, strlen(UNLOAD_KEY),
                      (const uint8_t *)UNLOAD_VALUE, strlen(UNLOAD_VALUE), UNLOAD_NO_TTL);
    if (rc == TDB_SUCCESS) rc = api->commit(txn);
    api->txn_free(txn);
    if (rc != TDB_SUCCESS || api->flush(db) != TDB_SUCCESS) return -1;
    return 0;
}

int main(int argc, char **argv)
{
    char db_path[UNLOAD_PATH_MAX];
    unload_api_t api;
    unload_reader_t reader;
    pthread_t thread;
    tidesdb_t *db = NULL;
    if (argc != 2)
    {
        fprintf(stderr, "usage %s <path to the shared library>\n", argv[0]);
        return UNLOAD_EXIT_FAILED;
    }
    (void)snprintf(db_path, sizeof(db_path), "%s%s", argv[0], UNLOAD_DIR_SUFFIX);

    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle)
    {
        fprintf(stderr, "library_unload dlopen failed %s\n", dlerror());
        return UNLOAD_EXIT_FAILED;
    }
    if (unload_resolve_api(handle, &api) != 0) return UNLOAD_EXIT_FAILED;

    tidesdb_config_t config = api.default_config();
    config.db_path = db_path;
    config.log_level = TDB_LOG_NONE;
    if (api.open(&config, &db) != TDB_SUCCESS) return UNLOAD_EXIT_FAILED;

    memset(&reader, 0, sizeof(reader));
    reader.api = &api;
    reader.db = db;
    if (unload_seed(&api, db, &reader.cf) != 0) return UNLOAD_EXIT_FAILED;
    if (pthread_create(&thread, NULL, unload_reader, &reader) != 0) return UNLOAD_EXIT_FAILED;
    while (!atomic_load(&reader.read_done)) usleep(UNLOAD_PAUSE_US);

    int close_rc = api.close(db);
    int unload_rc = dlclose(handle);
    atomic_store(&reader.unloaded, 1);
    (void)pthread_join(thread, NULL);

    if (reader.rc != TDB_SUCCESS || close_rc != TDB_SUCCESS || unload_rc != 0)
    {
        fprintf(stderr, "library_unload read %d close %d dlclose %d\n", reader.rc, close_rc,
                unload_rc);
        return UNLOAD_EXIT_FAILED;
    }
    printf("library_unload thread exited after the unload\n");
    return 0;
}
