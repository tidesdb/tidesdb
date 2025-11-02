/*
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* disable format-truncation warnings. all path buffers use TDB_MAX_PATH_LENGTH (1024) */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"

#include "tidesdb.h"

/* global debug logging flag */
int _tidesdb_debug_enabled = 0;

/* comparator registry */
typedef struct
{
    char name[TDB_MAX_COMPARATOR_NAME];
    skip_list_comparator_fn compare_fn;
} comparator_entry_t;

static comparator_entry_t comparator_registry[TDB_MAX_COMPARATORS];
static int num_comparators = 0;
static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;

/* register built-in comparators automatically */
static void __attribute__((constructor)) init_builtin_comparators(void)
{
    tidesdb_register_comparator("memcmp", skip_list_comparator_memcmp);
    tidesdb_register_comparator("string", skip_list_comparator_string);
    tidesdb_register_comparator("numeric", skip_list_comparator_numeric);
}

int tidesdb_register_comparator(const char *name, skip_list_comparator_fn compare_fn)
{
    if (!name || !compare_fn) return -1;

    pthread_mutex_lock(&registry_lock);

    /* check if already registered */
    for (int i = 0; i < num_comparators; i++)
    {
        if (strcmp(comparator_registry[i].name, name) == 0)
        {
            /* update existing */
            comparator_registry[i].compare_fn = compare_fn;
            pthread_mutex_unlock(&registry_lock);
            return 0;
        }
    }

    /* add new */
    if (num_comparators >= TDB_MAX_COMPARATORS)
    {
        pthread_mutex_unlock(&registry_lock);
        return -1;
    }

    strncpy(comparator_registry[num_comparators].name, name, TDB_MAX_COMPARATOR_NAME - 1);
    comparator_registry[num_comparators].name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';
    comparator_registry[num_comparators].compare_fn = compare_fn;
    num_comparators++;

    pthread_mutex_unlock(&registry_lock);
    return 0;
}

skip_list_comparator_fn tidesdb_get_comparator(const char *name)
{
    if (!name) return skip_list_comparator_memcmp; /* default */

    pthread_mutex_lock(&registry_lock);

    for (int i = 0; i < num_comparators; i++)
    {
        if (strcmp(comparator_registry[i].name, name) == 0)
        {
            skip_list_comparator_fn fn = comparator_registry[i].compare_fn;
            pthread_mutex_unlock(&registry_lock);
            return fn;
        }
    }

    pthread_mutex_unlock(&registry_lock);
    return NULL; /* not found */
}

/* forward declarations for static functions */
static int tidesdb_load_sstable(tidesdb_column_family_t *cf, uint64_t sstable_id,
                                tidesdb_sstable_t **sstable);
static void tidesdb_sstable_free(tidesdb_sstable_t *sstable);
static int tidesdb_recover_wal(tidesdb_column_family_t *cf);
static int tidesdb_check_and_flush(tidesdb_column_family_t *cf);
static void *tidesdb_background_compaction_thread(void *arg);

tidesdb_column_family_config_t tidesdb_default_column_family_config(void)
{
    tidesdb_column_family_config_t config = {
        .memtable_flush_size = TDB_DEFAULT_MEMTABLE_FLUSH_SIZE,
        .max_sstables_before_compaction = TDB_DEFAULT_MAX_SSTABLES,
        .compaction_threads = TDB_DEFAULT_COMPACTION_THREADS,
        .max_level = 12,
        .probability = 0.25f,
        .compressed = 1,
        .compress_algo = COMPRESS_LZ4,
        .bloom_filter_fp_rate = 0.01,
        .enable_background_compaction = 1,
        .use_sbha = 1,
        .sync_mode = TDB_SYNC_BACKGROUND,
        .sync_interval = 1.0f,  /* 1 second default */
        .comparator_name = NULL /* NULL = use "memcmp" */
    };
    return config;
}

/* internal helper to create directory if it doesn't exist */
static int mkdir_p(const char *path)
{
    struct stat st;
    if (stat(path, &st) == -1)
    {
        if (mkdir(path, 0755) == -1)
        {
            return -1;
        }
    }
    return 0;
}

/* internal helper to get column family directory path */
static void get_cf_path(const tidesdb_t *db, const char *cf_name, char *path)
{
    /* TDB_MAX_PATH_LENGTH (1024) is sufficient for db_path + "/" + cf_name */
    (void)snprintf(path, TDB_MAX_PATH_LENGTH, "%s/%s", db->config.db_path, cf_name);
}

/* internal helper to get wal path */
static void get_wal_path(const tidesdb_column_family_t *cf, char *path)
{
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(cf->db, cf->name, cf_path);
    (void)snprintf(path, TDB_MAX_PATH_LENGTH, "%s/wal%s", cf_path, TDB_WAL_EXT);
}

/* internal helper to get sstable path */
static void get_sstable_path(const tidesdb_column_family_t *cf, uint64_t sstable_id, char *path)
{
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(cf->db, cf->name, cf_path);
    (void)snprintf(path, TDB_MAX_PATH_LENGTH, "%s/sstable_%llu%s", cf_path,
                   (unsigned long long)sstable_id, TDB_SSTABLE_EXT);
}

int tidesdb_open(const tidesdb_config_t *config, tidesdb_t **db)
{
    if (!config || !db) return -1;

    /* set global debug flag */
    _tidesdb_debug_enabled = config->enable_debug_logging;

    TDB_DEBUG_LOG("Opening TidesDB at path: %s", config->db_path);

    *db = malloc(sizeof(tidesdb_t));
    if (!*db) return -1;

    memcpy(&(*db)->config, config, sizeof(tidesdb_config_t));
    (*db)->column_families = NULL;
    (*db)->num_cfs = 0;
    (*db)->cf_capacity = 0;

    if (pthread_rwlock_init(&(*db)->db_lock, NULL) != 0)
    {
        free(*db);
        return -1;
    }

    /* create database directory */
    if (mkdir_p(config->db_path) == -1)
    {
        pthread_rwlock_destroy(&(*db)->db_lock);
        free(*db);
        return -1;
    }

    TDB_DEBUG_LOG("Database directory created/verified");

    /* clean up any temp files from incomplete operations */
    DIR *cleanup_dir = opendir(config->db_path);
    if (cleanup_dir)
    {
        struct dirent *entry;
        while ((entry = readdir(cleanup_dir)) != NULL)
        {
            if (strstr(entry->d_name, TDB_TEMP_EXT) != NULL)
            {
                char temp_file_path[TDB_MAX_PATH_LENGTH];
                (void)snprintf(temp_file_path, TDB_MAX_PATH_LENGTH, "%s/%s", config->db_path,
                               entry->d_name);
                TDB_DEBUG_LOG("Cleaning up incomplete temp file: %s", temp_file_path);
                unlink(temp_file_path);
            }
        }
        closedir(cleanup_dir);
    }

    /* scan for existing column families */
    DIR *dir = opendir(config->db_path);
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0)
            {
                /* load existing column family with default config */
                tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
                if (tidesdb_create_column_family(*db, entry->d_name, &cf_config) == -1)
                {
                    closedir(dir);
                    tidesdb_close(*db);
                    return -1;
                }
            }
        }
        closedir(dir);
    }

    return 0;
}

int tidesdb_close(tidesdb_t *db)
{
    if (!db) return -1;

    pthread_rwlock_wrlock(&db->db_lock);

    /* close all column families */
    for (int i = 0; i < db->num_cfs; i++)
    {
        tidesdb_column_family_t *cf = db->column_families[i];
        if (!cf) continue;

        /* stop background compaction thread if running */
        if (cf->config.enable_background_compaction)
        {
            atomic_store(&cf->compaction_stop, 1);
            pthread_join(cf->compaction_thread, NULL);
        }

        /* flush memtable to ensure data persistence */
        if (cf->memtable && atomic_load(&cf->memtable->total_size) > 0)
        {
            tidesdb_flush_memtable(cf);
        }

        /* close wal */
        if (cf->wal)
        {
            block_manager_close(cf->wal);
        }

        /* free sstables */
        for (int j = 0; j < cf->num_sstables; j++)
        {
            if (cf->sstables[j])
            {
                tidesdb_sstable_free(cf->sstables[j]);
            }
        }
        free(cf->sstables);

        /* free memtable */
        if (cf->memtable)
        {
            skip_list_free(cf->memtable);
        }

        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        free(cf);
    }

    free(db->column_families);
    pthread_rwlock_unlock(&db->db_lock);
    pthread_rwlock_destroy(&db->db_lock);
    free(db);

    return 0;
}

int tidesdb_create_column_family(tidesdb_t *db, const char *name,
                                 const tidesdb_column_family_config_t *config)
{
    if (!db || !name || strlen(name) >= TDB_MAX_CF_NAME_LENGTH) return -1;

    TDB_DEBUG_LOG("Creating column family: %s", name);

    pthread_rwlock_wrlock(&db->db_lock);

    /* check if column family already exists */
    for (int i = 0; i < db->num_cfs; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            TDB_DEBUG_LOG("Column family %s already exists", name);
            pthread_rwlock_unlock(&db->db_lock);
            return 0; /* already exists */
        }
    }

    /* allocate column family */
    tidesdb_column_family_t *cf = malloc(sizeof(tidesdb_column_family_t));
    if (!cf)
    {
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    strncpy(cf->name, name, TDB_MAX_CF_NAME_LENGTH - 1);
    cf->name[TDB_MAX_CF_NAME_LENGTH - 1] = '\0';
    cf->db = db;
    cf->sstables = NULL;
    atomic_store(&cf->num_sstables, 0);
    cf->sstable_array_capacity = 0;
    atomic_store(&cf->next_sstable_id, 0);
    atomic_store(&cf->compaction_stop, 0);

    /* use provided config or defaults */
    if (config)
    {
        memcpy(&cf->config, config, sizeof(tidesdb_column_family_config_t));
    }
    else
    {
        cf->config = tidesdb_default_column_family_config();
    }

    /* lookup comparator by name */
    const char *cmp_name = cf->config.comparator_name ? cf->config.comparator_name : "memcmp";
    skip_list_comparator_fn cmp_fn = tidesdb_get_comparator(cmp_name);

    if (!cmp_fn)
    {
        TDB_DEBUG_LOG("Comparator '%s' not found in registry", cmp_name);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    /* save comparator name */
    strncpy(cf->comparator_name, cmp_name, TDB_MAX_COMPARATOR_NAME - 1);
    cf->comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';

    TDB_DEBUG_LOG("Column family '%s' using comparator '%s'", name, cf->comparator_name);

    /* initialize locks */
    if (pthread_rwlock_init(&cf->cf_lock, NULL) != 0)
    {
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    if (pthread_mutex_init(&cf->flush_lock, NULL) != 0)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    if (pthread_mutex_init(&cf->compaction_lock, NULL) != 0)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    /* create column family directory */
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(db, name, cf_path);
    if (mkdir_p(cf_path) == -1)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    /* create memtable with comparator */
    if (skip_list_new_with_comparator(&cf->memtable, cf->config.max_level, cf->config.probability,
                                      cmp_fn, NULL) == -1)
    {
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    /* init sstables array (grows dynamically) */
    cf->sstables = NULL;
    cf->sstable_array_capacity = 0;

    /* open WAL */
    char wal_path[TDB_MAX_PATH_LENGTH];
    get_wal_path(cf, wal_path);
    if (block_manager_open(&cf->wal, wal_path, cf->config.sync_mode, cf->config.sync_interval) ==
        -1)
    {
        skip_list_free(cf->memtable);
        pthread_rwlock_destroy(&cf->cf_lock);
        pthread_mutex_destroy(&cf->flush_lock);
        pthread_mutex_destroy(&cf->compaction_lock);
        free(cf);
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    /* recover from WAL if it exists */
    tidesdb_recover_wal(cf);

    /* load existing sstables */
    DIR *dir = opendir(cf_path);
    if (dir)
    {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            if (strstr(entry->d_name, TDB_SSTABLE_EXT))
            {
                /* parse sstable ID using strtoul for safer conversion */
                const char *id_start = entry->d_name + 8; /* skip "sstable_" */
                char *endptr;
                uint64_t sstable_id = strtoul(id_start, &endptr, 10);
                if (endptr != id_start && strstr(endptr, ".sst"))
                {
                    tidesdb_sstable_t *sst = NULL;
                    if (tidesdb_load_sstable(cf, sstable_id, &sst) == 0)
                    {
                        /* grow array if needed */
                        if (cf->num_sstables >= cf->sstable_array_capacity)
                        {
                            int new_cap = cf->sstable_array_capacity == 0
                                              ? 8
                                              : cf->sstable_array_capacity * 2;
                            tidesdb_sstable_t **new_ssts = realloc(
                                cf->sstables, (size_t)new_cap * sizeof(tidesdb_sstable_t *));
                            if (new_ssts)
                            {
                                cf->sstables = new_ssts;
                                cf->sstable_array_capacity = new_cap;
                            }
                        }

                        if (cf->num_sstables < cf->sstable_array_capacity)
                        {
                            cf->sstables[cf->num_sstables] = sst;
                            atomic_fetch_add(&cf->num_sstables, 1);
                            if (sstable_id >= atomic_load(&cf->next_sstable_id))
                            {
                                atomic_store(&cf->next_sstable_id, sstable_id + 1);
                            }
                        }
                    }
                }
            }
        }
        closedir(dir);
    }

    /* start background compaction thread if enabled */
    if (cf->config.enable_background_compaction)
    {
        if (pthread_create(&cf->compaction_thread, NULL, tidesdb_background_compaction_thread,
                           cf) != 0)
        {
            /* failed to create thread, but continue anyway */
            cf->config.enable_background_compaction = 0;
        }
    }

    /* add to database */
    if (db->num_cfs >= db->cf_capacity)
    {
        int new_cap = db->cf_capacity == 0 ? 8 : db->cf_capacity * 2;
        tidesdb_column_family_t **new_cfs =
            realloc(db->column_families, (size_t)new_cap * sizeof(tidesdb_column_family_t *));
        if (!new_cfs)
        {
            skip_list_free(cf->memtable);
            block_manager_close(cf->wal);
            pthread_rwlock_destroy(&cf->cf_lock);
            pthread_mutex_destroy(&cf->flush_lock);
            pthread_mutex_destroy(&cf->compaction_lock);
            free(cf);
            pthread_rwlock_unlock(&db->db_lock);
            return -1;
        }
        db->column_families = new_cfs;
        db->cf_capacity = new_cap;
    }

    db->column_families[db->num_cfs++] = cf;

    pthread_rwlock_unlock(&db->db_lock);
    return 0;
}

int tidesdb_drop_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return -1;

    pthread_rwlock_wrlock(&db->db_lock);

    int found = -1;
    for (int i = 0; i < db->num_cfs; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            found = i;
            break;
        }
    }

    if (found == -1)
    {
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    tidesdb_column_family_t *cf = db->column_families[found];

    /* stop background compaction thread if running */
    if (cf->config.enable_background_compaction)
    {
        atomic_store(&cf->compaction_stop, 1);
        pthread_join(cf->compaction_thread, NULL);
    }

    /* close and delete WAL */
    if (cf->wal)
    {
        block_manager_close(cf->wal);
    }

    /* delete sstables */
    for (int i = 0; i < cf->num_sstables; i++)
    {
        if (cf->sstables[i])
        {
            char path[TDB_MAX_PATH_LENGTH];
            get_sstable_path(cf, cf->sstables[i]->id, path);
            unlink(path);
            tidesdb_sstable_free(cf->sstables[i]);
        }
    }
    free(cf->sstables);

    /* free memtable */
    if (cf->memtable)
    {
        skip_list_free(cf->memtable);
    }

    /* delete directory */
    char cf_path[TDB_MAX_PATH_LENGTH];
    get_cf_path(db, name, cf_path);
    rmdir(cf_path);

    pthread_rwlock_destroy(&cf->cf_lock);
    pthread_mutex_destroy(&cf->flush_lock);
    pthread_mutex_destroy(&cf->compaction_lock);
    free(cf);

    /* remove from array */
    for (int i = found; i < db->num_cfs - 1; i++)
    {
        db->column_families[i] = db->column_families[i + 1];
    }
    db->num_cfs--;

    pthread_rwlock_unlock(&db->db_lock);
    return 0;
}

tidesdb_column_family_t *tidesdb_get_column_family(tidesdb_t *db, const char *name)
{
    if (!db || !name) return NULL;

    pthread_rwlock_rdlock(&db->db_lock);

    for (int i = 0; i < db->num_cfs; i++)
    {
        if (strcmp(db->column_families[i]->name, name) == 0)
        {
            tidesdb_column_family_t *cf = db->column_families[i];
            pthread_rwlock_unlock(&db->db_lock);
            return cf;
        }
    }

    pthread_rwlock_unlock(&db->db_lock);
    return NULL;
}

int tidesdb_list_column_families(tidesdb_t *db, char ***names, int *count)
{
    if (!db || !names || !count) return -1;

    pthread_rwlock_rdlock(&db->db_lock);

    *count = db->num_cfs;

    if (*count == 0)
    {
        *names = NULL;
        pthread_rwlock_unlock(&db->db_lock);
        return 0;
    }

    /* alloc array of string pointers */
    *names = malloc(sizeof(char *) * (size_t)(*count));
    if (!*names)
    {
        pthread_rwlock_unlock(&db->db_lock);
        return -1;
    }

    /* copy each column family name */
    for (int i = 0; i < *count; i++)
    {
        (*names)[i] = malloc(TDB_MAX_CF_NAME_LENGTH);
        if (!(*names)[i])
        {
            /* free previously allocated names */
            for (int j = 0; j < i; j++)
            {
                free((*names)[j]);
            }
            free(*names);
            pthread_rwlock_unlock(&db->db_lock);
            return -1;
        }
        strncpy((*names)[i], db->column_families[i]->name, TDB_MAX_CF_NAME_LENGTH - 1);
        (*names)[i][TDB_MAX_CF_NAME_LENGTH - 1] = '\0';
    }

    pthread_rwlock_unlock(&db->db_lock);
    return 0;
}

int tidesdb_get_column_family_stats(tidesdb_t *db, const char *name,
                                    tidesdb_column_family_stat_t **stats)
{
    if (!db || !name || !stats) return -1;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, name);
    if (!cf) return -1;

    /* alloc stats struct */
    *stats = malloc(sizeof(tidesdb_column_family_stat_t));
    if (!*stats) return -1;

    pthread_rwlock_rdlock(&cf->cf_lock);

    /* copy basic info */
    strncpy((*stats)->name, cf->name, TDB_MAX_CF_NAME_LENGTH - 1);
    (*stats)->name[TDB_MAX_CF_NAME_LENGTH - 1] = '\0';

    strncpy((*stats)->comparator_name, cf->comparator_name, TDB_MAX_COMPARATOR_NAME - 1);
    (*stats)->comparator_name[TDB_MAX_COMPARATOR_NAME - 1] = '\0';

    /* sst stats */
    (*stats)->num_sstables = atomic_load(&cf->num_sstables);

    /* calc total ssts size */
    (*stats)->total_sstable_size = 0;
    for (int i = 0; i < (*stats)->num_sstables; i++)
    {
        if (cf->sstables[i] && cf->sstables[i]->block_manager)
        {
            uint64_t size = 0;
            if (block_manager_get_size(cf->sstables[i]->block_manager, &size) == 0)
            {
                (*stats)->total_sstable_size += size;
            }
        }
    }

    /* memtable stats */
    (*stats)->memtable_size = (size_t)skip_list_get_size(cf->memtable);
    (*stats)->memtable_entries = skip_list_count_entries(cf->memtable);

    /* copy config */
    memcpy(&(*stats)->config, &cf->config, sizeof(tidesdb_column_family_config_t));

    pthread_rwlock_unlock(&cf->cf_lock);
    return 0;
}

int tidesdb_flush_memtable(tidesdb_column_family_t *cf)
{
    if (!cf) return -1;

    TDB_DEBUG_LOG("Flushing memtable for column family: %s", cf->name);

    pthread_mutex_lock(&cf->flush_lock);
    pthread_rwlock_wrlock(&cf->cf_lock);

    if (skip_list_count_entries(cf->memtable) == 0)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->flush_lock);
        return 0; /* nothing to flush */
    }

    /* create new sstable */
    uint64_t sstable_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    char sstable_path[TDB_MAX_PATH_LENGTH];
    get_sstable_path(cf, sstable_id, sstable_path);

    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (!sst)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->flush_lock);
        return -1;
    }

    sst->id = sstable_id;
    sst->cf = cf;
    sst->min_key = NULL;
    sst->max_key = NULL;
    sst->num_entries = 0;

    /* open block manager */
    if (block_manager_open(&sst->block_manager, sstable_path, cf->config.sync_mode,
                           cf->config.sync_interval) == -1)
    {
        free(sst);
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->flush_lock);
        return -1;
    }

    /* create bloom filter and index */
    int num_entries = skip_list_count_entries(cf->memtable);
    bloom_filter_new(&sst->bloom_filter, cf->config.bloom_filter_fp_rate, num_entries);
    sst->index = binary_hash_array_new((size_t)num_entries);

    /* iterate through memtable and write to sstable */
    skip_list_cursor_t *cursor = skip_list_cursor_init(cf->memtable);
    if (cursor)
    {
        /* pos cursor at header (before first element) */
        cursor->current = cf->memtable->header;

        while (skip_list_cursor_has_next(cursor))
        {
            /* adv to next element */
            if (skip_list_cursor_next(cursor) != 0) break;

            uint8_t *k = NULL, *v = NULL;
            size_t k_size = 0, v_size = 0;
            time_t ttl = 0;
            uint8_t deleted = 0;

            if (skip_list_cursor_get(cursor, &k, &k_size, &v, &v_size, &ttl, &deleted) == 0)
            {
                /* store min/max keys */
                if (!sst->min_key)
                {
                    sst->min_key = malloc(k_size);
                    if (sst->min_key)
                    {
                        memcpy(sst->min_key, k, k_size);
                        sst->min_key_size = k_size;
                    }
                }

                if (sst->max_key) free(sst->max_key);
                sst->max_key = malloc(k_size);
                if (sst->max_key)
                {
                    memcpy(sst->max_key, k, k_size);
                    sst->max_key_size = k_size;
                }

                /* create block data with streamlined format: [header][key][value] */
                tidesdb_kv_pair_header_t header = {.version = TDB_KV_FORMAT_VERSION,
                                                   .flags = deleted ? TDB_KV_FLAG_TOMBSTONE : 0,
                                                   .key_size = (uint32_t)k_size,
                                                   .value_size = (uint32_t)v_size,
                                                   .ttl = (int64_t)ttl};

                size_t block_size = sizeof(tidesdb_kv_pair_header_t) + k_size + v_size;
                uint8_t *block_data = malloc(block_size);
                if (block_data)
                {
                    uint8_t *ptr = block_data;
                    memcpy(ptr, &header, sizeof(tidesdb_kv_pair_header_t));
                    ptr += sizeof(tidesdb_kv_pair_header_t);
                    memcpy(ptr, k, k_size);
                    ptr += k_size;
                    memcpy(ptr, v, v_size);

                    /* optionally compress */
                    uint8_t *final_data = block_data;
                    size_t final_size = block_size;

                    if (cf->config.compressed)
                    {
                        size_t compressed_size = 0;
                        uint8_t *compressed = compress_data(
                            block_data, block_size, &compressed_size, cf->config.compress_algo);
                        if (compressed)
                        {
                            free(block_data);
                            final_data = compressed;
                            final_size = compressed_size;
                        }
                    }

                    /* write block and get offset */
                    block_manager_block_t *block =
                        block_manager_block_create(final_size, final_data);
                    if (block)
                    {
                        long offset = block_manager_block_write(sst->block_manager, block);
                        if (offset >= 0)
                        {
                            /* add to bloom filter and index */
                            bloom_filter_add(sst->bloom_filter, k, k_size);
                            binary_hash_array_add(sst->index, k, k_size, offset);
                            sst->num_entries++;
                        }
                        block_manager_block_free(block);
                    }
                    free(final_data);
                }
            }
        }
        skip_list_cursor_free(cursor);
    }

    /* write bloom filter and index as metadata blocks */
    size_t bloom_size = 0;
    uint8_t *bloom_data = bloom_filter_serialize(sst->bloom_filter, &bloom_size);
    if (bloom_data)
    {
        block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
        if (bloom_block)
        {
            block_manager_block_write(sst->block_manager, bloom_block);
            block_manager_block_free(bloom_block);
        }
        free(bloom_data);
    }

    size_t index_size = 0;
    uint8_t *index_data = binary_hash_array_serialize(sst->index, &index_size);
    if (index_data)
    {
        block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
        if (index_block)
        {
            block_manager_block_write(sst->block_manager, index_block);
            block_manager_block_free(index_block);
        }
        free(index_data);
    }

    /* write metadata block [magic][num_entries][min_key_size][min_key][max_key_size][max_key] */
    if (sst->min_key && sst->max_key)
    {
        uint32_t magic = 0x5353544D; /* "SSTM"  sst metadata */
        size_t metadata_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) +
                               sst->min_key_size + sizeof(uint32_t) + sst->max_key_size;
        uint8_t *metadata = malloc(metadata_size);
        if (metadata)
        {
            uint8_t *ptr = metadata;
            memcpy(ptr, &magic, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            uint64_t num_entries_u64 = (uint64_t)sst->num_entries;
            memcpy(ptr, &num_entries_u64, sizeof(uint64_t));
            ptr += sizeof(uint64_t);
            uint32_t min_size = (uint32_t)sst->min_key_size;
            memcpy(ptr, &min_size, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy(ptr, sst->min_key, sst->min_key_size);
            ptr += sst->min_key_size;
            uint32_t max_size = (uint32_t)sst->max_key_size;
            memcpy(ptr, &max_size, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy(ptr, sst->max_key, sst->max_key_size);

            block_manager_block_t *metadata_block =
                block_manager_block_create(metadata_size, metadata);
            if (metadata_block)
            {
                block_manager_block_write(sst->block_manager, metadata_block);
                block_manager_block_free(metadata_block);
            }
            free(metadata);
        }
    }

    /* add sstable to array - grow if needed */
    if (cf->num_sstables >= cf->sstable_array_capacity)
    {
        int new_cap = cf->sstable_array_capacity == 0 ? 8 : cf->sstable_array_capacity * 2;
        tidesdb_sstable_t **new_ssts =
            realloc(cf->sstables, (size_t)new_cap * sizeof(tidesdb_sstable_t *));
        if (new_ssts)
        {
            cf->sstables = new_ssts;
            cf->sstable_array_capacity = new_cap;
        }
    }

    if (cf->num_sstables < cf->sstable_array_capacity)
    {
        cf->sstables[cf->num_sstables] = sst;
        atomic_fetch_add(&cf->num_sstables, 1);
    }

    /* clear memtable and WAL */
    skip_list_clear(cf->memtable);
    block_manager_truncate(cf->wal);

    pthread_rwlock_unlock(&cf->cf_lock);
    pthread_mutex_unlock(&cf->flush_lock);

    return 0;
}

int tidesdb_compact(tidesdb_column_family_t *cf)
{
    if (!cf) return -1;

    /* route to parallel compaction if threads > 0 */
    if (cf->config.compaction_threads > 0)
    {
        return tidesdb_compact_parallel(cf);
    }

    TDB_DEBUG_LOG("Starting single-threaded compaction for column family: %s (sstables: %d)",
                  cf->name, atomic_load(&cf->num_sstables));

    pthread_mutex_lock(&cf->compaction_lock);
    pthread_rwlock_wrlock(&cf->cf_lock);

    int num_ssts = atomic_load(&cf->num_sstables);
    if (num_ssts < 2)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return 0; /* nothing to compact */
    }

    /* pairwise merging: merge pairs of sstables */
    int pairs_to_merge = num_ssts / 2;

    for (int p = 0; p < pairs_to_merge; p++)
    {
        tidesdb_sstable_t *sst1 = cf->sstables[p * 2];
        tidesdb_sstable_t *sst2 = cf->sstables[p * 2 + 1];

        if (!sst1 || !sst2) continue;

        /* create new merged sstable with temp extension */
        uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
        char new_path[TDB_MAX_PATH_LENGTH];
        char temp_path[TDB_MAX_PATH_LENGTH];
        get_sstable_path(cf, new_id, new_path);
        (void)snprintf(temp_path, TDB_MAX_PATH_LENGTH, "%s%s", new_path, TDB_TEMP_EXT);

        TDB_DEBUG_LOG("Compacting sstables %llu and %llu into %llu (temp: %s)",
                      (unsigned long long)sst1->id, (unsigned long long)sst2->id,
                      (unsigned long long)new_id, temp_path);

        tidesdb_sstable_t *merged = malloc(sizeof(tidesdb_sstable_t));
        if (!merged) continue;

        merged->id = new_id;
        merged->cf = cf;
        merged->min_key = NULL;
        merged->max_key = NULL;
        merged->num_entries = 0;

        if (block_manager_open(&merged->block_manager, temp_path, cf->config.sync_mode,
                               cf->config.sync_interval) == -1)
        {
            free(merged);
            continue;
        }

        bloom_filter_new(&merged->bloom_filter, cf->config.bloom_filter_fp_rate,
                         sst1->num_entries + sst2->num_entries);
        merged->index =
            binary_hash_array_new((size_t)sst1->num_entries + (size_t)sst2->num_entries);

        /* merge entries from both sstables using cursors */
        block_manager_cursor_t *cursor1 = NULL;
        block_manager_cursor_t *cursor2 = NULL;
        block_manager_cursor_init(&cursor1, sst1->block_manager);
        block_manager_cursor_init(&cursor2, sst2->block_manager);

        if (cursor1) block_manager_cursor_goto_first(cursor1);
        if (cursor2) block_manager_cursor_goto_first(cursor2);

        int has1 = cursor1 ? block_manager_cursor_has_next(cursor1) : 0;
        int has2 = cursor2 ? block_manager_cursor_has_next(cursor2) : 0;

        while (has1 || has2)
        {
            block_manager_block_t *block = NULL;
            /* use cursor1 unless only cursor2 has data */
            int use1 = !(has2 && !has1);

            if (use1 && has1)
            {
                block = block_manager_cursor_read(cursor1);
                block_manager_cursor_next(cursor1);
                has1 = block_manager_cursor_has_next(cursor1);
            }
            else if (has2)
            {
                block = block_manager_cursor_read(cursor2);
                block_manager_cursor_next(cursor2);
                has2 = block_manager_cursor_has_next(cursor2);
            }

            if (block && block->data)
            {
                /* decompress if needed */
                uint8_t *data = block->data;
                size_t data_size = block->size;

                if (cf->config.compressed)
                {
                    size_t decompressed_size = 0;
                    uint8_t *decompressed = decompress_data(data, data_size, &decompressed_size,
                                                            cf->config.compress_algo);
                    if (decompressed)
                    {
                        data = decompressed;
                        data_size = decompressed_size;
                    }
                }

                /* parse key from block using new format */
                if (data_size < sizeof(tidesdb_kv_pair_header_t))
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                tidesdb_kv_pair_header_t header;
                memcpy(&header, data, sizeof(tidesdb_kv_pair_header_t));

                /* skip tombstones during compaction */
                if (header.flags & TDB_KV_FLAG_TOMBSTONE)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                /* skip expired entries during compaction */
                if (header.ttl > 0 && time(NULL) > header.ttl)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }

                uint8_t *key = data + sizeof(tidesdb_kv_pair_header_t);
                size_t k_size = header.key_size;

                /* copy key to avoid use-after-free when data is freed */
                uint8_t *key_copy = malloc(k_size);
                if (!key_copy)
                {
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    continue;
                }
                memcpy(key_copy, key, k_size);

                /* write to merged sstable */
                uint8_t *final_data = data;
                size_t final_size = data_size;

                if (cf->config.compressed)
                {
                    size_t compressed_size = 0;
                    uint8_t *compressed =
                        compress_data(data, data_size, &compressed_size, cf->config.compress_algo);
                    if (compressed)
                    {
                        if (data != block->data)
                        {
                            free(data);
                            data = NULL;
                        }
                        final_data = compressed;
                        final_size = compressed_size;
                    }
                }

                block_manager_block_t *new_block =
                    block_manager_block_create(final_size, final_data);
                if (new_block)
                {
                    long offset = block_manager_block_write(merged->block_manager, new_block);
                    if (offset >= 0)
                    {
                        bloom_filter_add(merged->bloom_filter, key_copy, k_size);
                        binary_hash_array_add(merged->index, key_copy, k_size, offset);
                        merged->num_entries++;

                        if (!merged->min_key)
                        {
                            merged->min_key = malloc(k_size);
                            if (merged->min_key)
                            {
                                memcpy(merged->min_key, key_copy, k_size);
                                merged->min_key_size = k_size;
                            }
                        }

                        if (merged->max_key) free(merged->max_key);
                        merged->max_key = malloc(k_size);
                        if (merged->max_key)
                        {
                            memcpy(merged->max_key, key_copy, k_size);
                            merged->max_key_size = k_size;
                        }
                    }
                    block_manager_block_free(new_block);
                }

                free(key_copy);
                if (final_data != data && final_data != block->data) free(final_data);
                if (data && data != block->data) free(data);
                block_manager_block_free(block);
            }
        }

        if (cursor1) block_manager_cursor_free(cursor1);
        if (cursor2) block_manager_cursor_free(cursor2);

        /* write metadata */
        size_t bloom_size = 0;
        uint8_t *bloom_data = bloom_filter_serialize(merged->bloom_filter, &bloom_size);
        if (bloom_data)
        {
            block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
            if (bloom_block)
            {
                block_manager_block_write(merged->block_manager, bloom_block);
                block_manager_block_free(bloom_block);
            }
            free(bloom_data);
        }

        size_t index_size = 0;
        uint8_t *index_data = binary_hash_array_serialize(merged->index, &index_size);
        if (index_data)
        {
            block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
            if (index_block)
            {
                block_manager_block_write(merged->block_manager, index_block);
                block_manager_block_free(index_block);
            }
            free(index_data);
        }

        /* close block manager before rename */
        block_manager_close(merged->block_manager);
        merged->block_manager = NULL;

        /* rename temp file to final name (atomic operation) */
        if (rename(temp_path, new_path) == 0)
        {
            TDB_DEBUG_LOG("Successfully renamed %s to %s", temp_path, new_path);
            /* reopen with final path */
            if (block_manager_open(&merged->block_manager, new_path, cf->config.sync_mode,
                                   cf->config.sync_interval) == -1)
            {
                TDB_DEBUG_LOG("Failed to reopen merged sstable after rename");
                tidesdb_sstable_free(merged);
                continue;
            }
        }
        else
        {
            TDB_DEBUG_LOG("Failed to rename temp file, cleaning up");
            unlink(temp_path);
            tidesdb_sstable_free(merged);
            continue;
        }

        /* delete old sstables */
        char path1[TDB_MAX_PATH_LENGTH], path2[TDB_MAX_PATH_LENGTH];
        get_sstable_path(cf, sst1->id, path1);
        get_sstable_path(cf, sst2->id, path2);
        unlink(path1);
        unlink(path2);

        tidesdb_sstable_free(sst1);
        tidesdb_sstable_free(sst2);

        /* replace in array */
        cf->sstables[p * 2] = merged;
        cf->sstables[p * 2 + 1] = NULL;
    }

    /* compact array */
    int new_count = 0;
    for (int i = 0; i < num_ssts; i++)
    {
        if (cf->sstables[i])
        {
            cf->sstables[new_count++] = cf->sstables[i];
        }
    }
    atomic_store(&cf->num_sstables, new_count);

    pthread_rwlock_unlock(&cf->cf_lock);
    pthread_mutex_unlock(&cf->compaction_lock);

    return 0;
}

/* parallel compaction structures */
typedef struct
{
    tidesdb_column_family_t *cf;
    tidesdb_sstable_t *sst1;
    tidesdb_sstable_t *sst2;
    tidesdb_sstable_t **result;
    sem_t *semaphore;
    int *error;
} compaction_job_t;

/* worker thread function for parallel compaction */
static void *tidesdb_compaction_worker(void *arg)
{
    compaction_job_t *job = (compaction_job_t *)arg;
    tidesdb_column_family_t *cf = job->cf;
    tidesdb_sstable_t *sst1 = job->sst1;
    tidesdb_sstable_t *sst2 = job->sst2;

    /* create new merged sstable with temp extension */
    uint64_t new_id = atomic_fetch_add(&cf->next_sstable_id, 1);
    char new_path[TDB_MAX_PATH_LENGTH];
    char temp_path[TDB_MAX_PATH_LENGTH];
    get_sstable_path(cf, new_id, new_path);
    (void)snprintf(temp_path, TDB_MAX_PATH_LENGTH, "%s%s", new_path, TDB_TEMP_EXT);

    TDB_DEBUG_LOG("[Thread] Compacting sstables %llu and %llu into %llu",
                  (unsigned long long)sst1->id, (unsigned long long)sst2->id,
                  (unsigned long long)new_id);

    tidesdb_sstable_t *merged = malloc(sizeof(tidesdb_sstable_t));
    if (!merged)
    {
        *job->error = 1;
        sem_post(job->semaphore);
        return NULL;
    }

    merged->id = new_id;
    merged->cf = cf;
    merged->min_key = NULL;
    merged->max_key = NULL;
    merged->num_entries = 0;

    if (block_manager_open(&merged->block_manager, temp_path, cf->config.sync_mode,
                           cf->config.sync_interval) == -1)
    {
        free(merged);
        *job->error = 1;
        sem_post(job->semaphore);
        return NULL;
    }

    bloom_filter_new(&merged->bloom_filter, cf->config.bloom_filter_fp_rate,
                     sst1->num_entries + sst2->num_entries);
    merged->index = binary_hash_array_new((size_t)sst1->num_entries + (size_t)sst2->num_entries);

    /* merge entries from both sstables */
    block_manager_cursor_t *cursor1 = NULL;
    block_manager_cursor_t *cursor2 = NULL;
    block_manager_cursor_init(&cursor1, sst1->block_manager);
    block_manager_cursor_init(&cursor2, sst2->block_manager);

    if (cursor1) block_manager_cursor_goto_first(cursor1);
    if (cursor2) block_manager_cursor_goto_first(cursor2);

    int has1 = cursor1 ? block_manager_cursor_has_next(cursor1) : 0;
    int has2 = cursor2 ? block_manager_cursor_has_next(cursor2) : 0;

    while (has1 || has2)
    {
        block_manager_block_t *block = NULL;
        /* use cursor1 unless only cursor2 has data */
        int use1 = !(has2 && !has1);

        if (use1 && has1)
        {
            block = block_manager_cursor_read(cursor1);
            block_manager_cursor_next(cursor1);
            has1 = block_manager_cursor_has_next(cursor1);
        }
        else if (has2)
        {
            block = block_manager_cursor_read(cursor2);
            block_manager_cursor_next(cursor2);
            has2 = block_manager_cursor_has_next(cursor2);
        }

        if (block && block->data)
        {
            uint8_t *data = block->data;
            size_t data_size = block->size;

            if (cf->config.compressed)
            {
                size_t decompressed_size = 0;
                uint8_t *decompressed =
                    decompress_data(data, data_size, &decompressed_size, cf->config.compress_algo);
                if (decompressed)
                {
                    data = decompressed;
                    data_size = decompressed_size;
                }
            }

            if (data_size >= sizeof(tidesdb_kv_pair_header_t))
            {
                tidesdb_kv_pair_header_t header;
                memcpy(&header, data, sizeof(tidesdb_kv_pair_header_t));

                /* skip tombstones and expired entries */
                if (!(header.flags & TDB_KV_FLAG_TOMBSTONE) &&
                    !(header.ttl > 0 && time(NULL) > header.ttl))
                {
                    uint8_t *key = data + sizeof(tidesdb_kv_pair_header_t);
                    size_t k_size = header.key_size;

                    /* write to merged sst */
                    uint8_t *final_data = data;
                    size_t final_size = data_size;

                    if (cf->config.compressed)
                    {
                        size_t compressed_size = 0;
                        uint8_t *compressed = compress_data(data, data_size, &compressed_size,
                                                            cf->config.compress_algo);
                        if (compressed)
                        {
                            final_data = compressed;
                            final_size = compressed_size;
                        }
                    }

                    block_manager_block_t *new_block =
                        block_manager_block_create(final_size, final_data);
                    if (new_block)
                    {
                        long offset = block_manager_block_write(merged->block_manager, new_block);
                        if (offset >= 0)
                        {
                            bloom_filter_add(merged->bloom_filter, key, k_size);
                            binary_hash_array_add(merged->index, key, k_size, offset);
                            merged->num_entries++;

                            /* update min/max keys */
                            if (!merged->min_key)
                            {
                                merged->min_key = malloc(k_size);
                                if (merged->min_key)
                                {
                                    memcpy(merged->min_key, key, k_size);
                                    merged->min_key_size = k_size;
                                }
                            }
                            if (merged->max_key) free(merged->max_key);
                            merged->max_key = malloc(k_size);
                            if (merged->max_key)
                            {
                                memcpy(merged->max_key, key, k_size);
                                merged->max_key_size = k_size;
                            }
                        }
                        block_manager_block_free(new_block);
                    }

                    if (cf->config.compressed && final_data != data)
                    {
                        free(final_data);
                    }
                }
            }

            if (cf->config.compressed && data != block->data)
            {
                free(data);
            }
            block_manager_block_free(block);
        }
    }

    if (cursor1) block_manager_cursor_free(cursor1);
    if (cursor2) block_manager_cursor_free(cursor2);

    /* write metadata */
    if (merged->min_key && merged->max_key)
    {
        uint32_t magic = 0x5353544D;
        size_t metadata_size = sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint32_t) +
                               merged->min_key_size + sizeof(uint32_t) + merged->max_key_size;
        uint8_t *metadata = malloc(metadata_size);
        if (metadata)
        {
            uint8_t *ptr = metadata;
            memcpy(ptr, &magic, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            uint64_t num_entries = (uint64_t)merged->num_entries;
            memcpy(ptr, &num_entries, sizeof(uint64_t));
            ptr += sizeof(uint64_t);
            uint32_t min_size = (uint32_t)merged->min_key_size;
            memcpy(ptr, &min_size, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy(ptr, merged->min_key, merged->min_key_size);
            ptr += merged->min_key_size;
            uint32_t max_size = (uint32_t)merged->max_key_size;
            memcpy(ptr, &max_size, sizeof(uint32_t));
            ptr += sizeof(uint32_t);
            memcpy(ptr, merged->max_key, merged->max_key_size);

            block_manager_block_t *metadata_block =
                block_manager_block_create(metadata_size, metadata);
            if (metadata_block)
            {
                block_manager_block_write(merged->block_manager, metadata_block);
                block_manager_block_free(metadata_block);
            }
            free(metadata);
        }
    }

    /* write bloom filter and index */
    size_t bloom_size = 0;
    uint8_t *bloom_data = bloom_filter_serialize(merged->bloom_filter, &bloom_size);
    if (bloom_data)
    {
        block_manager_block_t *bloom_block = block_manager_block_create(bloom_size, bloom_data);
        if (bloom_block)
        {
            block_manager_block_write(merged->block_manager, bloom_block);
            block_manager_block_free(bloom_block);
        }
        free(bloom_data);
    }

    size_t index_size = 0;
    uint8_t *index_data = binary_hash_array_serialize(merged->index, &index_size);
    if (index_data)
    {
        block_manager_block_t *index_block = block_manager_block_create(index_size, index_data);
        if (index_block)
        {
            block_manager_block_write(merged->block_manager, index_block);
            block_manager_block_free(index_block);
        }
        free(index_data);
    }

    block_manager_close(merged->block_manager);

    /* rename temp to final */
    if (rename(temp_path, new_path) == 0)
    {
        if (block_manager_open(&merged->block_manager, new_path, cf->config.sync_mode,
                               cf->config.sync_interval) == 0)
        {
            *job->result = merged;
        }
        else
        {
            tidesdb_sstable_free(merged);
            *job->error = 1;
        }
    }
    else
    {
        tidesdb_sstable_free(merged);
        *job->error = 1;
    }

    sem_post(job->semaphore);
    return NULL;
}

int tidesdb_compact_parallel(tidesdb_column_family_t *cf)
{
    if (!cf) return -1;

    TDB_DEBUG_LOG("Starting parallel compaction for column family: %s (sstables: %d, threads: %d)",
                  cf->name, atomic_load(&cf->num_sstables), cf->config.compaction_threads);

    pthread_mutex_lock(&cf->compaction_lock);
    pthread_rwlock_wrlock(&cf->cf_lock);

    int num_ssts = atomic_load(&cf->num_sstables);
    if (num_ssts < 2)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return 0;
    }

    int pairs_to_merge = num_ssts / 2;
    int num_threads = cf->config.compaction_threads;
    if (num_threads > pairs_to_merge) num_threads = pairs_to_merge;

    /* init semaphore to limit concurrent threads */
    sem_t semaphore;
    if (sem_init(&semaphore, 0, (unsigned int)num_threads) != 0)
    {
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return -1;
    }

    /* allocate arrays for jobs, threads, and results */
    compaction_job_t *jobs = calloc((size_t)pairs_to_merge, sizeof(compaction_job_t));
    pthread_t *threads = calloc((size_t)pairs_to_merge, sizeof(pthread_t));
    tidesdb_sstable_t **merged_sstables =
        calloc((size_t)pairs_to_merge, sizeof(tidesdb_sstable_t *));
    int *errors = calloc((size_t)pairs_to_merge, sizeof(int));

    if (!jobs || !threads || !merged_sstables || !errors)
    {
        free(jobs);
        free(threads);
        free(merged_sstables);
        free(errors);
        sem_destroy(&semaphore);
        pthread_rwlock_unlock(&cf->cf_lock);
        pthread_mutex_unlock(&cf->compaction_lock);
        return -1;
    }

    /* launch worker threads for each pair */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        sem_wait(&semaphore);

        jobs[p].cf = cf;
        jobs[p].sst1 = cf->sstables[p * 2];
        jobs[p].sst2 = cf->sstables[p * 2 + 1];
        jobs[p].result = &merged_sstables[p];
        jobs[p].semaphore = &semaphore;
        jobs[p].error = &errors[p];

        pthread_create(&threads[p], NULL, tidesdb_compaction_worker, &jobs[p]);
    }

    /* wait for all threads to complete */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        pthread_join(threads[p], NULL);
    }

    /* clean up old SSTables and update array */
    for (int p = 0; p < pairs_to_merge; p++)
    {
        if (!errors[p] && merged_sstables[p])
        {
            /* delete old sstable files */
            tidesdb_sstable_t *sst1 = cf->sstables[p * 2];
            tidesdb_sstable_t *sst2 = cf->sstables[p * 2 + 1];

            char path1[TDB_MAX_PATH_LENGTH];
            char path2[TDB_MAX_PATH_LENGTH];
            get_sstable_path(cf, sst1->id, path1);
            get_sstable_path(cf, sst2->id, path2);

            tidesdb_sstable_free(sst1);
            tidesdb_sstable_free(sst2);
            remove(path1);
            remove(path2);
        }
    }

    /* rebuild sstable array */
    tidesdb_sstable_t **new_sstables =
        malloc((size_t)(pairs_to_merge + (num_ssts % 2)) * sizeof(tidesdb_sstable_t *));
    int new_count = 0;

    for (int p = 0; p < pairs_to_merge; p++)
    {
        if (!errors[p] && merged_sstables[p])
        {
            new_sstables[new_count++] = merged_sstables[p];
        }
    }

    /* add odd sst if exists */
    if (num_ssts % 2 == 1)
    {
        new_sstables[new_count++] = cf->sstables[num_ssts - 1];
    }

    free(cf->sstables);
    cf->sstables = new_sstables;
    atomic_store(&cf->num_sstables, new_count);

    /* cleanup */
    free(jobs);
    free(threads);
    free(merged_sstables);
    free(errors);
    sem_destroy(&semaphore);

    pthread_rwlock_unlock(&cf->cf_lock);
    pthread_mutex_unlock(&cf->compaction_lock);

    TDB_DEBUG_LOG("Parallel compaction complete: %d -> %d sstables", num_ssts, new_count);
    return 0;
}

static void *tidesdb_background_compaction_thread(void *arg)
{
    tidesdb_column_family_t *cf = (tidesdb_column_family_t *)arg;

    while (!atomic_load(&cf->compaction_stop))
    {
        /* check if compaction is needed (minimum 2 SSTables required) */
        int num_ssts = atomic_load(&cf->num_sstables);
        if (num_ssts >= 2 && num_ssts >= cf->config.max_sstables_before_compaction)
        {
            /* attempt compaction */
            tidesdb_compact(cf);
        }

        /* sleep for 1 second before checking again */
        sleep(1);
    }

    return NULL;
}

static int tidesdb_check_and_flush(tidesdb_column_family_t *cf)
{
    if (!cf) return -1;

    size_t memtable_size = (size_t)skip_list_get_size(cf->memtable);
    if (memtable_size >= cf->config.memtable_flush_size)
    {
        int result = tidesdb_flush_memtable(cf);

        /* after flush, check if we need compaction (requires at least 2 ssts) */
        int num_ssts = atomic_load(&cf->num_sstables);
        if (result == 0 && num_ssts >= 2 && num_ssts >= cf->config.max_sstables_before_compaction)
        {
            tidesdb_compact(cf);
        }

        return result;
    }

    return 0;
}

static int tidesdb_load_sstable(tidesdb_column_family_t *cf, uint64_t sstable_id,
                                tidesdb_sstable_t **sstable)
{
    if (!cf || !sstable) return -1;

    char path[TDB_MAX_PATH_LENGTH];
    get_sstable_path(cf, sstable_id, path);

    tidesdb_sstable_t *sst = malloc(sizeof(tidesdb_sstable_t));
    if (!sst) return -1;

    sst->id = sstable_id;
    sst->cf = cf;
    sst->min_key = NULL;
    sst->max_key = NULL;
    sst->num_entries = 0;
    sst->bloom_filter = NULL;
    sst->index = NULL;

    if (block_manager_open(&sst->block_manager, path, cf->config.sync_mode,
                           cf->config.sync_interval) == -1)
    {
        free(sst);
        return -1;
    }

    /* load metadata, index, and bloom filter from last blocks */
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, sst->block_manager) == 0)
    {
        block_manager_cursor_goto_last(cursor);

        /* try to read metadata (last block) - check for magic number */
        block_manager_block_t *metadata_block = block_manager_cursor_read(cursor);
        int has_metadata = 0;
        if (metadata_block && metadata_block->data &&
            metadata_block->size >= sizeof(uint32_t) + sizeof(uint64_t) + 2 * sizeof(uint32_t))
        {
            /* check for magic number "SSTM" */
            uint8_t *ptr = metadata_block->data;
            uint32_t magic;
            memcpy(&magic, ptr, sizeof(uint32_t));

            if (magic == 0x5353544D) /* "SSTM" */
            {
                ptr += sizeof(uint32_t);
                uint64_t num_entries;
                memcpy(&num_entries, ptr, sizeof(uint64_t));
                ptr += sizeof(uint64_t);
                uint32_t min_key_size;
                memcpy(&min_key_size, ptr, sizeof(uint32_t));
                ptr += sizeof(uint32_t);

                sst->num_entries = (int)num_entries;
                sst->min_key = malloc(min_key_size);
                if (sst->min_key)
                {
                    memcpy(sst->min_key, ptr, min_key_size);
                    sst->min_key_size = min_key_size;
                }
                ptr += min_key_size;
                uint32_t max_key_size;
                memcpy(&max_key_size, ptr, sizeof(uint32_t));
                ptr += sizeof(uint32_t);
                sst->max_key = malloc(max_key_size);
                if (sst->max_key)
                {
                    memcpy(sst->max_key, ptr, max_key_size);
                    sst->max_key_size = max_key_size;
                }
                has_metadata = 1;
            }
        }
        if (metadata_block) block_manager_block_free(metadata_block);

        /* read index */
        if (has_metadata)
        {
            block_manager_cursor_prev(cursor);
        }
        block_manager_block_t *index_block = block_manager_cursor_read(cursor);
        if (index_block && index_block->data)
        {
            sst->index = binary_hash_array_deserialize(index_block->data);
            block_manager_block_free(index_block);
        }

        /* read bloom filter */
        block_manager_cursor_prev(cursor);
        block_manager_block_t *bloom_block = block_manager_cursor_read(cursor);
        if (bloom_block && bloom_block->data)
        {
            sst->bloom_filter = bloom_filter_deserialize(bloom_block->data);
            block_manager_block_free(bloom_block);
        }

        block_manager_cursor_free(cursor);
    }

    *sstable = sst;
    return 0;
}

static int tidesdb_sstable_get(tidesdb_sstable_t *sstable, const uint8_t *key, size_t key_size,
                               uint8_t **value, size_t *value_size)
{
    if (!sstable || !key || !value || !value_size) return -1;

    /* check bloom filter first */
    if (sstable->bloom_filter && !bloom_filter_contains(sstable->bloom_filter, key, key_size))
    {
        return -1; /* definitely not in sstable */
    }

    int64_t offset = -1;

    /* if SBHA is enabled, use it for direct lookup */
    if (sstable->cf->config.use_sbha && sstable->index)
    {
        offset = binary_hash_array_contains(sstable->index, (uint8_t *)key, key_size);
        if (offset < 0) return -1; /* not found in index */
    }
    else
    {
        /* fallback is linear scan through blocks (slower) */
        block_manager_cursor_t *cursor = NULL;
        if (block_manager_cursor_init(&cursor, sstable->block_manager) != 0) return -1;

        block_manager_cursor_goto_first(cursor);

        while (block_manager_cursor_has_next(cursor))
        {
            block_manager_block_t *block = block_manager_cursor_read(cursor);
            if (block && block->data)
            {
                /* decompress if needed */
                uint8_t *data = block->data;
                size_t data_size = block->size;

                if (sstable->cf->config.compressed)
                {
                    size_t decompressed_size = 0;
                    uint8_t *decompressed = decompress_data(data, data_size, &decompressed_size,
                                                            sstable->cf->config.compress_algo);
                    if (decompressed)
                    {
                        data = decompressed;
                        data_size = decompressed_size;
                    }
                }

                /* parse key */
                uint8_t *ptr = data;
                size_t k_size = 0;
                memcpy(&k_size, ptr, sizeof(size_t));
                ptr += sizeof(size_t);
                uint8_t *block_key = ptr;

                if (k_size == key_size && memcmp(block_key, key, key_size) == 0)
                {
                    /* found it, get the offset and break */
                    block_manager_cursor_t *offset_cursor = NULL;
                    block_manager_cursor_init(&offset_cursor, sstable->block_manager);
                    /* get current position - simplified, just use 0 for now */
                    if (data != block->data) free(data);
                    block_manager_block_free(block);
                    block_manager_cursor_free(cursor);
                    /* fallback to indexed lookup not implemented fully */
                    return -1;
                }

                if (data != block->data) free(data);
                block_manager_block_free(block);
            }
            block_manager_cursor_next(cursor);
        }

        block_manager_cursor_free(cursor);
        return -1; /* not found */
    }

    /* read block at offset from SBHA */
    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, sstable->block_manager) != 0) return -1;

    if (block_manager_cursor_goto(cursor, (uint64_t)offset) != 0)
    {
        block_manager_cursor_free(cursor);
        return -1;
    }

    block_manager_block_t *block = block_manager_cursor_read(cursor);
    block_manager_cursor_free(cursor);

    if (!block || !block->data)
    {
        if (block) block_manager_block_free(block);
        return -1;
    }

    /* decompress if needed */
    uint8_t *data = block->data;
    size_t data_size = block->size;

    if (sstable->cf->config.compressed)
    {
        size_t decompressed_size = 0;
        uint8_t *decompressed =
            decompress_data(data, data_size, &decompressed_size, sstable->cf->config.compress_algo);
        if (decompressed)
        {
            data = decompressed;
            data_size = decompressed_size;
        }
    }

    /* parse block using new format: [header][key][value] */
    if (data_size < sizeof(tidesdb_kv_pair_header_t))
    {
        if (data != block->data) free(data);
        block_manager_block_free(block);
        return -1;
    }

    tidesdb_kv_pair_header_t header;
    memcpy(&header, data, sizeof(tidesdb_kv_pair_header_t));

    uint8_t *ptr = data + sizeof(tidesdb_kv_pair_header_t);
    uint8_t *block_key = ptr;
    ptr += header.key_size;
    uint8_t *block_value = ptr;

    /* verify key matches */
    if (header.key_size != key_size || memcmp(block_key, key, key_size) != 0)
    {
        if (data != block->data) free(data);
        block_manager_block_free(block);
        return -1;
    }

    /* check if deleted (tombstone) or expired */
    int is_deleted = (header.flags & TDB_KV_FLAG_TOMBSTONE) != 0;
    int is_expired = (header.ttl > 0 && time(NULL) > header.ttl);

    if (is_deleted || is_expired)
    {
        if (data != block->data) free(data);
        block_manager_block_free(block);
        return -1;
    }

    /* copy value, handle empty values */
    if (header.value_size > 0)
    {
        *value = malloc(header.value_size);
        if (!*value)
        {
            if (data != block->data) free(data);
            block_manager_block_free(block);
            return -1;
        }
        memcpy(*value, block_value, header.value_size);
    }
    else
    {
        *value = malloc(1);
        if (!*value)
        {
            if (data != block->data) free(data);
            block_manager_block_free(block);
            return -1;
        }
    }
    *value_size = header.value_size;

    if (data != block->data) free(data);
    block_manager_block_free(block);

    return 0;
}

static void tidesdb_sstable_free(tidesdb_sstable_t *sstable)
{
    if (!sstable) return;

    if (sstable->block_manager)
    {
        block_manager_close(sstable->block_manager);
    }

    if (sstable->index)
    {
        binary_hash_array_free(sstable->index);
    }

    if (sstable->bloom_filter)
    {
        bloom_filter_free(sstable->bloom_filter);
    }

    if (sstable->min_key) free(sstable->min_key);
    if (sstable->max_key) free(sstable->max_key);

    free(sstable);
}

static int tidesdb_txn_get_internal(tidesdb_txn_t *txn, tidesdb_column_family_t *cf,
                                    const uint8_t *key, size_t key_size, uint8_t **value,
                                    size_t *value_size)
{
    if (!txn || !cf || !key || !value || !value_size) return -1;

    pthread_rwlock_rdlock(&cf->cf_lock);

    /* check memtable first */
    uint8_t *mem_value = NULL;
    size_t mem_value_size = 0;
    uint8_t deleted = 0;

    int memtable_result =
        skip_list_get(cf->memtable, key, key_size, &mem_value, &mem_value_size, &deleted);

    if (memtable_result == 0)
    {
        /* key found in memtable */
        if (deleted)
        {
            /* key is tombstoned */
            if (mem_value) free(mem_value);
            pthread_rwlock_unlock(&cf->cf_lock);
            return -1;
        }

        /* handle both non-empty and empty values */
        if (mem_value_size > 0)
        {
            *value = malloc(mem_value_size);
            if (!*value)
            {
                if (mem_value) free(mem_value);
                pthread_rwlock_unlock(&cf->cf_lock);
                return -1;
            }
            memcpy(*value, mem_value, mem_value_size);
        }
        else
        {
            /* empty value,allocate minimal buffer */
            *value = malloc(1);
            if (!*value)
            {
                if (mem_value) free(mem_value);
                pthread_rwlock_unlock(&cf->cf_lock);
                return -1;
            }
        }

        *value_size = mem_value_size;
        if (mem_value) free(mem_value);
        pthread_rwlock_unlock(&cf->cf_lock);
        return 0;
    }

    /* key not in memtable, check sstables */

    /* check sstables from newest to oldest */
    int num_ssts = atomic_load(&cf->num_sstables);
    for (int i = num_ssts - 1; i >= 0; i--)
    {
        tidesdb_sstable_t *sst = cf->sstables[i];
        if (!sst) continue;

        uint8_t *sst_value = NULL;
        size_t sst_value_size = 0;

        if (tidesdb_sstable_get(sst, key, key_size, &sst_value, &sst_value_size) == 0)
        {
            *value = sst_value;
            *value_size = sst_value_size;
            pthread_rwlock_unlock(&cf->cf_lock);
            return 0;
        }
    }

    pthread_rwlock_unlock(&cf->cf_lock);
    return -1; /* not found */
}

static int tidesdb_recover_wal(tidesdb_column_family_t *cf)
{
    if (!cf || !cf->wal) return -1;

    block_manager_cursor_t *cursor = NULL;
    if (block_manager_cursor_init(&cursor, cf->wal) != 0) return -1;

    block_manager_cursor_goto_first(cursor);

    while (block_manager_cursor_has_next(cursor))
    {
        /* adv cursor first before reading */
        if (block_manager_cursor_next(cursor) != 0) break;

        block_manager_block_t *block = block_manager_cursor_read(cursor);
        if (block && block->data)
        {
            /* parse WAL entry using format [header][key][value] */
            if (block->size < sizeof(tidesdb_kv_pair_header_t))
            {
                block_manager_block_free(block);
                continue;
            }

            tidesdb_kv_pair_header_t header;
            memcpy(&header, block->data, sizeof(tidesdb_kv_pair_header_t));

            uint8_t *ptr = block->data + sizeof(tidesdb_kv_pair_header_t);
            uint8_t *key = ptr;
            ptr += header.key_size;
            uint8_t *value = ptr;

            /* restore to memtable (WAL entries are never tombstones) */
            skip_list_put(cf->memtable, key, header.key_size, value, header.value_size,
                          (time_t)header.ttl);

            block_manager_block_free(block);
        }
    }

    block_manager_cursor_free(cursor);
    return 0;
}

int tidesdb_txn_begin(tidesdb_t *db, tidesdb_txn_t **txn)
{
    if (!db || !txn) return -1;

    *txn = malloc(sizeof(tidesdb_txn_t));
    if (!*txn) return -1;

    (*txn)->db = db;
    (*txn)->operations = NULL;
    (*txn)->num_ops = 0;
    (*txn)->op_capacity = 0;
    (*txn)->committed = 0;
    (*txn)->snapshot_version = 0; /* will be set on first read */
    (*txn)->read_only = 0;

    return 0;
}

int tidesdb_txn_begin_read(tidesdb_t *db, tidesdb_txn_t **txn)
{
    if (!db || !txn) return -1;

    *txn = malloc(sizeof(tidesdb_txn_t));
    if (!*txn) return -1;

    (*txn)->db = db;
    (*txn)->operations = NULL;
    (*txn)->num_ops = 0;
    (*txn)->op_capacity = 0;
    (*txn)->committed = 0;
    (*txn)->snapshot_version = 0;
    (*txn)->read_only = 1;

    return 0;
}

int tidesdb_txn_get(tidesdb_txn_t *txn, const char *cf_name, const uint8_t *key, size_t key_size,
                    uint8_t **value, size_t *value_size)
{
    if (!txn || !cf_name || !key || !value || !value_size) return -1;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(txn->db, cf_name);
    if (!cf) return -1;

    /* check pending writes in transaction first (read your own writes) */
    if (!txn->read_only)
    {
        for (int i = txn->num_ops - 1; i >= 0; i--)
        {
            tidesdb_operation_t *op = &txn->operations[i];
            if (strcmp(op->cf_name, cf_name) == 0 && op->key_size == key_size &&
                memcmp(op->key, key, key_size) == 0)
            {
                if (op->type == TIDESDB_OP_DELETE)
                {
                    return -1; /* deleted in this transaction */
                }
                else if (op->type == TIDESDB_OP_PUT)
                {
                    *value = malloc(op->value_size);
                    if (*value)
                    {
                        memcpy(*value, op->value, op->value_size);
                        *value_size = op->value_size;
                        return 0;
                    }
                    return -1;
                }
            }
        }
    }

    /* read from database */
    return tidesdb_txn_get_internal(txn, cf, key, key_size, value, value_size);
}

int tidesdb_txn_put(tidesdb_txn_t *txn, const char *cf_name, const uint8_t *key, size_t key_size,
                    const uint8_t *value, size_t value_size, time_t ttl)
{
    if (!txn || !cf_name || !key || !value) return -1;
    if (txn->committed) return -1;
    if (txn->read_only) return -1; /* cannot write in read-only transaction */

    /* expand operations array if needed */
    if (txn->num_ops >= txn->op_capacity)
    {
        int new_cap = txn->op_capacity == 0 ? 8 : txn->op_capacity * 2;
        tidesdb_operation_t *new_ops =
            realloc(txn->operations, (size_t)new_cap * sizeof(tidesdb_operation_t));
        if (!new_ops) return -1;
        txn->operations = new_ops;
        txn->op_capacity = new_cap;
    }

    tidesdb_operation_t *op = &txn->operations[txn->num_ops];
    op->type = TIDESDB_OP_PUT;
    strncpy(op->cf_name, cf_name, TDB_MAX_CF_NAME_LENGTH - 1);
    op->cf_name[TDB_MAX_CF_NAME_LENGTH - 1] = '\0';

    /* allocate and copy key */
    op->key = malloc(key_size);
    if (!op->key) return -1;
    memcpy(op->key, key, key_size);
    op->key_size = key_size;

    /* allocate and copy value */
    op->value = malloc(value_size);
    if (!op->value)
    {
        free(op->key);
        return -1;
    }
    memcpy(op->value, value, value_size);
    op->value_size = value_size;
    op->ttl = ttl;

    txn->num_ops++;
    return 0;
}

int tidesdb_txn_delete(tidesdb_txn_t *txn, const char *cf_name, const uint8_t *key, size_t key_size)
{
    if (!txn || !cf_name || !key) return -1;
    if (txn->committed) return -1;
    if (txn->read_only) return -1; /* cannot write in read-only transaction */

    /* expand operations array if needed */
    if (txn->num_ops >= txn->op_capacity)
    {
        int new_cap = txn->op_capacity == 0 ? 8 : txn->op_capacity * 2;
        tidesdb_operation_t *new_ops =
            realloc(txn->operations, (size_t)new_cap * sizeof(tidesdb_operation_t));
        if (!new_ops) return -1;
        txn->operations = new_ops;
        txn->op_capacity = new_cap;
    }

    tidesdb_operation_t *op = &txn->operations[txn->num_ops];
    op->type = TIDESDB_OP_DELETE;
    strncpy(op->cf_name, cf_name, TDB_MAX_CF_NAME_LENGTH - 1);
    op->cf_name[TDB_MAX_CF_NAME_LENGTH - 1] = '\0';

    /* allocate and copy key */
    op->key = malloc(key_size);
    if (!op->key) return -1;
    memcpy(op->key, key, key_size);
    op->key_size = key_size;
    op->value = NULL;
    op->value_size = 0;
    op->ttl = 0;

    txn->num_ops++;
    return 0;
}

int tidesdb_txn_commit(tidesdb_txn_t *txn)
{
    if (!txn || txn->committed) return -1;
    if (txn->read_only)
    {
        txn->committed = 1;
        return 0; /* nothing to commit for read-only */
    }

    /* apply all operations atomically */
    for (int i = 0; i < txn->num_ops; i++)
    {
        tidesdb_operation_t *op = &txn->operations[i];

        tidesdb_column_family_t *cf = tidesdb_get_column_family(txn->db, op->cf_name);
        if (!cf) return -1;

        pthread_rwlock_wrlock(&cf->cf_lock); /* write lock for modifications */

        if (op->type == TIDESDB_OP_PUT)
        {
            /* write to WAL first using new format */
            if (cf->wal)
            {
                tidesdb_kv_pair_header_t header = {
                    .version = TDB_KV_FORMAT_VERSION,
                    .flags = 0, /* WAL entries are never tombstones */
                    .key_size = (uint32_t)op->key_size,
                    .value_size = (uint32_t)op->value_size,
                    .ttl = (int64_t)op->ttl};

                size_t wal_size = sizeof(tidesdb_kv_pair_header_t) + op->key_size + op->value_size;
                uint8_t *wal_data = malloc(wal_size);
                if (wal_data)
                {
                    uint8_t *ptr = wal_data;
                    memcpy(ptr, &header, sizeof(tidesdb_kv_pair_header_t));
                    ptr += sizeof(tidesdb_kv_pair_header_t);
                    memcpy(ptr, op->key, op->key_size);
                    ptr += op->key_size;
                    memcpy(ptr, op->value, op->value_size);

                    block_manager_block_t *block = block_manager_block_create(wal_size, wal_data);
                    if (block)
                    {
                        block_manager_block_write(cf->wal, block);
                        block_manager_block_free(block);
                    }
                    free(wal_data);
                }
            }

            /* write to memtable */
            if (skip_list_put(cf->memtable, op->key, op->key_size, op->value, op->value_size,
                              op->ttl) != 0)
            {
                pthread_rwlock_unlock(&cf->cf_lock);
                return -1;
            }
        }
        else if (op->type == TIDESDB_OP_DELETE)
        {
            /* write to WAL for delete using new format with tombstone flag */
            if (cf->wal)
            {
                tidesdb_kv_pair_header_t header = {
                    .version = TDB_KV_FORMAT_VERSION,
                    .flags = TDB_KV_FLAG_TOMBSTONE, /* mark as deleted */
                    .key_size = (uint32_t)op->key_size,
                    .value_size = 0, /* no value for deletes */
                    .ttl = 0};

                size_t wal_size = sizeof(tidesdb_kv_pair_header_t) + op->key_size;
                uint8_t *wal_data = malloc(wal_size);
                if (wal_data)
                {
                    uint8_t *ptr = wal_data;
                    memcpy(ptr, &header, sizeof(tidesdb_kv_pair_header_t));
                    ptr += sizeof(tidesdb_kv_pair_header_t);
                    memcpy(ptr, op->key, op->key_size);

                    block_manager_block_t *block = block_manager_block_create(wal_size, wal_data);
                    if (block)
                    {
                        block_manager_block_write(cf->wal, block);
                        block_manager_block_free(block);
                    }
                    free(wal_data);
                }
            }

            /* insert tombstone in memtable, use skip_list_put with empty value and deleted flag
             * this works whether the key exists in memtable or only in sst */
            uint8_t empty_value = 0;
            if (skip_list_put(cf->memtable, op->key, op->key_size, &empty_value, 0, 0) != 0)
            {
                pthread_rwlock_unlock(&cf->cf_lock);
                return -1;
            }
            /* now mark it as deleted */
            if (skip_list_delete(cf->memtable, op->key, op->key_size) != 0)
            {
                /* if delete fails, the put succeeded so we have a valid entry - continue */
            }
        }

        pthread_rwlock_unlock(&cf->cf_lock);

        /* check if flush is needed */
        tidesdb_check_and_flush(cf);
    }

    txn->committed = 1;
    return 0;
}

int tidesdb_txn_rollback(tidesdb_txn_t *txn)
{
    if (!txn) return -1;

    /* mark as rolled back - operations won't be committed */
    txn->committed = -1;
    return 0;
}

void tidesdb_txn_free(tidesdb_txn_t *txn)
{
    if (!txn) return;

    /* free all operations */
    for (int i = 0; i < txn->num_ops; i++)
    {
        tidesdb_operation_t *op = &txn->operations[i];
        if (op->key) free(op->key);
        if (op->value) free(op->value);
    }

    if (txn->operations) free(txn->operations);
    free(txn);
}

/* helper to parse a block and extract key/value */
static int parse_block(block_manager_block_t *block, tidesdb_column_family_t *cf, uint8_t **key,
                       size_t *key_size, uint8_t **value, size_t *value_size, uint8_t *deleted,
                       time_t *ttl)
{
    if (!block || !block->data) return -1;

    uint8_t *data = block->data;
    size_t data_size = block->size;

    /* decompress if needed */
    if (cf->config.compressed)
    {
        size_t decompressed_size = 0;
        uint8_t *decompressed =
            decompress_data(data, data_size, &decompressed_size, cf->config.compress_algo);
        if (!decompressed)
        {
            /* decompression failed - corrupted or invalid data */
            return -1;
        }
        data = decompressed;
        data_size = decompressed_size;
    }

    /* parse streamlined format [header][key][value] */
    if (data_size < sizeof(tidesdb_kv_pair_header_t))
    {
        if (data != block->data) free(data);
        return -1;
    }

    tidesdb_kv_pair_header_t header;
    uint8_t *ptr = data;
    memcpy(&header, ptr, sizeof(tidesdb_kv_pair_header_t));
    ptr += sizeof(tidesdb_kv_pair_header_t);

    /* check version */
    if (header.version != TDB_KV_FORMAT_VERSION)
    {
        if (data != block->data) free(data);
        return -1;
    }


    /* verify we have enough data for key and value */
    if (data_size < sizeof(tidesdb_kv_pair_header_t) + header.key_size + header.value_size)
    {
        if (data != block->data) free(data);
        return -1;
    }

    /* extract key */
    *key = malloc(header.key_size);
    if (!*key)
    {
        if (data != block->data) free(data);
        return -1;
    }
    memcpy(*key, ptr, header.key_size);
    *key_size = header.key_size;
    ptr += header.key_size;

    /* extract value - handle empty values */
    if (header.value_size > 0)
    {
        *value = malloc(header.value_size);
        if (!*value)
        {
            free(*key);
            if (data != block->data) free(data);
            return -1;
        }
        memcpy(*value, ptr, header.value_size);
    }
    else
    {
        /* empty value, allocate minimal buffer to avoid NULL */
        *value = malloc(1);
        if (!*value)
        {
            free(*key);
            if (data != block->data) free(data);
            return -1;
        }
    }
    *value_size = header.value_size;

    /* extract metadata from header */
    *ttl = (time_t)header.ttl;
    *deleted = (header.flags & TDB_KV_FLAG_TOMBSTONE) ? 1 : 0;

    if (data != block->data) free(data);
    return 0;
}

/* helper to compare keys for merge iteration using column family's comparator */
static int compare_keys_with_cf(tidesdb_column_family_t *cf, const uint8_t *key1, size_t key1_size,
                                const uint8_t *key2, size_t key2_size)
{
    /* use the column family's memtable comparator (which is set from config) */
    return skip_list_compare_keys(cf->memtable, key1, key1_size, key2, key2_size);
}

int tidesdb_iter_new(tidesdb_txn_t *txn, const char *cf_name, tidesdb_iter_t **iter)
{
    if (!txn || !cf_name || !iter) return -1;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(txn->db, cf_name);
    if (!cf) return -1;

    *iter = malloc(sizeof(tidesdb_iter_t));
    if (!*iter) return -1;

    (*iter)->txn = txn;
    (*iter)->cf = cf;
    (*iter)->current_key = NULL;
    (*iter)->current_value = NULL;
    (*iter)->current_key_size = 0;
    (*iter)->current_value_size = 0;
    (*iter)->current_deleted = 0;
    (*iter)->valid = 0;
    (*iter)->direction = 1; /* forward by default */

    /* create memtable cursor */
    (*iter)->memtable_cursor = skip_list_cursor_init(cf->memtable);

    /* create sstable cursors */
    int num_ssts = atomic_load(&cf->num_sstables);
    (*iter)->num_sstable_cursors = num_ssts;
    (*iter)->sstable_cursors = NULL;

    if (num_ssts > 0)
    {
        (*iter)->sstable_cursors = malloc((size_t)num_ssts * sizeof(block_manager_cursor_t *));
        if (!(*iter)->sstable_cursors)
        {
            if ((*iter)->memtable_cursor) skip_list_cursor_free((*iter)->memtable_cursor);
            free(*iter);
            return -1;
        }

        for (int i = 0; i < num_ssts; i++)
        {
            (*iter)->sstable_cursors[i] = NULL;
            if (cf->sstables[i] && cf->sstables[i]->block_manager)
            {
                block_manager_cursor_init(&(*iter)->sstable_cursors[i],
                                          cf->sstables[i]->block_manager);
            }
        }
    }

    return 0;
}

int tidesdb_iter_seek_to_first(tidesdb_iter_t *iter)
{
    if (!iter) return -1;

    iter->direction = 1;
    iter->valid = 0;

    /* position memtable cursor BEFORE first element (at header) */
    if (iter->memtable_cursor)
    {
        /* reset cursor to header so next() will read the first element */
        iter->memtable_cursor->current = iter->memtable_cursor->list->header;
    }

    /* position sstable cursors BEFORE first block */
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        if (iter->sstable_cursors[i])
        {
            /* reset cursor position to before first block */
            iter->sstable_cursors[i]->current_pos = BLOCK_MANAGER_HEADER_SIZE;
            iter->sstable_cursors[i]->current_block_size = 0;
        }
    }

    /* advance to find first valid entry */
    return tidesdb_iter_next(iter);
}

int tidesdb_iter_seek_to_last(tidesdb_iter_t *iter)
{
    if (!iter) return -1;

    iter->direction = -1;
    iter->valid = 0;

    /* position all cursors at last */
    if (iter->memtable_cursor)
    {
        skip_list_cursor_goto_last(iter->memtable_cursor);
    }

    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        if (iter->sstable_cursors[i])
        {
            block_manager_cursor_goto_last(iter->sstable_cursors[i]);
        }
    }

    /* advance to find last valid entry */
    return tidesdb_iter_prev(iter);
}

int tidesdb_iter_next(tidesdb_iter_t *iter)
{
    if (!iter) return -1;

    iter->direction = 1;

    /* free previous current key/value */
    if (iter->current_key)
    {
        free(iter->current_key);
        iter->current_key = NULL;
    }
    if (iter->current_value)
    {
        free(iter->current_value);
        iter->current_value = NULL;
    }

    /* merge iteration, find smallest key across all sources */
    uint8_t *min_key = NULL;
    size_t min_key_size = 0;
    uint8_t *min_value = NULL;
    size_t min_value_size = 0;
    uint8_t min_deleted = 0;

    /* check memtable , keep advancing until we find a non-expired entry */
    if (iter->memtable_cursor)
    {
        while (skip_list_cursor_has_next(iter->memtable_cursor))
        {
            /* adv cursor first before reading */
            if (skip_list_cursor_next(iter->memtable_cursor) != 0) break;

            uint8_t *k = NULL, *v = NULL;
            size_t k_size = 0, v_size = 0;
            time_t ttl = 0;
            uint8_t deleted = 0;

            if (skip_list_cursor_get(iter->memtable_cursor, &k, &k_size, &v, &v_size, &ttl,
                                     &deleted) != 0)
                break;

            /* skip expired entries, continue to next */
            int is_expired = (ttl > 0 && time(NULL) > ttl);
            if (is_expired) continue;

            /* found valid entry */
            min_key = malloc(k_size);
            if (min_key)
            {
                memcpy(min_key, k, k_size);
                min_key_size = k_size;
                min_value = malloc(v_size);
                if (min_value)
                {
                    memcpy(min_value, v, v_size);
                    min_value_size = v_size;
                    min_deleted = deleted;
                }
            }
            break; /* found valid entry, stop searching memtable */
        }
    }

    /* check sstables, keep advancing until we find a non-expired entry for each sst */
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        if (!iter->sstable_cursors[i]) continue;

        /* keep advancing this sst cursor until we find a valid entry */
        while (block_manager_cursor_has_next(iter->sstable_cursors[i]))
        {
            /* adv cursor first before reading */
            if (block_manager_cursor_next(iter->sstable_cursors[i]) != 0) break;

            block_manager_block_t *block = block_manager_cursor_read(iter->sstable_cursors[i]);
            if (!block) break;

            uint8_t *k = NULL, *v = NULL;
            size_t k_size = 0, v_size = 0;
            uint8_t deleted = 0;
            time_t ttl = 0;

            int parse_result =
                parse_block(block, iter->cf, &k, &k_size, &v, &v_size, &deleted, &ttl);
            block_manager_block_free(block);

            if (parse_result != 0) break;

            /* skip expired entries ,continue to next block */
            int is_expired = (ttl > 0 && time(NULL) > ttl);
            if (is_expired)
            {
                free(k);
                free(v);
                continue;
            }

            /* found valid entry, check if it's the minimum */
            if (!min_key || compare_keys_with_cf(iter->cf, k, k_size, min_key, min_key_size) < 0)
            {
                if (min_key) free(min_key);
                if (min_value) free(min_value);

                min_key = k;
                min_key_size = k_size;
                min_value = v;
                min_value_size = v_size;
                min_deleted = deleted;
            }
            else
            {
                free(k);
                free(v);
            }
            break; /* found valid entry for this sst, move to next sst */
        }
    }

    if (min_key)
    {
        iter->current_key = min_key;
        iter->current_key_size = min_key_size;
        iter->current_value = min_value;
        iter->current_value_size = min_value_size;
        iter->current_deleted = min_deleted;
        iter->valid = 1;

        return 0;
    }

    iter->valid = 0;
    return -1;
}

int tidesdb_iter_prev(tidesdb_iter_t *iter)
{
    if (!iter) return -1;

    iter->direction = -1;

    /* free previous current key/value */
    if (iter->current_key)
    {
        free(iter->current_key);
        iter->current_key = NULL;
    }
    if (iter->current_value)
    {
        free(iter->current_value);
        iter->current_value = NULL;
    }

    /* merge iteration find largest key across all sources */
    uint8_t *max_key = NULL;
    size_t max_key_size = 0;
    uint8_t *max_value = NULL;
    size_t max_value_size = 0;
    uint8_t max_deleted = 0;

    /* check memtable */
    if (iter->memtable_cursor && skip_list_cursor_has_prev(iter->memtable_cursor))
    {
        if (skip_list_cursor_prev(iter->memtable_cursor) == 0)
        {
            uint8_t *k = NULL, *v = NULL;
            size_t k_size = 0, v_size = 0;
            time_t ttl = 0;
            uint8_t deleted = 0;

            if (skip_list_cursor_get(iter->memtable_cursor, &k, &k_size, &v, &v_size, &ttl,
                                     &deleted) == 0)
            {
                max_key = malloc(k_size);
                if (max_key)
                {
                    memcpy(max_key, k, k_size);
                    max_key_size = k_size;
                    max_value = malloc(v_size);
                    if (max_value)
                    {
                        memcpy(max_value, v, v_size);
                        max_value_size = v_size;
                        max_deleted = deleted;
                    }
                }
            }
        }
    }

    /* check sstables */
    for (int i = 0; i < iter->num_sstable_cursors; i++)
    {
        if (!iter->sstable_cursors[i]) continue;
        if (!block_manager_cursor_has_prev(iter->sstable_cursors[i])) continue;

        if (block_manager_cursor_prev(iter->sstable_cursors[i]) != 0) continue;

        block_manager_block_t *block = block_manager_cursor_read(iter->sstable_cursors[i]);
        if (!block) continue;

        uint8_t *k = NULL, *v = NULL;
        size_t k_size = 0, v_size = 0;
        uint8_t deleted = 0;
        time_t ttl = 0;

        if (parse_block(block, iter->cf, &k, &k_size, &v, &v_size, &deleted, &ttl) == 0)
        {
            if (!max_key || compare_keys_with_cf(iter->cf, k, k_size, max_key, max_key_size) > 0)
            {
                if (max_key) free(max_key);
                if (max_value) free(max_value);

                max_key = k;
                max_key_size = k_size;
                max_value = v;
                max_value_size = v_size;
                max_deleted = deleted;
            }
            else
            {
                free(k);
                free(v);
            }
        }

        block_manager_block_free(block);
    }

    if (max_key)
    {
        iter->current_key = max_key;
        iter->current_key_size = max_key_size;
        iter->current_value = max_value;
        iter->current_value_size = max_value_size;
        iter->current_deleted = max_deleted;
        iter->valid = 1;

        return 0;
    }

    iter->valid = 0;
    return -1;
}

int tidesdb_iter_valid(tidesdb_iter_t *iter)
{
    if (!iter) return 0;
    return iter->valid;
}

int tidesdb_iter_key(tidesdb_iter_t *iter, uint8_t **key, size_t *key_size)
{
    if (!iter || !iter->valid || !key || !key_size) return -1;

    *key = iter->current_key;
    *key_size = iter->current_key_size;
    return 0;
}

int tidesdb_iter_value(tidesdb_iter_t *iter, uint8_t **value, size_t *value_size)
{
    if (!iter || !iter->valid || !value || !value_size) return -1;

    if (iter->current_deleted) return -1; /* deleted entry */

    *value = iter->current_value;
    *value_size = iter->current_value_size;
    return 0;
}

void tidesdb_iter_free(tidesdb_iter_t *iter)
{
    if (!iter) return;

    if (iter->current_key) free(iter->current_key);
    if (iter->current_value) free(iter->current_value);

    if (iter->memtable_cursor) skip_list_cursor_free(iter->memtable_cursor);

    if (iter->sstable_cursors)
    {
        for (int i = 0; i < iter->num_sstable_cursors; i++)
        {
            if (iter->sstable_cursors[i])
            {
                block_manager_cursor_free(iter->sstable_cursors[i]);
            }
        }
        free(iter->sstable_cursors);
    }

    free(iter);
}