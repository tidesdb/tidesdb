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
#include "tidesdb.h"

tidesdb_err* tidesdb_open(const tidesdb_config* config, tidesdb** tdb)
{
    /* we check if the config is NULL */
    if (config == NULL) return tidesdb_err_new(1001, "Config is NULL");

    /* we check if the tdb is NULL */
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* first we allocate memory for the tidesdb struct */
    *tdb = malloc(sizeof(tidesdb));

    /* we check if allocation was successful */
    if (*tdb == NULL) return tidesdb_err_new(1000, "Failed to allocate memory for new db");

    /* we set the config */
    (*tdb)->config = *config;

    /* set column families */
    (*tdb)->column_families = NULL;
    (*tdb)->num_column_families = 0; /* 0 for now until we read db path */

    /* we check the configured db path */
    if (config->db_path == NULL) return tidesdb_err_new(1003, "DB path is NULL");

    /* we check to see if the db path exists
     * if not we create it */
    if (access(config->db_path, F_OK) == -1) /* we create the directory **/
        if (mkdir(config->db_path, 0777) == -1)
            return tidesdb_err_new(1004, "Failed to create db directory");

    /* now we load the column families */
    if (!_load_column_families(*tdb))
        return tidesdb_err_new(1041, "Failed to load column families");

    (*tdb)->wal = malloc(sizeof(wal));

    /* now we open the wal */
    if (!_open_wal((*tdb)->config.db_path, &(*tdb)->wal))
        return tidesdb_err_new(1042, "Failed to open wal");

    if ((*tdb)->num_column_families > 0)
    {
        /* we iterate over the column families
         * loading their sstables and sorting them by last modified being last */
        for (int i = 0; i < (*tdb)->num_column_families; i++)
        {
            /* we load the sstables */
            _load_sstables(&(*tdb)->column_families[i]); /* there could be no sstables */

            if ((*tdb)->column_families[i].num_sstables > 0)
            {
                /* we sort the sstables */
                if (!_sort_sstables(&(*tdb)->column_families[i]))
                    return tidesdb_err_new(1008, "Failed to sort sstables");
            }
        }
    }

    /* initialize the flush queue */
    (*tdb)->flush_queue = queue_new();
    if ((*tdb)->flush_queue == NULL)
    {
        free(*tdb);
        return tidesdb_err_new(1010, "Failed to initialize flush queue");
    }

    /* initialize flush_mutex */
    if (pthread_mutex_init(&(*tdb)->flush_lock, NULL) != 0)
    {
        free(*tdb);
        return tidesdb_err_new(1046, "Failed to initialize flush mutex");
    }

    /* initialize flush_cond **/
    if (pthread_cond_init(&(*tdb)->flush_cond, NULL) != 0)
    {
        free(*tdb);
        return tidesdb_err_new(1047, "Failed to initialize flush condition variable");
    }

    (*tdb)->stop_flush_thread = false; /* set stop_flush_thread to false */

    /* initialize column_families_lock */
    if (pthread_rwlock_init(&(*tdb)->column_families_lock, NULL) != 0)
    {
        free(*tdb);
        return tidesdb_err_new(1013, "Failed to initialize column families lock");
    }

    /* start the flush thread */
    if (pthread_create(&(*tdb)->flush_thread, NULL, _flush_memtable_thread, *tdb) != 0)
    {
        free(*tdb);
        return tidesdb_err_new(1014, "Failed to start flush thread");
    }

    /* now we replay from the wal */
    if (!_replay_from_wal((*tdb), (*tdb)->wal))
        return tidesdb_err_new(1009, "Failed to replay wal");

    return NULL;
}

tidesdb_err* tidesdb_create_column_family(tidesdb* tdb, const char* name, int flush_threshold,
                                          int max_level, float probability)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* we check if the name is NULL */
    if (name == NULL) return tidesdb_err_new(1015, "Column family name is NULL");

    /* we check if the column family name is greater than 2 */
    if (strlen(name) < 2) return tidesdb_err_new(1016, "Column family name is too short");

    /* we check flush threshold
     * the system expects at least a 1mb threshold */
    if (flush_threshold < 1048576) return tidesdb_err_new(1017, "Flush threshold is too low");

    /* we check max level
     * the system expects at least a level of 5 */
    if (max_level < 5) return tidesdb_err_new(1018, "Max level is too low");

    /* we check probability
     * the system expects at least a probability of 0.1 */
    if (probability < 0.1) return tidesdb_err_new(1019, "Probability is too low");

    column_family* cf = NULL;
    if (!_new_column_family(tdb->config.db_path, name, flush_threshold, max_level, probability,
                            &cf))
        return tidesdb_err_new(1020, "Failed to create new column family");

    /* now we add the column family */
    if (!_add_column_family(tdb, cf)) return tidesdb_err_new(1021, "Failed to add column family");

    return NULL;
}

tidesdb_err* tidesdb_drop_column_family(tidesdb* tdb, const char* name)
{
    /* check if either tdb or name is NULL */
    if (tdb == NULL || name == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* lock the column families lock */
    if (pthread_rwlock_wrlock(&tdb->column_families_lock) != 0)
        return tidesdb_err_new(1022, "Failed to lock column families lock");

    /* iterate over the column families to find the one to remove */
    int index = -1;
    for (int i = 0; i < tdb->num_column_families; i++)
    {
        if (strcmp(tdb->column_families[i].config.name, name) == 0)
        {
            index = i;
            break;
        }
    }

    if (index == -1)
    {
        pthread_rwlock_unlock(&tdb->column_families_lock);
        return tidesdb_err_new(1028, "Column family not found");
    }

    /* free the resources associated with the column family */
    free(tdb->column_families[index].config.name);

    /* check if the column family has sstables */
    if (tdb->column_families[index].num_sstables > 0)
    {
        /* lck the sstables lock */
        if (pthread_rwlock_wrlock(&tdb->column_families[index].sstables_lock) != 0)
        {
            pthread_rwlock_unlock(&tdb->column_families_lock);
            return tidesdb_err_new(1024, "Failed to lock sstables lock");
        }

        /* iterate over the sstables and free the resources */
        for (int i = 0; i < tdb->column_families[index].num_sstables; i++)
            _free_sstable(tdb->column_families[index].sstables[i]);

        /* free the sstables array */
        free(tdb->column_families[index].sstables);

        /* unlock the sstables lock */
        pthread_rwlock_unlock(&tdb->column_families[index].sstables_lock);
    }

    skiplist_destroy(tdb->column_families[index].memtable);
    pthread_rwlock_destroy(&tdb->column_families[index].sstables_lock);

    /* remove all files in the column family directory */
    _remove_directory(tdb->column_families[index].path);
    free(tdb->column_families[index].sstables);
    free(tdb->column_families[index].path);

    /* reallocate memory for the column families array */
    if (tdb->num_column_families > 1)
    {
        for (int i = index; i < tdb->num_column_families - 1; i++)
            tdb->column_families[i] = tdb->column_families[i + 1];

        tdb->num_column_families--;
        column_family* temp_families = (column_family*)realloc(
            tdb->column_families, tdb->num_column_families * sizeof(column_family));
        if (temp_families == NULL)
        {
            pthread_rwlock_unlock(&tdb->column_families_lock);
            return tidesdb_err_new(1048, "Failed to reallocate memory for column families");
        }

        tdb->column_families = temp_families;
    }
    else
    {
        /* free the column families array */
        free(tdb->column_families);
        tdb->num_column_families = 0;
    }

    /* unlock the column families lock */
    pthread_rwlock_unlock(&tdb->column_families_lock);

    return NULL;
}

tidesdb_err* tidesdb_compact_sstables(tidesdb* tdb, column_family* cf, int max_threads)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* we check if column family is NULL */
    if (cf == NULL) return tidesdb_err_new(1028, "Column family not found");

    /* minimum threads is 1 */
    if (max_threads < 1) return tidesdb_err_new(1029, "Max threads is too low");

    /* lock the sstables lock */
    if (pthread_rwlock_wrlock(&cf->sstables_lock) != 0)
        return tidesdb_err_new(1030, "Failed to lock sstables lock");

    /* number of sstables to compact */
    int num_sstables = cf->num_sstables;
    if (num_sstables < 2)
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        return tidesdb_err_new(1051, "Not enough sstables to compact");
    }

    /* sort sstables by last modified time (oldest first) */
    qsort(cf->sstables, num_sstables, sizeof(sstable*), _compare_sstables);

    /* split the work based on max_threads */
    int sstables_per_thread = (num_sstables + max_threads - 1) / max_threads;
    pthread_t threads[max_threads];
    compact_thread_args* thread_args = malloc(
        max_threads * sizeof(compact_thread_args)); /* allocate memory for thread arguments */

    if (thread_args == NULL)
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        return tidesdb_err_new(1033, "Failed to allocate memory for thread arguments");
    }

    for (int i = 0; i < max_threads; i++)
    {
        thread_args[i].cf = cf;
        thread_args[i].start = i * sstables_per_thread;
        thread_args[i].end = (i + 1) * sstables_per_thread;
        if (thread_args[i].end > num_sstables) thread_args[i].end = num_sstables;

        if (pthread_create(&threads[i], NULL, _compact_sstables_thread, (void*)&thread_args[i]) !=
            0)
        {
            pthread_rwlock_unlock(&cf->sstables_lock);
            free(thread_args);
            return tidesdb_err_new(1032, "Failed to create compaction thread");
        }
    }

    /* wait for all threads to finish */
    for (int i = 0; i < max_threads; i++) pthread_join(threads[i], NULL);

    /* we remove the null sstables */
    int j = 0;
    for (int i = 0; i < num_sstables; i++)
    {
        if (cf->sstables[i] != NULL) cf->sstables[j++] = cf->sstables[i];
    }

    /* update the number of sstables */
    cf->num_sstables = j;

    /* unlock the sstables lock */
    pthread_rwlock_unlock(&cf->sstables_lock);

    free(thread_args); /* free allocated memory for thread arguments */

    return NULL;
}

void* _compact_sstables_thread(void* arg)
{
    compact_thread_args* args = arg;
    column_family* cf = args->cf;
    int start = args->start;
    int end = args->end;

    /* perform the compaction for the given range of sstables */
    for (int i = start; i < end - 1; i += 2)
    {
        if (i + 1 >= cf->num_sstables) break; /* ensure we do not exceed the number of sstables */

        /* merge sstables[i] and sstables[i+1] into a new sstable */
        sstable* new_sstable = _merge_sstables(cf->sstables[i], cf->sstables[i + 1], cf);

        /* we check if the new sstable is NULL */
        if (new_sstable == NULL) continue;

        /* remove old sstable files */
        char sstable_path1[PATH_MAX];
        char sstable_path2[PATH_MAX];

        /* get the sstable paths */
        snprintf(sstable_path1, PATH_MAX, "%s", cf->sstables[i]->pager->filename);
        snprintf(sstable_path2, PATH_MAX, "%s", cf->sstables[i + 1]->pager->filename);

        /* free the old sstables */
        _free_sstable(cf->sstables[i]);
        _free_sstable(cf->sstables[i + 1]);

        /* remove the sstable files */
        remove(sstable_path1);
        remove(sstable_path2);

        /* replace the old sstables with the new one */
        cf->sstables[i] = new_sstable;
        cf->sstables[i + 1] = NULL;
    }

    return NULL;
}

sstable* _merge_sstables(sstable* sst1, sstable* sst2, column_family* cf)
{
    if (cf == NULL || sst1 == NULL || sst2 == NULL || sst1->pager->num_pages == 0 ||
        sst2->pager->num_pages == 0)
        return NULL;

    skiplist* mergetable = new_skiplist(cf->config.max_level, cf->config.probability);
    if (mergetable == NULL) return NULL;

    bloomfilter* bf = bloomfilter_create(BLOOMFILTER_SIZE);
    if (bf == NULL)
    {
        skiplist_destroy(mergetable);
        return NULL;
    }

    pager_cursor* cursor1 = NULL;
    pager_cursor* cursor2 = NULL;

    if (!pager_cursor_init(sst1->pager, &cursor1) || !pager_cursor_init(sst2->pager, &cursor2))
    {
        skiplist_destroy(mergetable);
        bloomfilter_destroy(bf);
        if (cursor1) pager_cursor_free(cursor1);
        if (cursor2) pager_cursor_free(cursor2);
        return NULL;
    }

    bool has_next1 = true;
    bool has_next2 = true;

    while (has_next1 || has_next2)
    {
        uint8_t* buffer1 = NULL;
        size_t buffer_len1 = 0;
        uint8_t* buffer2 = NULL;
        size_t buffer_len2 = 0;

        if (has_next1)
        {
            has_next1 = pager_cursor_next(cursor1);
            if (has_next1 && !pager_read(sst1->pager, cursor1->page_number, &buffer1, &buffer_len1))
            {
                free(buffer1);
                break;
            }
        }

        if (has_next2)
        {
            has_next2 = pager_cursor_next(cursor2);
            if (has_next2 && !pager_read(sst2->pager, cursor2->page_number, &buffer2, &buffer_len2))
            {
                free(buffer2);
                free(buffer1);
                break;
            }
        }

        key_value_pair* kv1 = NULL;
        key_value_pair* kv2 = NULL;

        if (buffer1 &&
            !deserialize_key_value_pair(buffer1, buffer_len1, &kv1, cf->config.compressed))
        {
            free(buffer1);
            free(buffer2);
            break;
        }

        if (buffer2 &&
            !deserialize_key_value_pair(buffer2, buffer_len2, &kv2, cf->config.compressed))
        {
            free(buffer1);
            free(buffer2);
            break;
        }

        if (kv1 && !_is_tombstone(kv1->value, kv1->value_size) &&
            !skiplist_put(mergetable, kv1->key, kv1->key_size, kv1->value, kv1->value_size,
                          kv1->ttl))
        {
            free(buffer1);
            free(buffer2);
            free(kv1->key);
            free(kv1->value);
            free(kv1);
        }

        if (kv2 && !_is_tombstone(kv2->value, kv2->value_size) &&
            !skiplist_put(mergetable, kv2->key, kv2->key_size, kv2->value, kv2->value_size,
                          kv2->ttl))
        {
            free(buffer1);
            free(buffer2);
            free(kv2->key);
            free(kv2->value);
            free(kv2);
        }

        if (kv1)
        {
            bloomfilter_add(bf, kv1->key, kv1->key_size);
            free(kv1->key);
            free(kv1->value);
            free(kv1);
        }

        if (kv2)
        {
            bloomfilter_add(bf, kv2->key, kv2->key_size);
            free(kv2->key);
            free(kv2->value);
            free(kv2);
        }

        free(buffer1);
        free(buffer2);
    }

    pager* new_pager = NULL;
    char new_sstable_name[PATH_MAX];
    char numeric_part1[PATH_MAX / 4];
    char numeric_part2[PATH_MAX / 4];
    _sst_extract_numeric_parts(sst1->pager->filename, numeric_part1);
    _sst_extract_numeric_parts(sst2->pager->filename, numeric_part2);

    snprintf(new_sstable_name, PATH_MAX, "%s%ssstable_%s_%s.sst", cf->path, _get_path_seperator(),
             numeric_part1, numeric_part2);

    if (!pager_open(new_sstable_name, &new_pager))
    {
        skiplist_destroy(mergetable);
        bloomfilter_destroy(bf);
        return NULL;
    }

    uint8_t* bf_buffer = NULL;
    size_t bf_buffer_len = 0;

    if (!serialize_bloomfilter(bf, &bf_buffer, &bf_buffer_len, cf->config.compressed))
    {
        skiplist_destroy(mergetable);
        bloomfilter_destroy(bf);
        pager_close(new_pager);
        return NULL;
    }

    unsigned int page_num;

    if (!pager_write(new_pager, bf_buffer, bf_buffer_len, &page_num))
    {
        skiplist_destroy(mergetable);
        bloomfilter_destroy(bf);
        pager_close(new_pager);
        free(bf_buffer);
        return NULL;
    }

    free(bf_buffer);
    bloomfilter_destroy(bf);

    skiplist_cursor* sl_cursor = skiplist_cursor_init(mergetable);

    do
    {
        unsigned char* kv_buffer = NULL;
        size_t kv_buffer_len = 0;

        key_value_pair* kvp = malloc(sizeof(key_value_pair));
        if (!kvp) break;

        kvp->key = sl_cursor->current->key;
        kvp->key_size = sl_cursor->current->key_size;
        kvp->value = sl_cursor->current->value;
        kvp->value_size = sl_cursor->current->value_size;
        kvp->ttl = sl_cursor->current->ttl;

        if (!serialize_key_value_pair(kvp, &kv_buffer, &kv_buffer_len, cf->config.compressed))
        {
            free(kvp);
            break;
        }

        free(kvp);

        unsigned int page_number;

        if (!pager_write(new_pager, kv_buffer, kv_buffer_len, &page_number))
        {
            free(kv_buffer);
            break;
        }

        free(kv_buffer);
        new_pager->num_pages++;

    } while (skiplist_cursor_next(sl_cursor));

    skiplist_destroy(mergetable);

    sstable* new_sstable = malloc(sizeof(sstable));
    if (!new_sstable)
    {
        pager_close(new_pager);
        return NULL;
    }

    new_sstable->pager = new_pager;

    return new_sstable;
}

tidesdb_err* tidesdb_put(tidesdb* tdb, const char* column_family_name, const unsigned char* key,
                         size_t key_size, const unsigned char* value, size_t value_size, time_t ttl)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* we check if the column family name is NULL */
    if (column_family_name == NULL) return tidesdb_err_new(1015, "Column family name is NULL");

    /* we check if the key is NULL */
    if (key == NULL) return tidesdb_err_new(1026, "Key is NULL");

    /* we check if the value is NULL */
    if (value == NULL) return tidesdb_err_new(1027, "Value is NULL");

    /* we get column family */
    column_family* cf = NULL;

    if (!_get_column_family(tdb, column_family_name, &cf))
        return tidesdb_err_new(1028, "Column family not found");

    /* we append to the wal */
    if (!_append_to_wal(tdb, tdb->wal, key, key_size, value, value_size, ttl, OP_PUT,
                        column_family_name))
        return tidesdb_err_new(1049, "Failed to append to wal");

    /* put in memtable */
    if (!skiplist_put(cf->memtable, key, key_size, value, value_size, ttl))
        return tidesdb_err_new(1050, "Failed to put into memtable");

    /* we check if the memtable has reached the flush threshold */
    if ((int)cf->memtable->total_size >= cf->config.flush_threshold)
    {
        /* get flush mutex */
        pthread_mutex_lock(&tdb->flush_lock);

        queue_entry* entry = (queue_entry*)malloc(sizeof(queue_entry));
        if (entry == NULL)
        {
            /* unlock the flush mutex */
            pthread_mutex_unlock(&tdb->flush_lock);
            return tidesdb_err_new(1045, "Failed to allocate memory for queue entry");
        }

        /* we make a copy of the memtable */
        entry->memtable = skiplist_copy(cf->memtable);
        if (entry->memtable == NULL)
        {
            /* unlock the flush mutex */
            pthread_mutex_unlock(&tdb->flush_lock);
            free(entry);
            return tidesdb_err_new(1011, "Failed to copy memtable");
        }
        entry->cf = cf;

        if (!pager_size(tdb->wal->pager, &entry->wal_checkpoint))
        {
            pthread_mutex_unlock(&tdb->flush_lock);
            free(entry);
            return tidesdb_err_new(1012, "Failed to get wal checkpoint");
        }

        /* enqueue the entry */
        queue_enqueue(tdb->flush_queue, entry);

        /* we signal the flush thread */
        pthread_cond_signal(&tdb->flush_cond);

        /* now we clear the memtable */
        skiplist_clear(cf->memtable);

        /* unlock the flush mutex */
        pthread_mutex_unlock(&tdb->flush_lock);
    }

    return NULL;
}

tidesdb_err* tidesdb_get(tidesdb* tdb, const char* column_family_name, const unsigned char* key,
                         size_t key_size, unsigned char** value, size_t* value_size)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* we check if the column family name is NULL */
    if (column_family_name == NULL) return tidesdb_err_new(1015, "Column family name is NULL");

    /* we check if key is NULL */
    if (key == NULL) return tidesdb_err_new(1026, "Key is NULL");

    /* we get column family */
    column_family* cf = NULL;
    if (!_get_column_family(tdb, column_family_name, &cf))
        return tidesdb_err_new(1028, "Column family not found");

    /* we check if the key exists in the memtable */
    if (skiplist_get(cf->memtable, key, key_size, value, value_size))
    {
        /* we found the key in the memtable
         * we check if the value is a tombstone */
        if (_is_tombstone(*value, *value_size)) return tidesdb_err_new(1031, "Key not found");

        return NULL;
    }

    /* we check if the key exists in the sstables */

    /* we grab flush lock
     * we don't want a flush or compaction to happen while we are reading from sstables */
    if (pthread_mutex_lock(&tdb->flush_lock) != 0)
        return tidesdb_err_new(1032, "Failed to lock flush lock");

    for (int i = cf->num_sstables - 1; i >= 0; i--)
    {
        if (cf->sstables[i] == NULL) continue;

        /* we read initial pages for bloom filter for the current sstable */
        uint8_t* bloom_filter_buffer = NULL;
        size_t bloom_filter_read = 0;

        if (!pager_read(cf->sstables[i]->pager, 0, &bloom_filter_buffer, &bloom_filter_read))
        {
            pthread_mutex_unlock(&tdb->flush_lock);
            return tidesdb_err_new(1055, "Failed to read bloom filter");
        }

        bloomfilter* bf = NULL;

        /* we deserialize the bloom filter */
        if (!deserialize_bloomfilter(bloom_filter_buffer, bloom_filter_read, &bf,
                                     cf->config.compressed))
        {
            free(bloom_filter_buffer);
            pthread_mutex_unlock(&tdb->flush_lock);
            return tidesdb_err_new(1034, "Failed to deserialize bloom filter");
        }

        if (bf == NULL)
        {
            free(bloom_filter_buffer);
            continue;
        }

        if (!bloomfilter_check(bf, key, key_size))
        {
            free(bloom_filter_buffer);
            bloomfilter_destroy(bf);
            continue;
        }

        pager_cursor* cursor = NULL;
        if (!pager_cursor_init(cf->sstables[i]->pager, &cursor))
        {
            bloomfilter_destroy(bf);
            free(bloom_filter_buffer);
            pthread_mutex_unlock(&tdb->flush_lock);
            return tidesdb_err_new(1035, "Failed to initialize sstable cursor");
        }

        /* we skip the bloom filter page(s) */
        if (!pager_cursor_next(cursor))
        {
            bloomfilter_destroy(bf);
            free(bloom_filter_buffer);
            pager_cursor_free(cursor);
            continue;
        }

        bool has_next = true;
        while (has_next)
        {
            uint8_t* buffer = NULL;
            size_t buffer_len = 0;

            if (!pager_read(cf->sstables[i]->pager, cursor->page_number, &buffer, &buffer_len))
            {
                if (buffer != NULL) free(buffer);

                if (bf != NULL) bloomfilter_destroy(bf);

                if (bloom_filter_buffer != NULL) free(bloom_filter_buffer);

                if (cursor != NULL) pager_cursor_free(cursor);

                pthread_mutex_unlock(&tdb->flush_lock);
                return tidesdb_err_new(1036, "Failed to read sstable");
            }

            key_value_pair* kv = NULL;

            if (!deserialize_key_value_pair(buffer, buffer_len, &kv, cf->config.compressed))
            {
                if (buffer != NULL) free(buffer);

                if (bf != NULL) bloomfilter_destroy(bf);

                if (bloom_filter_buffer != NULL) free(bloom_filter_buffer);

                if (cursor != NULL) pager_cursor_free(cursor);

                pthread_mutex_unlock(&tdb->flush_lock);
                return tidesdb_err_new(1037, "Failed to deserialize key value pair");
            }

            if (kv == NULL)
            {
                if (buffer != NULL) free(buffer);

                if (bf != NULL) bloomfilter_destroy(bf);

                if (bloom_filter_buffer != NULL) free(bloom_filter_buffer);

                if (cursor != NULL) pager_cursor_free(cursor);

                pthread_mutex_unlock(&tdb->flush_lock);
                return tidesdb_err_new(1038, "Key value pair is NULL");
            }

            if (memcmp(kv->key, key, key_size) == 0)
            {
                if (_is_tombstone(kv->value, kv->value_size))
                {
                    if (buffer != NULL) free(buffer);

                    if (bf != NULL) bloomfilter_destroy(bf);

                    if (bloom_filter_buffer != NULL) free(bloom_filter_buffer);

                    if (cursor != NULL) pager_cursor_free(cursor);

                    pthread_mutex_unlock(&tdb->flush_lock);
                    return tidesdb_err_new(1031, "Key not found");
                }

                /* check if ttl is set and has expired */
                if (kv->ttl != -1 && kv->ttl < time(NULL))
                {
                    if (buffer != NULL) free(buffer);

                    if (bf != NULL) bloomfilter_destroy(bf);

                    if (bloom_filter_buffer != NULL) free(bloom_filter_buffer);

                    if (cursor != NULL) pager_cursor_free(cursor);

                    if (kv != NULL) free(kv);

                    pthread_mutex_unlock(&tdb->flush_lock);
                    return tidesdb_err_new(1039, "Key not found");
                }

                *value = kv->value;
                *value_size = kv->value_size;

                if (buffer != NULL) free(buffer);

                if (bf != NULL) bloomfilter_destroy(bf);

                if (bloom_filter_buffer != NULL) free(bloom_filter_buffer);

                if (cursor != NULL) pager_cursor_free(cursor);

                if (kv != NULL) free(kv);

                pthread_mutex_unlock(&tdb->flush_lock);

                return NULL;
            }

            if (pager_cursor_next(cursor))
            {
                has_next = true;
            }
            else
            {
                break;
            }
        }

        if (bloom_filter_buffer != NULL) free(bloom_filter_buffer);

        if (bf != NULL) bloomfilter_destroy(bf);

        if (cursor == NULL) continue;

        pager_cursor_free(cursor);
    }

    pthread_mutex_unlock(&tdb->flush_lock);
    return tidesdb_err_new(1031, "Key not found");
}

tidesdb_err* tidesdb_delete(tidesdb* tdb, const char* column_family_name, const unsigned char* key,
                            size_t key_size)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    if (column_family_name == NULL) return tidesdb_err_new(1015, "Column family name is NULL");

    if (key == NULL) return tidesdb_err_new(1026, "Key is NULL");

    /* get column family */
    column_family* cf = NULL;
    if (!_get_column_family(tdb, column_family_name, &cf))
        return tidesdb_err_new(1028, "Column family not found");

    /* append to wal */
    if (!_append_to_wal(tdb, tdb->wal, key, key_size, NULL, 0, 0, OP_DELETE, column_family_name))
        return tidesdb_err_new(1029, "Failed to append to wal");

    unsigned char* tombstone = malloc(4);

    if (tombstone != NULL)
    {
        uint32_t tombstone_value = TOMBSTONE;
        memcpy(tombstone, &tombstone_value, sizeof(uint32_t));
    }

    /* add to memtable */
    if (!skiplist_put(cf->memtable, key, key_size, tombstone, 4, -1))
        return tidesdb_err_new(1030, "Failed to put into memtable");

    return NULL;
}

tidesdb_err* tidesdb_txn_begin(txn** transaction, const char* column_family)
{
    /* we check if column family is NULL */
    if (column_family == NULL) return tidesdb_err_new(1015, "Column family name is NULL");

    *transaction = (txn*)malloc(sizeof(txn));
    if (*transaction == NULL)
        return tidesdb_err_new(1052, "Failed to allocate memory for transaction");

    (*transaction)->column_family = strdup(column_family);
    (*transaction)->ops = NULL;
    (*transaction)->num_ops = 0;

    return NULL;
}

tidesdb_err* tidesdb_txn_put(txn* transaction, const unsigned char* key, size_t key_size,
                             const unsigned char* value, size_t value_size, time_t ttl)
{
    /* we check if the transaction is NULL */
    if (transaction == NULL) return tidesdb_err_new(1054, "Transaction is NULL");

    /* we check if the key is NULL */
    if (key == NULL) return tidesdb_err_new(1026, "Key is NULL");

    /* we check if the value is NULL */
    if (value == NULL) return tidesdb_err_new(1027, "Value is NULL");

    txn_op* temp_ops = realloc(transaction->ops, (transaction->num_ops + 1) * sizeof(txn_op));
    if (temp_ops == NULL)
    {
        return tidesdb_err_new(1056, "Failed to reallocate memory for transaction operations");
    }
    transaction->ops = temp_ops;

    transaction->ops[transaction->num_ops].op = (operation*)malloc(sizeof(operation));
    transaction->ops[transaction->num_ops].op->op_code = OP_PUT;
    transaction->ops[transaction->num_ops].op->column_family = strdup(transaction->column_family);
    transaction->ops[transaction->num_ops].op->kv = (key_value_pair*)malloc(sizeof(key_value_pair));
    transaction->ops[transaction->num_ops].op->kv->key_size = key_size;
    transaction->ops[transaction->num_ops].op->kv->key = (unsigned char*)malloc(key_size);
    memcpy(transaction->ops[transaction->num_ops].op->kv->key, key, key_size);
    transaction->ops[transaction->num_ops].op->kv->value_size = value_size;
    transaction->ops[transaction->num_ops].op->kv->value = (unsigned char*)malloc(value_size);
    memcpy(transaction->ops[transaction->num_ops].op->kv->value, value, value_size);
    transaction->ops[transaction->num_ops].op->kv->ttl = ttl;

    transaction->ops[transaction->num_ops].rollback_op = (operation*)malloc(sizeof(operation));

    /* a rollback for put is a delete */
    transaction->ops[transaction->num_ops].rollback_op->op_code = OP_DELETE;
    transaction->ops[transaction->num_ops].rollback_op->column_family =
        strdup(transaction->column_family);
    transaction->ops[transaction->num_ops].rollback_op->kv =
        (key_value_pair*)malloc(sizeof(key_value_pair));
    transaction->ops[transaction->num_ops].rollback_op->kv->key_size = key_size;
    transaction->ops[transaction->num_ops].rollback_op->kv->key = (unsigned char*)malloc(key_size);
    memcpy(transaction->ops[transaction->num_ops].rollback_op->kv->key, key, key_size);

    transaction->num_ops++;

    return NULL;
}

tidesdb_err* tidesdb_txn_delete(txn* transaction, const unsigned char* key, size_t key_size)
{
    /* we check if the transaction is NULL */
    if (transaction == NULL) return tidesdb_err_new(1032, "Transaction is NULL");

    /* we check if the key is NULL */
    if (key == NULL) return tidesdb_err_new(1026, "Key is NULL");

    txn_op* temp_ops = realloc(transaction->ops, (transaction->num_ops + 1) * sizeof(txn_op));
    if (temp_ops == NULL) return tidesdb_err_new(1031, "Failed to allocate memory for transaction");

    transaction->ops = temp_ops;

    transaction->ops[transaction->num_ops].op = (operation*)malloc(sizeof(operation));
    transaction->ops[transaction->num_ops].op->op_code = OP_DELETE;
    transaction->ops[transaction->num_ops].op->column_family = strdup(transaction->column_family);
    transaction->ops[transaction->num_ops].op->kv = (key_value_pair*)malloc(sizeof(key_value_pair));
    transaction->ops[transaction->num_ops].op->kv->key_size = key_size;
    transaction->ops[transaction->num_ops].op->kv->key = (unsigned char*)malloc(key_size);
    memcpy(transaction->ops[transaction->num_ops].op->kv->key, key, key_size);
    transaction->ops[transaction->num_ops].op->kv->value_size = 0;
    transaction->ops[transaction->num_ops].op->kv->value = NULL;
    transaction->ops[transaction->num_ops].op->kv->ttl = 0;

    transaction->ops[transaction->num_ops].rollback_op = (operation*)malloc(sizeof(operation));

    /* a rollback for delete is a put */
    transaction->ops[transaction->num_ops].rollback_op->op_code = OP_PUT;
    transaction->ops[transaction->num_ops].rollback_op->column_family =
        strdup(transaction->column_family);
    transaction->ops[transaction->num_ops].rollback_op->kv =
        (key_value_pair*)malloc(sizeof(key_value_pair));
    transaction->ops[transaction->num_ops].rollback_op->kv->key_size = key_size;
    transaction->ops[transaction->num_ops].rollback_op->kv->key = (unsigned char*)malloc(key_size);
    memcpy(transaction->ops[transaction->num_ops].rollback_op->kv->key, key, key_size);

    transaction->ops[transaction->num_ops].rollback_op->kv->value_size = 0;
    transaction->ops[transaction->num_ops].rollback_op->kv->value = NULL;
    transaction->ops[transaction->num_ops].rollback_op->kv->ttl = 0;

    transaction->num_ops++;

    return NULL;
}

tidesdb_err* tidesdb_txn_commit(tidesdb* tdb, txn* transaction)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* we check if the transaction is NULL */
    if (transaction == NULL) return tidesdb_err_new(1032, "Transaction is NULL");

    /* we get column family */
    column_family* cf = NULL;
    if (!_get_column_family(tdb, transaction->column_family, &cf))
        return tidesdb_err_new(1028, "Column family not found");

    /* we lock the memtable */
    pthread_rwlock_wrlock(&cf->memtable->lock);

    /* we run the operations */
    for (int i = 0; i < transaction->num_ops; i++)
    {
        operation op = *transaction->ops[i].op;

        switch (op.op_code)
        {
            case OP_PUT:

                skiplist_put(cf->memtable, op.kv->key, op.kv->key_size, op.kv->value,
                             op.kv->value_size, op.kv->ttl);
                /* mark op committed */
                transaction->ops[i].committed = true;

                break;
            case OP_DELETE:

                /* put tombstone value */
                unsigned char* tombstone = (unsigned char*)malloc(4);
                if (tombstone != NULL)
                {
                    uint32_t tombstone_value = TOMBSTONE;
                    memcpy(tombstone, &tombstone_value, sizeof(uint32_t));
                }

                skiplist_put(cf->memtable, op.kv->key, op.kv->key_size, tombstone, 4, 0);
                /* mark op committed */
                transaction->ops[i].committed = true;

                break;
            default:
                break;
        }
    }

    if ((int)cf->memtable->total_size >= cf->config.flush_threshold)
    {
        /* get flush mutex */
        pthread_mutex_lock(&tdb->flush_lock);

        queue_entry* entry = malloc(sizeof(queue_entry));
        if (entry == NULL)
        {
            /* unlock the flush mutex */
            pthread_mutex_unlock(&tdb->flush_lock);
            return tidesdb_err_new(1010, "Failed to allocate memory for queue entry");
        }

        /* we make a copy of the memtable */
        entry->memtable = skiplist_copy(cf->memtable);
        if (entry->memtable == NULL)
        {
            /* unlock the flush mutex */
            pthread_mutex_unlock(&tdb->flush_lock);
            free(entry);
            return tidesdb_err_new(1011, "Failed to copy memtable");
        }

        entry->cf = cf;

        if (!pager_size(tdb->wal->pager, &entry->wal_checkpoint))
        {
            pthread_mutex_unlock(&tdb->flush_lock);
            free(entry);
            return tidesdb_err_new(1012, "Failed to get wal checkpoint");
        }

        queue_enqueue(tdb->flush_queue, entry);
        pthread_cond_signal(&tdb->flush_cond);

        /* now we clear the memtable */
        skiplist_clear(cf->memtable);

        pthread_mutex_unlock(&tdb->flush_lock);
    }

    return NULL;
}

tidesdb_err* tidesdb_txn_rollback(tidesdb* tdb, txn* transaction)
{
    /* we check if the db is NULL */
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* we check if the transaction is NULL */
    if (transaction == NULL) return tidesdb_err_new(1032, "Transaction is NULL");

    for (int i = 0; i < transaction->num_ops; i++)
    {
        if (transaction->ops[i].committed)
        {
            operation op = *transaction->ops[i].rollback_op;
            column_family* cf = NULL;

            if (!_get_column_family(tdb, op.column_family, &cf))
                return tidesdb_err_new(1028, "Column family not found");

            switch (op.op_code)
            {
                case OP_PUT:
                    /* we delete the key-value pair */
                    skiplist_delete(cf->memtable, op.kv->key, op.kv->key_size);
                    break;
                case OP_DELETE:
                    /* we put back the key-value pair */
                    skiplist_put(cf->memtable, op.kv->key, op.kv->key_size, op.kv->value,
                                 op.kv->value_size, op.kv->ttl);
                    break;
                default:
                    break;
            }
        }
    }

    /* we free the transaction */
    tidesdb_txn_free(transaction);

    return NULL;
}

tidesdb_err* tidesdb_txn_free(txn* transaction)
{
    if (transaction == NULL) return tidesdb_err_new(1032, "Transaction is NULL");

    for (int i = 0; i < transaction->num_ops; i++)
    {
        free(transaction->ops[i].op->column_family);
        if (transaction->ops[i].op->kv != NULL)
        {
            free(transaction->ops[i].op->kv->key);
            free(transaction->ops[i].op->kv->value);
            free(transaction->ops[i].op->kv);
        }

        if (transaction->ops[i].rollback_op != NULL)
        {
            free(transaction->ops[i].rollback_op->column_family);
            if (transaction->ops[i].rollback_op->kv != NULL)
            {
                free(transaction->ops[i].rollback_op->kv->key);
                free(transaction->ops[i].rollback_op->kv->value);
                free(transaction->ops[i].rollback_op->kv);
            }
        }
        free(transaction->ops[i].op);
        free(transaction->ops[i].rollback_op);
    }

    free(transaction->column_family);
    free(transaction->ops);
    free(transaction);

    return NULL;
}

tidesdb_err* tidesdb_cursor_init(tidesdb* tdb, const char* column_family_name,
                                 tidesdb_cursor** cursor)
{
    /*** @TODO */
    return NULL;
}

tidesdb_err* tidesdb_cursor_next(tidesdb_cursor* cursor)
{
    /*** @TODO */
    return NULL;
}

tidesdb_err* tidesdb_cursor_prev(tidesdb_cursor* cursor)
{
    /*** @TODO */
    return NULL;
}

tidesdb_err* tidesdb_cursor_get(tidesdb_cursor* cursor, key_value_pair** kv)
{
    /*** @TODO */
    return NULL;
}

tidesdb_err* tidesdb_cursor_free(tidesdb_cursor* cursor)
{
    /* we try to free the sstable cursor */
    if (cursor->sstable_cursor != NULL) pager_cursor_free(cursor->sstable_cursor);

    /* now we try to free the memtable cursor */
    if (cursor->memtable_cursor != NULL) skiplist_cursor_free(cursor->memtable_cursor);

    /* now we free the cursor */
    free(cursor);

    cursor = NULL;

    return NULL;
}

bool _new_column_family(const char* db_path, const char* name, int flush_threshold, int max_level,
                        float probability, column_family** cf)
{
    /* we allocate memory for the column family */
    *cf = malloc(sizeof(column_family));

    /* we check if allocation was successful */
    if (*cf == NULL) return false;

    /* we copy the name */
    (*cf)->config.name = strdup(name);

    /* we check if the name was copied */
    if ((*cf)->config.name == NULL)
    {
        free(*cf);
        return false;
    }

    /* we set the flush threshold */
    (*cf)->config.flush_threshold = flush_threshold;

    /* we set the max level */
    (*cf)->config.max_level = max_level;

    /* we set the probability */
    (*cf)->config.probability = probability;

    /* we construct the path to the column family */
    char cf_path[PATH_MAX];

    /* we use snprintf to construct the path */
    snprintf(cf_path, sizeof(cf_path), "%s%s%s", db_path, _get_path_seperator(), name);

    /* we check if the column family path exists */
    if (access(cf_path, F_OK) == -1)
    {
        /* we create the directory */
        if (mkdir(cf_path, 0777) == -1)
        {
            free((*cf)->config.name);
            free(*cf);
            return false;
        }
    }

    /* we create config file name
     * each column family has a config file
     * this contains a serialized version of the column family struct */
    char config_file_name[PATH_MAX];

    snprintf(config_file_name, sizeof(config_file_name), "%s%s%s%s%s%s", db_path,
             _get_path_seperator(), name, _get_path_seperator(), name,
             COLUMN_FAMILY_CONFIG_FILE_EXT);

    /* now we serialize the column family struct */
    size_t serialized_size;
    uint8_t* serialized_cf;

    if (!serialize_column_family_config(&(*cf)->config, &serialized_cf, &serialized_size))
    {
        free((*cf)->config.name);
        free(*cf);
        return false;
    }

    /* we open the config file (new file) */
    FILE* config_file = fopen(config_file_name, "wb");
    if (config_file == NULL)
    {
        free((*cf)->config.name);
        free(*cf);
        free(serialized_cf);
        return false;
    }

    /* we write the serialized column family struct to the config file */
    if (fwrite(serialized_cf, serialized_size, 1, config_file) != 1)
    {
        free((*cf)->config.name);
        free(*cf);
        free(serialized_cf);
        fclose(config_file);
        return false;
    }

    /* we set the path */
    (*cf)->path = strdup(cf_path);

    /* we check if the path was copied */
    if ((*cf)->path == NULL)
    {
        free((*cf)->config.name);
        free(*cf);
        free(serialized_cf);
        fclose(config_file);
        return false;
    }

    /* we init sstables array and len */
    (*cf)->num_sstables = 0;
    (*cf)->sstables = NULL;

    /* we initialize sstables lock */
    if (pthread_rwlock_init(&(*cf)->sstables_lock, NULL) != 0)
    {
        free((*cf)->config.name);
        free((*cf)->path);
        free(*cf);
        free(serialized_cf);
        fclose(config_file);
        return false;
    }

    /* we create memtable */
    (*cf)->memtable = new_skiplist((*cf)->config.max_level, (*cf)->config.probability);

    /* we check if the memtable was created */
    if ((*cf)->memtable == NULL)
    {
        free((*cf)->config.name);
        free((*cf)->path);
        pthread_rwlock_destroy(&(*cf)->sstables_lock);
        free(*cf);
        free(serialized_cf);
        fclose(config_file);
        return false;
    }

    /* we free what we must */
    free(serialized_cf);
    fclose(config_file);

    return true;
}

bool _add_column_family(tidesdb* tdb, column_family* cf)
{
    /* we check if tdb or cf is NULL */
    if (tdb == NULL || cf == NULL) return false;

    /* we lock the column families lock */
    if (pthread_rwlock_wrlock(&tdb->column_families_lock) != 0) return false;

    if (tdb->column_families == NULL)
    {
        tdb->column_families = malloc(sizeof(column_family));
        if (tdb->column_families == NULL)
        {
            /* release the lock */
            pthread_rwlock_unlock(&tdb->column_families_lock);
            return false;
        }
    }
    else
    {
        column_family* temp_families = (column_family*)realloc(
            tdb->column_families, sizeof(column_family) * (tdb->num_column_families + 1));
        /* we check if the reallocation was successful */
        if (temp_families == NULL)
        {
            pthread_rwlock_unlock(&tdb->column_families_lock);
            return false;
        }

        tdb->column_families = temp_families;
    }

    /* we increment the number of column families */
    tdb->num_column_families++;

    /* we add the column family */
    tdb->column_families[tdb->num_column_families - 1] = *cf;

    pthread_rwlock_unlock(&tdb->column_families_lock);
    return true;
}

bool _get_column_family(tidesdb* tdb, const char* name, column_family** cf)
{
    /* we check if tdb or name is NULL */
    if (tdb == NULL || name == NULL) return false;

    /* lock the column families lock */
    if (pthread_rwlock_rdlock(&tdb->column_families_lock) != 0) return false;

    /* we iterate over the column families and return the one with the matching name */
    for (int i = 0; i < tdb->num_column_families; i++)
    {
        if (strcmp(tdb->column_families[i].config.name, name) == 0)
        {
            /* unlock column_families_lock */
            pthread_rwlock_unlock(&tdb->column_families_lock);

            /* match on name we return the column family */
            *cf = &tdb->column_families[i];

            return true;
        }
    }

    pthread_rwlock_unlock(&tdb->column_families_lock);

    return false; /* no column family with that name */
}

bool _load_column_families(tidesdb* tdb)
{
    /* check if tdb is NULL */
    if (tdb == NULL) return false;

    /* open the db directory */
    DIR* tdb_dir = opendir(tdb->config.db_path);
    if (tdb_dir == NULL)
    {
        return false;
    }

    struct dirent* tdb_entry; /* create a dirent struct for the db directory */

    /* we iterate over the db directory */
    while ((tdb_entry = readdir(tdb_dir)) != NULL)
    {
        /* we skip the . and .. directories */
        if (strcmp(tdb_entry->d_name, ".") == 0 || strcmp(tdb_entry->d_name, "..") == 0) continue;

        /* each directory is a column family */
        char cf_path[PATH_MAX];
        snprintf(cf_path, sizeof(cf_path), "%s%s%s", tdb->config.db_path, _get_path_seperator(),
                 tdb_entry->d_name);

        /* we open the column family directory */
        DIR* cf_dir = opendir(cf_path);
        if (cf_dir == NULL) continue;

        struct dirent* cf_entry; /* create a dirent struct for the column family directory */

        /* we iterate over the column family directory */
        while ((cf_entry = readdir(cf_dir)) != NULL)
        {
            if (strstr(cf_entry->d_name, COLUMN_FAMILY_CONFIG_FILE_EXT) != NULL)
            { /* if the file is a column family config file */

                char config_file_path[PATH_MAX];
                if (snprintf(config_file_path, sizeof(config_file_path), "%s%s%s", cf_path,
                             _get_path_seperator(),
                             cf_entry->d_name) >= (long)sizeof(config_file_path))
                {
                    closedir(cf_dir);
                    closedir(tdb_dir);
                    return false;
                }

                /* load the config file into memory */
                FILE* config_file = fopen(config_file_path, "rb");
                if (config_file == NULL)
                {
                    closedir(cf_dir);
                    closedir(tdb_dir);
                    return false;
                }

                fseek(config_file, 0, SEEK_END);         /* seek to end of file */
                size_t config_size = ftell(config_file); /* get size of file */
                fseek(config_file, 0, SEEK_SET);         /* seek back to beginning of file */

                unsigned char* buffer = malloc(config_size);
                if (fread(buffer, 1, config_size, config_file) != config_size)
                {
                    free(buffer);
                    fclose(config_file);
                    closedir(cf_dir);
                    closedir(tdb_dir);
                    return false;
                }

                fclose(config_file);

                /* deserialize the cf config */
                column_family_config* config;

                if (!deserialize_column_family_config(buffer, config_size, &config))
                {
                    free(buffer);
                    closedir(cf_dir);
                    closedir(tdb_dir);
                    return false;
                }

                free(buffer);

                /* initialize the column family and add it to tidesdb */
                column_family* cf = (column_family*)malloc(sizeof(column_family));

                if (cf == NULL)
                {
                    closedir(cf_dir);
                    closedir(tdb_dir);
                    return false;
                }

                cf->config = *config;
                cf->path = strdup(cf_path);
                cf->sstables = NULL;
                cf->num_sstables = 0;
                cf->memtable = new_skiplist(cf->config.max_level, cf->config.probability);

                /* we check if the memtable was created */
                if (cf->memtable == NULL)
                {
                    free(cf->config.name);
                    free(cf);
                    closedir(cf_dir);
                    closedir(tdb_dir);
                    return false;
                }

                /* we initialize sstables lock */
                if (pthread_rwlock_init(&cf->sstables_lock, NULL) != 0)
                {
                    free(cf->config.name);
                    free(cf);
                    closedir(cf_dir);
                    closedir(tdb_dir);
                    return false;
                }

                /* we add the column family yo db */
                if (!_add_column_family(tdb, cf))
                {
                    free(cf->config.name);
                    free(cf);
                    closedir(cf_dir);
                    closedir(tdb_dir);
                    return false;
                }
            }
        }

        /* we free up resources */
        closedir(cf_dir);
    }

    /* we free up resources */
    closedir(tdb_dir);

    return true;
}

const char* _get_path_seperator()
{
#ifdef _WIN32
    return "\\";
#else
    return "/";
#endif
}

bool _append_to_wal(tidesdb* tdb, wal* wal, const unsigned char* key, size_t key_size,
                    const unsigned char* value, size_t value_size, time_t ttl, enum OP_CODE op_code,
                    const char* cf)
{
    if (tdb == NULL || wal == NULL || key == NULL) return false;

    column_family* column_family = NULL;
    if (!_get_column_family(tdb, cf, &column_family)) return false;

    operation* op = malloc(sizeof(operation));
    if (op == NULL) return false;

    op->op_code = op_code;
    op->column_family = strdup(cf);

    if (op->column_family == NULL)
    {
        free(op);
        return false;
    }

    op->kv = (key_value_pair*)malloc(sizeof(key_value_pair));
    if (op->kv == NULL)
    {
        free(op->column_family);
        free(op);
        return false;
    }

    op->kv->key = (unsigned char*)malloc(key_size);
    if (op->kv->key == NULL)
    {
        free(op->column_family);
        free(op->kv);
        free(op);
        return false;
    }

    memcpy(op->kv->key, key, key_size);
    op->kv->key_size = key_size;

    op->kv->value = (unsigned char*)malloc(value_size);
    if (op->kv->value == NULL)
    {
        free(op->column_family);
        free(op->kv->key);
        free(op->kv);
        free(op);
        return false;
    }

    memcpy(op->kv->value, value, value_size);
    op->kv->value_size = value_size;
    op->kv->ttl = ttl;

    uint8_t* serialized_op_buffer = NULL;
    size_t serialized_op_buffer_size = 0;

    if (!serialize_operation(op, &serialized_op_buffer, &serialized_op_buffer_size,
                             tdb->config.compressed_wal))
    {
        free(op->column_family);
        free(op->kv->key);
        free(op->kv->value);
        free(op->kv);
        free(op);
        return false;
    }

    unsigned int pg_num = 0;
    if (!pager_write(wal->pager, serialized_op_buffer, serialized_op_buffer_size, &pg_num))
    {
        free(op->column_family);
        free(op->kv->key);
        free(op->kv->value);
        free(op->kv);
        free(op);
        free(serialized_op_buffer);
        return false;
    }

    free(op->column_family);
    free(op->kv->key);
    free(op->kv->value);
    free(op->kv);
    free(op);
    free(serialized_op_buffer);

    return true;
}

bool _open_wal(const char* db_path, wal** w)
{
    /* we check if the db path is NULL */
    if (db_path == NULL) return false;

    /* we check if wal is NULL */
    if (w == NULL) return false;

    char wal_path[PATH_MAX];
    snprintf(wal_path, sizeof(wal_path), "%s%s%s", db_path, _get_path_seperator(), WAL_EXT);

    pager* p = NULL;
    if (!pager_open(wal_path, &p)) return false;

    *w = (wal*)malloc(sizeof(wal));
    if (*w == NULL)
    {
        pager_close(p);
        return false;
    }

    (*w)->pager = p;
    if (pthread_rwlock_init(&(*w)->lock, NULL) != 0)
    {
        free(*w);
        pager_close(p);
        return false;
    }

    return true;
}

void _close_wal(wal* wal)
{
    /* we check if the wal is NULL */
    if (wal == NULL) return;

    /* we close the pager */
    pager_close(wal->pager);

    /* we destroy the lock */
    pthread_rwlock_destroy(&wal->lock);

    /* we free the wal */
    free(wal);
}

bool _truncate_wal(wal* wal, int checkpoint)
{
    if (wal == NULL) return false;

    /* lock wal */
    pthread_rwlock_wrlock(&wal->lock);

    /* truncate the wal to provided checkpoint */
    if (!pager_truncate(wal->pager, checkpoint))
    {
        /* unlock wal */
        pthread_rwlock_unlock(&wal->lock);
        return false;
    }

    /* unlock wal */
    pthread_rwlock_unlock(&wal->lock);

    return true;
}

bool _replay_from_wal(tidesdb* tdb, wal* wal)
{
    if (wal == NULL || tdb == NULL) return false;

    /* we check if the wal is empty */
    size_t pages_count = 0;
    if (!pager_pages_count(wal->pager, &pages_count)) return false; /* failed to get pages count */

    if (pages_count == 0) return true; /* wal is empty */

    pager_cursor* pc = NULL;

    if (pager_cursor_init(wal->pager, &pc))
    {
        do
        {
            unsigned int pg_num;
            if (!pager_cursor_get(pc, &pg_num)) break;

            operation* op = NULL;

            uint8_t* op_buffer = NULL;
            size_t op_buffer_size = 0;

            if (!pager_read(wal->pager, pg_num, &op_buffer, &op_buffer_size))
            {
                free(op_buffer);
                break;
            }

            if (!deserialize_operation(op_buffer, op_buffer_size, &op, tdb->config.compressed_wal))
            {
                free(op_buffer);
                break;
            }

            column_family* cf = NULL;

            if (!_get_column_family(tdb, op->column_family, &cf))
            {
                free(op_buffer);
                free(op);
                break;
            }

            switch (op->op_code)
            {
                case OP_PUT:
                    skiplist_put(cf->memtable, op->kv->key, op->kv->key_size, op->kv->value,
                                 op->kv->value_size, op->kv->ttl);
                    break;

                case OP_DELETE:
                    unsigned char* tombstone = (unsigned char*)malloc(4);
                    if (tombstone != NULL)
                    {
                        uint32_t tombstone_value = TOMBSTONE;
                        memcpy(tombstone, &tombstone_value, sizeof(uint32_t));
                    }

                    /* add to memtable */
                    if (!skiplist_put(cf->memtable, op->kv->key, op->kv->key_size, tombstone, 4,
                                      -1))
                    {
                        free(tombstone);
                        break;
                    }

                    free(tombstone);
                    break;

                default:
                    break;
            }

            free(op->kv->value);
            free(op->kv->key);
            free(op->kv);
            free(op);
            free(op_buffer);

        } while (pager_cursor_next(pc));
    }

    pager_cursor_free(pc);

    return true;
}

bool _free_sstable(sstable* sst)
{
    /* we check if the sstable is NULL */
    if (sst == NULL) return false;

    /* we close the pager */
    pager_close(sst->pager);

    /* we free the sstable */
    free(sst);

    sst = NULL;

    return true;
}

int _compare_sstables(const void* a, const void* b)
{
    if (a == NULL || b == NULL) return 0;

    sstable* s1 = (sstable*)a;
    sstable* s2 = (sstable*)b;

    time_t last_modified_s1 = get_last_modified(s1->pager->filename);
    time_t last_modified_s2 = get_last_modified(s2->pager->filename);

    switch ((last_modified_s1 < last_modified_s2) - (last_modified_s1 > last_modified_s2))
    {
        case -1:
            return -1;
        case 1:
            return 1;
        default:
            return 0;
    }
}

bool _flush_memtable(tidesdb* tdb, column_family* cf, skiplist* memtable, int wal_checkpoint)
{
    /* we check if the tidesdb is NULL */
    if (tdb == NULL) return false;

    /* we check if the column family is NULL */
    if (cf == NULL) return false;

    /* we check if the memtable is NULL */
    if (memtable == NULL) return false;

    pthread_rwlock_wrlock(&cf->sstables_lock);
    char filename[1024];

    snprintf(filename, sizeof(filename), "%s%ssstable_%u%s", cf->path, _get_path_seperator(),
             cf->num_sstables, SSTABLE_EXT);

    pager* p = NULL;

    if (!pager_open(filename, &p))
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        return false;
    }

    sstable* sst = malloc(sizeof(sstable)); /* allocate memory for sstable */
    if (sst == NULL)
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        pager_close(p);
        return false;
    }

    sst->pager = p; /* set pager for sstable */

    bloomfilter* bf = bloomfilter_create(BLOOMFILTER_SIZE);
    if (bf == NULL)
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        free(sst);
        pager_close(p);
        return false;
    }

    /* create new cursor */
    skiplist_cursor* cursor = skiplist_cursor_init(memtable);
    if (cursor == NULL)
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        bloomfilter_destroy(bf);
        free(sst);
        pager_close(p);
        return false;
    }

    /* iterate over the memtable */
    do
    {
        if (cursor->current == NULL) continue;

        /* check if value is tombstone */
        if (_is_tombstone(cursor->current->value, cursor->current->value_size)) continue;

        /* check if ttl is set and if so if it has expired */
        if (cursor->current->ttl > 0 && cursor->current->ttl < time(NULL)) continue;

        /* we add the key to the bloom filter */
        bloomfilter_add(bf, cursor->current->key, cursor->current->key_size);
    } while (skiplist_cursor_next(cursor));

    /* we free cursor and create a new one */
    skiplist_cursor_free(cursor);

    if (bf->size == 0)
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        bloomfilter_destroy(bf);
        free(sst);
        pager_close(p);
        return false;
    }

    /* we serialize the bloom filter */
    uint8_t* bf_buffer = NULL;
    size_t bf_buffer_len = 0;
    if (!serialize_bloomfilter(bf, &bf_buffer, &bf_buffer_len, cf->config.compressed))
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        bloomfilter_destroy(bf);
        free(sst);
        pager_close(p);
        return false;
    }

    /* we write the bloom filter to the sstable */
    unsigned int pg_num = 0;

    if (!pager_write(p, bf_buffer, bf_buffer_len, &pg_num))
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        bloomfilter_destroy(bf);
        free(bf_buffer);
        free(sst);
        pager_close(p);
        return false;
    }

    /* we free the bloom filter */
    bloomfilter_destroy(bf);
    free(bf_buffer);

    cursor = skiplist_cursor_init(memtable);
    if (cursor == NULL)
    {
        pthread_rwlock_unlock(&cf->sstables_lock);
        free(sst);
        pager_close(p);
        return false;
    }

    /* we iterate over the memtable and write the key-value pairs to the sstable */
    do
    {
        if (cursor->current == NULL) continue;

        /* check if value is tombstone */
        if (_is_tombstone(cursor->current->value, cursor->current->value_size)) continue;

        /* check if ttl is set and if so if it has expired */
        if (cursor->current->ttl > 0 && cursor->current->ttl < time(NULL)) continue;

        /* we serialize the key-value pair */
        size_t encoded_size;
        key_value_pair kvp = {cursor->current->key, cursor->current->key_size,
                              cursor->current->value, cursor->current->value_size,
                              cursor->current->ttl};
        uint8_t* serialized_buffer = NULL;
        if (!serialize_key_value_pair(&kvp, &serialized_buffer, &encoded_size,
                                      cf->config.compressed))
            continue;

        if (serialized_buffer == NULL)
        {
            pthread_rwlock_unlock(&cf->sstables_lock);
            skiplist_cursor_free(cursor);
            free(sst);
            pager_close(p);
            return false;
        }

        /* we write the key-value pair to the sstable */
        if (!pager_write(p, serialized_buffer, encoded_size, &pg_num))
        {
            free(serialized_buffer);
            continue;
        }

        /* we free the serialized key-value pair */
        free(serialized_buffer);
    } while (skiplist_cursor_next(cursor));

    /* we free the cursor */
    skiplist_cursor_free(cursor);

    /* we now add the sstable to the column family */
    sstable** new_sstables = realloc(cf->sstables, (cf->num_sstables + 1) * sizeof(sstable*));
    if (new_sstables == NULL)
    {
        free(sst);
        pager_close(p);
        pthread_rwlock_unlock(&cf->sstables_lock);
        return false;
    }

    cf->sstables = new_sstables;
    cf->sstables[cf->num_sstables] = sst;
    cf->num_sstables++;
    pthread_rwlock_unlock(&cf->sstables_lock);

    skiplist_clear(memtable);
    skiplist_destroy(memtable);

    /* truncate the wal */
    if (!_truncate_wal(tdb->wal, wal_checkpoint)) return false;

    return true;
}

void* _flush_memtable_thread(void* arg)
{
    /* we set tidesdb */
    tidesdb* tdb = arg;

    while (true)
    {
        pthread_mutex_lock(&tdb->flush_lock);

        /* wait for the queue to have an element or stop signal */
        while (tdb->flush_queue->size == 0 && !tdb->stop_flush_thread)
            pthread_cond_wait(&tdb->flush_cond, &tdb->flush_lock);

        /* check if we need to stop the thread */
        if (tdb->stop_flush_thread)
        {
            pthread_mutex_unlock(&tdb->flush_lock);
            break;
        }

        /* dequeue the first memtable from the queue */
        queue_entry* qe = queue_dequeue(tdb->flush_queue);
        if (qe == NULL)
        {
            pthread_mutex_unlock(&tdb->flush_lock);
            continue;
        }

        pthread_mutex_unlock(&tdb->flush_lock);

        /* flush the memtable to disk sstable */
        _flush_memtable(tdb, qe->cf, qe->memtable, (int)qe->wal_checkpoint);
        free(qe);
    }

    /* escalate what's left in queue */
    while (tdb->flush_queue->size > 0)
    {
        queue_entry* qe = queue_dequeue(tdb->flush_queue);
        if (qe != NULL)
        {
            _flush_memtable(tdb, qe->cf, qe->memtable, (int)qe->wal_checkpoint);
            free(qe);
        }
    }

    return NULL;
}

bool _is_tombstone(const unsigned char* value, size_t value_size)
{
    return value_size == 4 && *(uint32_t*)value == TOMBSTONE;
}

tidesdb_err* tidesdb_close(tidesdb* tdb)
{
    if (tdb == NULL) return tidesdb_err_new(1002, "TidesDB is NULL");

    /* we lock the column families lock */
    if (pthread_rwlock_wrlock(&tdb->column_families_lock) != 0)
        return tidesdb_err_new(1003, "Failed to lock column families lock");

    /* we check if we have column families */
    if (tdb->num_column_families > 0)
    {
        /* we iterate over the column families and free them */
        for (int i = 0; i < tdb->num_column_families; i++)
        {
            /* we free the column family */
            free(tdb->column_families[i].config.name);
            free(tdb->column_families[i].path);
            if (tdb->column_families[i].memtable != NULL)
            {
                skiplist_clear(tdb->column_families[i].memtable);
                skiplist_destroy(tdb->column_families[i].memtable);
            }

            pthread_rwlock_destroy(&tdb->column_families[i].sstables_lock);

            /* we free the sstables */
            if (tdb->column_families[i].sstables != NULL)
            {
                for (int j = 0; j < tdb->column_families[i].num_sstables; j++)
                    _free_sstable(tdb->column_families[i].sstables[j]);

                free(tdb->column_families[i].sstables);
            }
        }

        /* we free the column families */
        free(tdb->column_families);
    }

    /* we unlock the column families lock */
    pthread_rwlock_unlock(&tdb->column_families_lock);

    /* we stop the flush thread */
    tdb->stop_flush_thread = true;

    /* we get flush lock */
    if (pthread_mutex_lock(&tdb->flush_lock) != 0)
        return tidesdb_err_new(1053, "Failed to lock flush lock");

    /* we signal the flush condition */
    if (pthread_cond_signal(&tdb->flush_cond) != 0)
        return tidesdb_err_new(1040, "Failed to signal flush condition");

    /* we unlock the flush lock */
    if (pthread_mutex_unlock(&tdb->flush_lock) != 0)
        return tidesdb_err_new(1005, "Failed to unlock flush lock");

    /* we join the flush thread */
    if (pthread_join(tdb->flush_thread, NULL) != 0)
        return tidesdb_err_new(1006, "Failed to join flush thread");

    /* now we clean up flush lock and condition */
    if (pthread_mutex_destroy(&tdb->flush_lock) != 0)
        return tidesdb_err_new(1007, "Failed to destroy flush lock");

    if (pthread_cond_destroy(&tdb->flush_cond) != 0)
        return tidesdb_err_new(1043, "Failed to destroy flush condition");

    /* we destroy the flush queue */
    queue_destroy(tdb->flush_queue);

    /* we close the wal */
    if (tdb->wal != NULL) _close_wal(tdb->wal);

    /* we destroy the column families lock */
    if (pthread_rwlock_destroy(&tdb->column_families_lock) != 0)
        return tidesdb_err_new(1044, "Failed to destroy column families lock");

    /* we free the tidesdb */
    free(tdb);

    tdb = NULL;

    return NULL;
}

bool _load_sstables(column_family* cf)
{
    /* we check if cf is NULL */
    if (cf == NULL) return false;

    /* we open the column family directory */
    DIR* cf_dir = opendir(cf->path);
    if (cf_dir == NULL)
    { /* we check if the directory was opened */
        return false;
    }

    struct dirent* entry;

    /* we iterate over the column family directory */
    while ((entry = readdir(cf_dir)) != NULL)
    {
        /* we skip the . and .. directories */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        /* we check if the file ends with .sst or contains */
        if (strstr(entry->d_name, ".sst") == NULL) continue;

        /* we construct the path to the sstable */
        char sstable_path[PATH_MAX];
        snprintf(sstable_path, sizeof(sstable_path), "%s%s%s", cf->path, _get_path_seperator(),
                 entry->d_name);

        /* we open the sstable */
        pager* sstable_pager = NULL;

        if (!pager_open(sstable_path, &sstable_pager))
        {
            /* free up resources */
            closedir(cf_dir);

            return false;
        }

        /* we create/alloc the sstable struct */
        sstable* sst = malloc(sizeof(sstable));
        if (sst == NULL) return false;

        /* we set the pager */
        sst->pager = sstable_pager;

        /* check if sstables is NULL */
        if (cf->sstables == NULL)
        {
            cf->sstables = malloc(sizeof(sstable));
            if (cf->sstables == NULL) return false;
        }
        else
        {
            /* we add the sstable to the column family */
            sstable** temp_sstables =
                realloc(cf->sstables, sizeof(sstable) * (cf->num_sstables + 1));
            if (temp_sstables == NULL) return false;

            cf->sstables = temp_sstables;
        }

        cf->sstables[cf->num_sstables] = sst;

        /* we increment the number of sstables */
        cf->num_sstables++;

        /* we free up resources */
        closedir(cf_dir);

        return true;
    }

    return false;
}

bool _sort_sstables(const column_family* cf)
{
    /* we check if the column family is NULL */
    if (cf == NULL) return false;

    /* if we have more than 1 sstable we sort them by last modified time */
    if (cf->num_sstables > 1)
    {
        qsort(cf->sstables, cf->num_sstables, sizeof(sstable), _compare_sstables);
        return true;
    }

    return false;
}

int _remove_directory(const char* path)
{
    /* we check if the path is NULL */
    if (path == NULL) return -1;

    /* we open the directory */
    struct dirent* entry;
    DIR* dir = opendir(path);

    /* we check if the directory was opened */
    if (dir == NULL)
    {
        perror("opendir");
        return -1;
    }

    /* we iterate over the directory */
    while ((entry = readdir(dir)) != NULL)
    {
        char full_path[1024];
        struct stat statbuf;

        /* we skip the . and .. directories */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        /* we construct the full path */
        snprintf(full_path, sizeof(full_path), "%s%s%s", path, _get_path_seperator(),
                 entry->d_name);

        /* we get the stat of the file */
        if (stat(full_path, &statbuf) == -1)
        {
            perror("stat");
            closedir(dir);
            return -1;
        }

        /* we check if the file is a directory */
        if (S_ISDIR(statbuf.st_mode))
        {
            /* we recursively remove the directory */
            if (_remove_directory(full_path) == -1)
            {
                closedir(dir);
                return -1;
            }
        }
        else
        {
            /* we remove the file */
            if (remove(full_path) == -1)
            {
                perror("remove");
                closedir(dir);
                return -1;
            }
        }
    }

    closedir(dir);

    if (rmdir(path) == -1)
    {
        perror("rmdir");
        return -1;
    }

    return 0;
}

void _sst_extract_numeric_parts(const char* filename, char* numeric_parts)
{
    const char* start = strrchr(filename, '_'); /* we get last '_' */

    if (start != NULL)
    {
        start++;                               /* move past the last '_' */
        const char* end = strrchr(start, '.'); /* stop at extension */
        if (end != NULL)
        {
            strncpy(numeric_parts, start, end - start); /* copy the numeric part */
            numeric_parts[end - start] = '\0';
        }
    }
}