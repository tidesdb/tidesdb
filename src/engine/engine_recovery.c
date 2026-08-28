/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/encoding/serialization.h" /* TDB_WAL_EXT */
#include "base/errors.h"
#include "base/log.h"
#include "column_family/cf_config.h"
#include "compat.h" /* PATH_SEPARATOR, opendir, readdir */
#include "engine_internal.h"
#include "io/block_manager.h"

/* rebuilding the write side from what is on disk -- the column family registry the manifest
 * records, and every surviving WAL generation replayed back into L0 behind a fresh active memtable.
 * reached only from engine_open, but kept apart from it because recovery reasons about the on-disk
 * layout where the rest of the composition root only wires live objects together. */

/* the next sstable id is one past the highest id any recovered manifest entry carries */
static uint64_t engine_recovered_max_sstable_id(const tidesdb_manifest_t *manifest)
{
    uint64_t max_id = 0;
    for (int i = 0; i < manifest->num_entries; i++)
        if (manifest->entries[i].id > max_id) max_id = manifest->entries[i].id;
    return max_id;
}

/* the highest sequence any recovered sstable holds, so the clock reseeds past data whose WAL a
 * flush already unlinked. after a flush retires an immutable and drops its WAL, the sstable is the
 * only record of those sequences, and a crash with no clean close leaves the manifest sequence
 * stale, so without this a snapshot read would filter every flushed row out */
uint64_t engine_recovered_max_sstable_seq(tidesdb_t *db)
{
    uint64_t max_seq = 0;
    cf_registry_rdlock(db->cfs);
    const int n = cf_registry_count_locked(db->cfs);
    for (int i = 0; i < n; i++)
    {
        cf_t *cf = cf_registry_at_locked(db->cfs, i);
        if (!cf) continue;
        const int total = level_set_collect_all(cf->levels, NULL, 0);
        if (total <= 0) continue;
        sstable_t **arr = malloc((size_t)total * sizeof(*arr));
        if (!arr) continue;
        const int got = level_set_collect_all(cf->levels, arr, total);
        if (got <= total)
            for (int j = 0; j < got; j++)
            {
                if (arr[j]->max_seq > max_seq) max_seq = arr[j]->max_seq;
                if (sstable_unref(arr[j])) sstable_close(arr[j]);
            }
        free(arr);
    }
    cf_registry_rdunlock(db->cfs);
    return max_seq;
}

/* the zero-padded width of an sstable id in a .klog file name, matching what the sstable module
 * writes */
#define ENGINE_SSTABLE_ID_DIGITS 7

/* the family-id field leading a key log's name, matching what sstable_klog_filename writes */
#define ENGINE_CF_ID_DIGITS 10

/* families a rebuild will adopt from a directory of orphaned key logs. a rebuild is a last resort
 * over whatever survived, so the bound is a guard against a corrupt directory rather than a limit
 * any real database approaches */
#define ENGINE_REBUILD_MAX_FAMILIES 4096

/* the level an adopted sstable is placed at. no file records the level it sat at, and L1 is the
 * one tier whose members may overlap in key range, so it is the only placement that cannot be
 * wrong */
#define ENGINE_REBUILD_LEVEL 1

/* adopted sstables are reopened without per-write durability -- they are read, never appended */
#define ENGINE_REBUILD_SYNC BLOCK_MANAGER_SYNC_NONE

/* whether name is exactly a CCCCCCCCCC.NNNNNNN.klog sstable file, decoding the family id into
 * out_cf_id and the sstable id into out_id. the family is part of the name because it is no longer
 * part of the path */
static int engine_parse_klog_name(const char *name, uint64_t *out_cf_id, uint64_t *out_id)
{
    const size_t ext_len = strlen(TDB_SSTABLE_KLOG_EXT);
    const size_t stem = (size_t)ENGINE_CF_ID_DIGITS + 1 + (size_t)ENGINE_SSTABLE_ID_DIGITS;
    if (strlen(name) != stem + ext_len) return 0;
    if (name[ENGINE_CF_ID_DIGITS] != '.') return 0;
    for (size_t i = 0; i < stem; i++)
    {
        if (i == (size_t)ENGINE_CF_ID_DIGITS) continue;
        if (name[i] < '0' || name[i] > '9') return 0;
    }
    if (strcmp(name + stem, TDB_SSTABLE_KLOG_EXT) != 0) return 0;

    *out_cf_id = strtoull(name, NULL, 10);
    *out_id = strtoull(name + ENGINE_CF_ID_DIGITS + 1, NULL, 10);
    return 1;
}

/* whether name ends with the leaf staging suffix, so a file abandoned mid-build is recognisable */
static int engine_is_klog_stage_name(const char *name)
{
    const size_t len = strlen(name);
    const size_t suffix_len = strlen(TDB_SSTABLE_KLOG_STAGE_EXT);
    if (len <= suffix_len) return 0;
    return strcmp(name + len - suffix_len, TDB_SSTABLE_KLOG_STAGE_EXT) == 0;
}

/* remove the key logs in dir that the manifest does not name, and any staging file left beside
 * them. returns the number of files unlinked */
static int engine_sweep_dir(tidesdb_t *db, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return 0;

    int swept = 0;
    const struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        uint64_t cf_id = 0, id = 0;
        const int is_klog = engine_parse_klog_name(e->d_name, &cf_id, &id);
        if (!is_klog && !engine_is_klog_stage_name(e->d_name)) continue;

        /* a klog the catalogue still names is live, whatever else is true of it -- including one
         * recovery skipped as unreadable, which stays for an operator to look at. the family comes
         * from the name, so a file left by a family that no longer exists is swept here too */
        if (is_klog && tidesdb_manifest_find_level_by_id(db->manifest, cf_id, id) > 0) continue;

        char path[CF_DIR_PATH_LEN];
        if (snprintf(path, sizeof(path), "%s%s%s", dir, PATH_SEPARATOR, e->d_name) >=
            (int)sizeof(path))
            continue;
        if (remove(path) == 0)
            swept++;
        else
            TDB_DEBUG_LOG(TDB_LOG_WARN, "could not unlink orphaned %s", path);
    }
    closedir(d);
    return swept;
}

int engine_sweep_orphan_sstables(tidesdb_t *db)
{
    if (!db || !db->manifest) return TDB_SUCCESS;

    /* a self-healed manifest was rebuilt from whatever sstables were on disk, so the files are the
     * catalogue's source rather than the other way round. sweeping against it would delete exactly
     * the ones the rebuild could not adopt, which is the last copy of that data */
    if (tidesdb_manifest_self_healed(db->manifest)) return TDB_SUCCESS;

    /* one pass over the database directory rather than one per family: every key log names the
     * family it belongs to, so the registry does not have to be walked to find them */
    const int swept = engine_sweep_dir(db, db->db_path);

    /* one line only when there was something to say, since a healthy database sweeps nothing and a
     * line every open would train an operator to ignore it */
    if (swept > 0)
        TDB_DEBUG_LOG(TDB_LOG_INFO, "removed %d orphaned sstable files left by an earlier run",
                      swept);
    return TDB_SUCCESS;
}

/* readopt one family's klogs into the manifest, each at L1. returns the number adopted, or -1 when
 * the directory could not be read */
static int engine_readopt_cf_dir(tidesdb_t *db, const char *cf_dir, uint64_t cf_id,
                                 const char *cf_name)
{
    DIR *d = opendir(cf_dir);
    if (!d) return -1;

    int adopted = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        uint64_t found_cf = 0, id = 0;
        if (!engine_parse_klog_name(ent->d_name, &found_cf, &id)) continue;
        if (found_cf != cf_id) continue;

        tidesdb_manifest_entry_t naming = {0};
        naming.id = id;
        naming.column_family_id = cf_id;
        naming.partition = MANIFEST_NO_PARTITION;
        naming.birth_level = ENGINE_REBUILD_LEVEL;

        /* the footer is the only description the file carries, so opening it is what says whether
         * this is a usable sstable at all. one left half-written by a crash fails here and is left
         * on disk untouched rather than adopted into the catalogue */
        sstable_t *sst = NULL;
        if (sstable_open_from_manifest(&sst, cf_dir, cf_name, &naming, ENGINE_REBUILD_SYNC,
                                       &db->encodings, db->cache, &db->fdm, db->arena,
                                       &db->now_seconds) != TDB_SUCCESS)
        {
            TDB_DEBUG_LOG(TDB_LOG_WARN, "rebuild skipping unreadable sstable %llu in %s",
                          (unsigned long long)id, cf_dir);
            continue;
        }

        uint64_t bytes = 0;
        block_manager_t *bm = sstable_ensure_open(sst);
        if (bm) (void)block_manager_get_size(bm, &bytes);
        const uint64_t entries = sst->distinct_key_count;
        const uint64_t max_seq = sst->max_seq;
        if (sstable_unref(sst)) sstable_close(sst);

        if (tidesdb_manifest_add_sstable(db->manifest, cf_id, ENGINE_REBUILD_LEVEL, id, entries,
                                         bytes, MANIFEST_NO_PARTITION) != 0)
        {
            closedir(d);
            return -1;
        }
        /* the clock has to resume above every sequence the adopted files hold, exactly as it does
         * for a manifest that survived */
        if (max_seq > 0) tidesdb_manifest_update_sequence(db->manifest, max_seq);
        adopted++;
    }
    closedir(d);
    return adopted;
}

/* whether a rebuild's catalogue writes should be made durable, which every mode but sync none
 * asks for */
static int engine_rebuild_durable(const tidesdb_t *db)
{
    return db->config.memtable_sync_mode != TDB_SYNC_NONE ? 1 : 0;
}

/**
 * engine_rebuild_from_sstables
 * rebuild what the catalogue lost from the files still on disk. a manifest whose header would not
 * validate is discarded at open, and without this every sstable in the database directory would
 * be unreferenced -- present, readable, and invisible. the footer is self-describing enough to
 * adopt a file, so each one is reopened and re-registered.
 *
 * two things the files cannot supply, and the limits they impose. a family's name lives only in
 * the manifest, and a key log carries its family's id rather than its name, so a rebuilt family is
 * named for that id and an operator renames it back; and no file records which level it sat at, so
 * every adopted sstable is placed at L1, the one tier that permits overlapping ranges. correctness
 * is unaffected -- versions resolve by sequence, not by level -- but the tree is left shallow and
 * compaction has work to do.
 * @param db the database, already through the manifest open
 * @return TDB_SUCCESS, or TDB_ERR_MEMORY when the catalogue could not be written back
 */
static int engine_rebuild_from_sstables(tidesdb_t *db)
{
    DIR *dir = opendir(db->db_path);
    if (!dir) return TDB_SUCCESS; /* nothing to adopt is not a failure */

    int families = 0, tables = 0, rc = TDB_SUCCESS, capped = 0;
    uint64_t max_cf_id = 0;
    struct dirent *ent;
    uint64_t seen[ENGINE_REBUILD_MAX_FAMILIES];
    int n_seen = 0;
    while (rc == TDB_SUCCESS && (ent = readdir(dir)) != NULL)
    {
        uint64_t cf_id = 0, sst_id = 0;
        if (!engine_parse_klog_name(ent->d_name, &cf_id, &sst_id)) continue;

        /* families are discovered from the files that name them, so each is adopted once however
         * many key logs it left behind */
        int already = 0;
        for (int i = 0; i < n_seen; i++)
            if (seen[i] == cf_id) already = 1;
        if (already) continue;
        if (n_seen == ENGINE_REBUILD_MAX_FAMILIES)
        {
            /* noted so the line below can say the rebuild stopped rather than finished -- a count
             * on its own reads as the whole directory, and the families past here are left
             * uncatalogued with their files still on disk */
            capped = 1;
            break;
        }
        seen[n_seen++] = cf_id;

        char cf_dir[CF_DIR_PATH_LEN];
        if (snprintf(cf_dir, sizeof(cf_dir), "%s", db->db_path) < 0) continue;

        /* the id is the only name left, so it becomes the family's until renamed */
        tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
        snprintf(cc.name, sizeof(cc.name), CF_DIR_PREFIX "%0*llu", CF_DIR_ID_DIGITS,
                 (unsigned long long)cf_id);

        uint8_t *blob = NULL;
        size_t blob_len = 0;
        if (cf_config_serialize(&cc, &blob, &blob_len) != 0)
        {
            rc = TDB_ERR_MEMORY;
            break;
        }
        if (tidesdb_manifest_add_cf(db->manifest, cf_id, cc.name, blob, blob_len) != 0)
            rc = TDB_ERR_MEMORY;
        free(blob);
        if (rc != TDB_SUCCESS) break;

        const int n = engine_readopt_cf_dir(db, cf_dir, cf_id, cc.name);
        if (n < 0)
        {
            rc = TDB_ERR_MEMORY;
            break;
        }
        if (cf_id > max_cf_id) max_cf_id = cf_id;
        families++;
        tables += n;
    }
    closedir(dir);
    if (rc != TDB_SUCCESS) return rc;
    if (families == 0) return TDB_SUCCESS;

    /* the cf-id allocator has to resume past every id adopted, or a family created later reuses one
     * and inherits its files. the high-water is raised, never lowered, so passing the largest
     * adopted id plus one is safe whatever the manifest already held */
    tidesdb_manifest_update_next_cf_id(db->manifest, max_cf_id + 1);

    if (tidesdb_manifest_commit(db->manifest, db->manifest->path, engine_rebuild_durable(db)) != 0)
        return TDB_ERR_IO;

    TDB_DEBUG_LOG(
        TDB_LOG_WARN,
        "manifest was unreadable, rebuilt %d families and %d sstables from disk at L1; "
        "families are named for their id and carry the default configuration until renamed",
        families, tables);
    if (capped)
        TDB_DEBUG_LOG(
            TDB_LOG_ERROR,
            "the rebuild stopped at its %d-family bound, so this directory holds families "
            "it did not adopt and whose files it left in place",
            ENGINE_REBUILD_MAX_FAMILIES);
    return TDB_SUCCESS;
}

/* rebuild the cf registry from the manifest -- open every persisted cf from its recorded config
 * blob and sstable entries, seed the cf-id allocator past the highest recovered id, and seed the
 * sstable-id sequence past the highest recovered entry id. an empty manifest yields an empty
 * registry. */
int engine_recover_cfs(tidesdb_t *db)
{
    /* a discarded manifest describes nothing, so the files on disk are all that is left to rebuild
     * from. done before the registry is read so the adopted entries are simply part of it */
    if (tidesdb_manifest_self_healed(db->manifest))
    {
        const int rc = engine_rebuild_from_sstables(db);
        if (rc != TDB_SUCCESS) return rc;
    }

    const int n = tidesdb_manifest_copy_cfs(db->manifest, NULL, 0);
    tidesdb_manifest_cf_t *cfs = NULL;
    if (n > 0)
    {
        cfs = malloc((size_t)n * sizeof(*cfs));
        if (!cfs) return TDB_ERR_MEMORY;
        if (tidesdb_manifest_copy_cfs(db->manifest, cfs, n) != n)
        {
            free(cfs);
            return TDB_ERR_IO;
        }
    }

    /* the surviving families only floor the allocator, since the largest id may belong to a family
     * that was dropped. the manifest's high-water is the authority -- it outlives the drop, so an
     * id whose unreaped wal records could still replay is never handed out a second time */
    uint64_t next_id = ENGINE_FIRST_CF_ID;
    for (int i = 0; i < n; i++)
        if (cfs[i].id + 1 > next_id) next_id = cfs[i].id + 1;
    const uint64_t recorded = atomic_load_explicit(&db->manifest->next_cf_id, memory_order_acquire);
    if (recorded > next_id) next_id = recorded;
    TDB_DEBUG_LOG(TDB_LOG_TRACE, "recovered %d cfs, cf id allocator seeded at %llu", n,
                  (unsigned long long)next_id);
    db->cfs = cf_registry_create(next_id);
    if (!db->cfs)
    {
        free(cfs);
        return TDB_ERR_MEMORY;
    }

    const int bm_sync = engine_durable_sync_mode(db->config.memtable_sync_mode);
    int rc = TDB_SUCCESS;
    for (int i = 0; i < n && rc == TDB_SUCCESS; i++)
    {
        /* keep the l0 cf-index allocator past every recovered index so it never reuses one */
        tidesdb_l0_cf_index_observe(db->l0, (uint32_t)cfs[i].id);
        if (cfs[i].config_blob_len == 0)
        {
            TDB_DEBUG_LOG(TDB_LOG_WARN, "cf %s has no persisted config, skipping recovery",
                          cfs[i].name);
            continue;
        }
        cf_t *cf = NULL;
        if (cf_open(db->db_path, db->manifest, cfs[i].id, cfs[i].name, cfs[i].config_blob,
                    cfs[i].config_blob_len, &db->encodings, db->vlog, db->cache, &db->fdm, bm_sync,
                    db->node_arena, &db->now_seconds, &cf) != 0)
        {
            rc = TDB_ERR_IO;
            break;
        }
        if (cf_registry_add(db->cfs, cf) != TDB_SUCCESS)
        {
            cf_free(cf);
            rc = TDB_ERR_MEMORY;
            break;
        }
        /* bind before the wal replay below so replayed keys rebuild the unflushed count */
        tidesdb_l0_bind_cf_counter(db->l0, (uint32_t)cf->cf_id, &cf->unflushed_key_count);
    }
    free(cfs);
    if (rc != TDB_SUCCESS) return rc;

    const uint64_t max_sst = engine_recovered_max_sstable_id(db->manifest);
    atomic_store_explicit(&db->next_sstable_id, max_sst ? max_sst + 1 : ENGINE_FIRST_SSTABLE_ID,
                          memory_order_relaxed);
    return TDB_SUCCESS;
}

/* whether name is exactly a NNNNNNN.log WAL file, decoding its generation into out_gen when it is
 */
/* one write-ahead log found on disk. flushed marks the form kept only for an undecided prepare,
 * whose data records reached L1 already and must not be replayed a second time */
typedef struct
{
    uint64_t gen;
    int flushed;
} engine_wal_gen_t;

static int engine_parse_wal_name(const char *name, uint64_t *out_gen, int *out_flushed)
{
    /* checked before the digits are read, since a shorter name would be walked past its end */
    const size_t len = strlen(name);
    if (len != (size_t)TDB_WAL_ID_DIGITS + strlen(TDB_WAL_EXT) &&
        len != (size_t)TDB_WAL_ID_DIGITS + strlen(TDB_WAL_FLUSHED_EXT))
        return 0;
    for (int i = 0; i < TDB_WAL_ID_DIGITS; i++)
        if (name[i] < '0' || name[i] > '9') return 0;

    /* a log carries one of two names -- the plain one, whose data is durable nowhere else, and the
     * flushed one, kept only for an undecided prepare after its memtable reached L1 */
    const char *ext = name + TDB_WAL_ID_DIGITS;
    int flushed;
    if (strcmp(ext, TDB_WAL_EXT) == 0)
        flushed = 0;
    else if (strcmp(ext, TDB_WAL_FLUSHED_EXT) == 0)
        flushed = 1;
    else
        return 0;

    char digits[TDB_WAL_ID_DIGITS + 1];
    memcpy(digits, name, TDB_WAL_ID_DIGITS);
    digits[TDB_WAL_ID_DIGITS] = '\0';
    *out_gen = strtoull(digits, NULL, 10);
    if (out_flushed) *out_flushed = flushed;
    return 1;
}

/* the log name a generation carries, which says whether its data records still matter */
static int engine_wal_gen_name(const engine_wal_gen_t *g, char *out, size_t out_size)
{
    return g->flushed ? tidesdb_wal_flushed_filename(g->gen, out, out_size)
                      : tidesdb_wal_filename(g->gen, out, out_size);
}

/* collect the WAL generations present under db_path into a sorted-ascending array, each carrying
 * whether its memtable was already flushed; returns the count and sets *out_gens (caller frees),
 * or -1 on error */
static int engine_scan_wal_generations(const char *db_dir, engine_wal_gen_t **out_gens)
{
    *out_gens = NULL;
    DIR *dir = opendir(db_dir);
    if (!dir) return -1;

    engine_wal_gen_t *gens = NULL;
    int count = 0, cap = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL)
    {
        uint64_t gen = 0;
        int flushed = 0;
        if (!engine_parse_wal_name(ent->d_name, &gen, &flushed)) continue;
        if (count == cap)
        {
            const int nc = cap ? cap * 2 : ENGINE_WAL_GEN_LIST_INIT;
            engine_wal_gen_t *grown = realloc(gens, (size_t)nc * sizeof(*grown));
            if (!grown)
            {
                free(gens);
                closedir(dir);
                return -1;
            }
            gens = grown;
            cap = nc;
        }
        gens[count].gen = gen;
        gens[count].flushed = flushed;
        count++;
    }
    closedir(dir);

    for (int i = 1; i < count; i++) /* insertion sort ascending; generations are few */
    {
        const engine_wal_gen_t v = gens[i];
        int j = i - 1;
        while (j >= 0 && gens[j].gen > v.gen)
        {
            gens[j + 1] = gens[j];
            j--;
        }
        gens[j + 1] = v;
    }
    *out_gens = gens;
    return count;
}

/* mint the WAL for a generation and install its memtable -- as the active one when is_first, else
 * by rotating it in, which seals the current active into the immutable queue. repoints wal_bm and
 * the generation counter at the new active */
static int engine_install_generation(tidesdb_t *db, uint64_t gen, int is_first, int sealed,
                                     int flushed)
{
    char wal_name[ENGINE_WAL_NAME_MAX], wal_path[ENGINE_PATH_BUF_SIZE];
    /* a generation kept only for its prepare carries the flushed name, and opening it under the
     * plain one would make an empty log beside it and lose the prepare the file was kept for */
    if ((flushed ? tidesdb_wal_flushed_filename(gen, wal_name, sizeof(wal_name))
                 : tidesdb_wal_filename(gen, wal_name, sizeof(wal_name))) != TDB_SUCCESS)
        return TDB_ERR_INVALID_ARGS;
    if (engine_build_path(db->db_path, wal_name, wal_path, sizeof(wal_path)) != TDB_SUCCESS)
        return TDB_ERR_INVALID_ARGS;
    block_manager_t *wal = NULL;
    const int orc =
        sealed ? engine_open_wal_sealed(db, wal_path, &wal) : engine_open_wal(db, wal_path, &wal);
    if (orc != 0) return TDB_ERR_IO;
    tidesdb_memtable_t *mt = tidesdb_memtable_create(
        wal, gen, gen, db->config.memtable_skip_list_max_level,
        db->config.memtable_skip_list_probability, &db->now_seconds, db->arena);
    if (!mt)
    {
        engine_close_wal(db, wal);
        return TDB_ERR_MEMORY;
    }
    /* the slot is empty on this path -- recovery seeds L0 before anything else installs a memtable,
     * and is_first is only set for the first generation it walks -- so the displaced memtable it
     * would hand back cannot exist */
    if (is_first)
        (void)tidesdb_l0_set_active(db->l0, mt);
    else if (tidesdb_l0_rotate(db->l0, mt) != TDB_SUCCESS)
    {
        tidesdb_memtable_free(mt);
        engine_close_wal(db, wal);
        return TDB_ERR_MEMORY;
    }
    db->wal_bm = wal; /* the previous active's WAL now belongs to the sealed immutable */
    atomic_store_explicit(&db->wal_generation, gen, memory_order_relaxed);
    return TDB_SUCCESS;
}

/* recover the shared L0 from the WAL generations on disk: replay each surviving generation into its
 * own memtable, sealing it into the immutable queue, then install a fresh empty active at the next
 * generation. a db with no WAL files starts a fresh generation-zero active. reports the number of
 * recovered immutables and the highest replayed sequence. the staging map is carried across every
 * generation, since a PREPARE in one is only decided by a COMMIT or ROLLBACK in a later one */
int engine_recover_wal(tidesdb_t *db, int *out_recovered, uint64_t *out_max_seq,
                       tdb_prepare_stage_t *stage)
{
    *out_recovered = 0;
    *out_max_seq = 0;

    engine_wal_gen_t *gens = NULL;
    const int n = engine_scan_wal_generations(db->db_path, &gens);
    if (n < 0) return TDB_ERR_IO;
    if (n == 0)
    {
        free(gens);
        return engine_install_generation(db, ENGINE_FIRST_WAL_GENERATION, 1, 0, 0);
    }

    const uint64_t max_gen = gens[n - 1].gen;
    int rc = TDB_SUCCESS;

    /* collect every cancelled commit before applying anything. a commit that failed after its batch
     * was durable appends its abort to whichever log was active by then, which may be a later
     * generation than the batch itself, so a single forward pass could apply a batch before it ever
     * saw the record cancelling it */
    tidesdb_l0_aborted_set_t aborted = {0};
    for (int i = 0; i < n && rc == TDB_SUCCESS; i++)
    {
        char scan_name[ENGINE_WAL_NAME_MAX], scan_path[ENGINE_PATH_BUF_SIZE];
        if (engine_wal_gen_name(&gens[i], scan_name, sizeof(scan_name)) != TDB_SUCCESS ||
            engine_build_path(db->db_path, scan_name, scan_path, sizeof(scan_path)) != TDB_SUCCESS)
        {
            rc = TDB_ERR_IO;
            break;
        }
        block_manager_t *scan = NULL;
        if (engine_open_wal_sealed(db, scan_path, &scan) != 0)
        {
            rc = TDB_ERR_IO;
            break;
        }
        rc = tidesdb_l0_scan_aborts(scan, &aborted);
        engine_close_wal(db, scan);
    }
    if (rc != TDB_SUCCESS)
    {
        tidesdb_l0_aborted_set_free(&aborted);
        free(gens);
        return rc;
    }

    /* a log can outlive the flush that installed its data -- kept because an undecided prepare
     * lives in it, or left behind by a crash between the install commit and the unlink. replaying
     * such a log puts entries into a memtable that the sstables have already superseded, and every
     * reader takes a memtable as newer than any sstable, so a deleted key would come back. the
     * filter drops exactly those entries, asking the sstables directly rather than the read stack,
     * which at this point is reading the memtables being rebuilt */
    const tidesdb_replay_filter_t filter = {.superseded = engine_replay_superseded, .ctx = db};
    for (int i = 0; i < n && rc == TDB_SUCCESS; i++)
    {
        /* every replayed generation is sealed; only the fresh active below takes writes */
        rc = engine_install_generation(db, gens[i].gen, i == 0, 1, gens[i].flushed);
        if (rc != TDB_SUCCESS) break;
        uint64_t m = 0;
        /* a generation whose memtable already reached L1 keeps its log only for the prepare in it,
         * so its data records are replayed as nothing. they are durable in an sstable, and a
         * compaction may since have retired versions they still name -- putting those back above
         * the sstables is what resurrects a deleted key */
        rc = tidesdb_l0_replay_wal(db->l0, db->wal_bm, gens[i].gen, &aborted, &m, stage, &filter,
                                   gens[i].flushed);
        /* replay carries a record's cf index verbatim and cannot tell a retired one from a live
         * one, so the generation and its high sequence are traced to place a replayed key in time
         */
        TDB_DEBUG_LOG(TDB_LOG_TRACE, "replayed wal generation %llu%s up to seq %llu",
                      (unsigned long long)gens[i].gen,
                      gens[i].flushed ? " (data already in l1)" : "", (unsigned long long)m);
        if (m > *out_max_seq) *out_max_seq = m;
    }
    tidesdb_l0_aborted_set_free(&aborted);
    free(gens);
    if (rc != TDB_SUCCESS) return rc;

    /* seal the last recovered generation by installing a fresh empty active above it */
    rc = engine_install_generation(db, max_gen + 1, 0, 0, 0);
    if (rc != TDB_SUCCESS) return rc;
    *out_recovered = n;
    return TDB_SUCCESS;
}
