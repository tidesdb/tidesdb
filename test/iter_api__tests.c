/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/column_family/column_family.h" /* cf_t and its range tombstone set */
#include "../src/engine/engine.h" /* the mvcc clock the tombstone sequence comes from */
#include "db.h"
#include "test_utils.h"

/* the reverse seek and the standalone value read on the public iterator. the merge iterator under
 * them is covered from the inside, but these two entry points had no caller at all, so nothing held
 * the facade's own behaviour in place. */

static int tests_passed = 0;
static int tests_failed = 0;

#define ITERAPI_DB_DIR "." PATH_SEPARATOR "test_iter_api_db"
#define ITERAPI_CF     "cf0"

static tidesdb_t *iterapi_open(char *db_path)
{
    tidesdb_config_t cfg = tidesdb_default_config();
    cfg.db_path = db_path;
    tidesdb_t *db = NULL;
    ASSERT_EQ(tidesdb_open(&cfg, &db), TDB_SUCCESS);
    ASSERT_TRUE(db != NULL);
    return db;
}

static void iterapi_put(tidesdb_t *db, tidesdb_column_family_t *cf, const char *key,
                        const char *val)
{
    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key), (const uint8_t *)val,
                              strlen(val), -1),
              TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
}

/* the key the iterator sits on, as a nul-terminated string */
static void iterapi_key_at(tidesdb_iter_t *it, char *out, size_t out_cap)
{
    uint8_t *key = NULL;
    size_t key_size = 0;
    ASSERT_EQ(tidesdb_iter_key(it, &key, &key_size), TDB_SUCCESS);
    ASSERT_TRUE(key_size < out_cap);
    memcpy(out, key, key_size);
    out[key_size] = '\0';
    free(key);
}

/* the value the iterator sits on, read through the entry point under test */
static void iterapi_value_at(tidesdb_iter_t *it, char *out, size_t out_cap)
{
    uint8_t *value = NULL;
    size_t value_size = 0;
    ASSERT_EQ(tidesdb_iter_value(it, &value, &value_size), TDB_SUCCESS);
    ASSERT_TRUE(value_size < out_cap);
    memcpy(out, value, value_size);
    out[value_size] = '\0';
    free(value);
}

/* the reverse seek lands on the last key at or below its target, where the forward seek would take
 * the first key at or above it, and the value read reports what sits at that position */
/* a scan hides every key a range tombstone covers, exactly as it already hides one whose newest
 * version is a point tombstone. this is the half a point read cannot stand in for -- the merge
 * resolves each key itself, so a delete written as an interval has to be applied where it lands */
/* the width of the inverted timestamp a versioned key carries */
#define UDT_STAMP_BYTES 8

/* build <id>|<inverted timestamp>. inverting makes a newer stamp sort earlier, so the newest
 * version of an id is the first key under its prefix and a seek to a stamp lands on the newest
 * version at or before it
 * @param out receives the key, at least strlen(id) + 1 + UDT_STAMP_BYTES bytes
 * @param id the logical key
 * @param ts the timestamp the version carries
 * @return the key length
 */
static size_t udt_key(uint8_t *out, const char *id, uint64_t ts)
{
    const size_t n = strlen(id);
    memcpy(out, id, n);
    out[n] = '|';
    const uint64_t inverted = UINT64_MAX - ts;
    for (int i = 0; i < UDT_STAMP_BYTES; i++) out[n + 1 + i] = (uint8_t)(inverted >> (56 - 8 * i));
    return n + 1 + UDT_STAMP_BYTES;
}

/* read the version of id the application would see as of ts, by seeking to the stamp and taking
 * what the iterator lands on when it still belongs to that id
 * @param it the iterator
 * @param id the logical key
 * @param ts the timestamp to read as of
 * @param out receives the value, nul-terminated, or an empty string when no version qualifies
 * @param out_cap capacity of out
 */
static void udt_read_as_of(tidesdb_iter_t *it, const char *id, uint64_t ts, char *out,
                           size_t out_cap)
{
    out[0] = '\0';

    uint8_t probe[64];
    const size_t probe_size = udt_key(probe, id, ts);
    if (tidesdb_iter_seek(it, probe, probe_size) != TDB_SUCCESS) return;
    if (!tidesdb_iter_valid(it)) return;

    uint8_t *k = NULL;
    size_t ks = 0;
    if (tidesdb_iter_key(it, &k, &ks) != TDB_SUCCESS) return;

    /* the seek runs past this id once nothing older remains, so what it landed on has to be checked
     * against the prefix before it is read as a version of it */
    const size_t idn = strlen(id);
    const int mine = ks >= idn + 1 && memcmp(k, id, idn) == 0 && k[idn] == '|';
    free(k); /* the key comes back owned, as the value below does */
    if (!mine) return;

    uint8_t *v = NULL;
    size_t vs = 0;
    if (tidesdb_iter_value(it, &v, &vs) != TDB_SUCCESS) return;
    if (vs >= out_cap) vs = out_cap - 1;
    memcpy(out, v, vs);
    out[vs] = '\0';
    free(v);
}

/* an application timestamp carried in the key, which is how a user-defined timestamp is done here
 * without the engine knowing about one. the ordering is memcmp and nothing else, so inverting the
 * stamp is what makes a seek resolve to the newest version at or before a moment */
void test_iter_user_timestamp_in_the_key_reads_as_of_a_moment(void)
{
    (void)remove_directory(ITERAPI_DB_DIR);
    char db_path[] = ITERAPI_DB_DIR;
    tidesdb_t *db = iterapi_open(db_path);

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, ITERAPI_CF, &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, ITERAPI_CF);
    ASSERT_TRUE(cf != NULL);

    /* three versions of one id, and a neighbour so the prefix boundary is exercised rather than
     * the end of the keyspace standing in for it */
    const uint64_t stamps[3] = {100, 200, 300};
    const char *const values[3] = {"v100", "v200", "v300"};
    for (int i = 0; i < 3; i++)
    {
        uint8_t key[64];
        const size_t key_size = udt_key(key, "doc", stamps[i]);
        tidesdb_txn_t *w = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &w), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(w, cf, key, key_size, (const uint8_t *)values[i],
                                  strlen(values[i]), -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(w), TDB_SUCCESS);
        tidesdb_txn_free(w);
    }
    {
        uint8_t key[64];
        const size_t key_size = udt_key(key, "doe", 100);
        tidesdb_txn_t *w = NULL;
        ASSERT_EQ(tidesdb_txn_begin(db, &w), TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_put(w, cf, key, key_size, (const uint8_t *)"other", 5, -1),
                  TDB_SUCCESS);
        ASSERT_EQ(tidesdb_txn_commit(w), TDB_SUCCESS);
        tidesdb_txn_free(w);
    }

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &it), TDB_SUCCESS);

    char got[32];

    /* exactly on a stamp resolves to that version */
    udt_read_as_of(it, "doc", 300, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "v300") == 0);
    udt_read_as_of(it, "doc", 200, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "v200") == 0);
    udt_read_as_of(it, "doc", 100, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "v100") == 0);

    /* between stamps resolves to the newest version at or before the moment */
    udt_read_as_of(it, "doc", 250, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "v200") == 0);
    udt_read_as_of(it, "doc", 999, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "v300") == 0);

    /* before the first version there is nothing to resolve to, and the neighbour the seek runs
     * into is not mistaken for one */
    udt_read_as_of(it, "doc", 99, got, sizeof(got));
    ASSERT_TRUE(got[0] == '\0');

    /* and the id's own prefix is what separates it from its neighbour */
    udt_read_as_of(it, "doe", 100, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "other") == 0);

    tidesdb_iter_free(it);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    /* every version of one id shares its prefix, so retiring the id is one delete however many
     * versions it accumulated */
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_delete_prefix(txn, cf, (const uint8_t *)"doc|", 4), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_txn_commit(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &it), TDB_SUCCESS);
    udt_read_as_of(it, "doc", 999, got, sizeof(got));
    ASSERT_TRUE(got[0] == '\0');
    udt_read_as_of(it, "doe", 100, got, sizeof(got));
    ASSERT_TRUE(strcmp(got, "other") == 0); /* the neighbour is untouched */
    tidesdb_iter_free(it);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);

    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ITERAPI_DB_DIR);
}

void test_iter_skips_keys_a_range_tombstone_covers(void)
{
    (void)remove_directory(ITERAPI_DB_DIR);
    char db_path[] = ITERAPI_DB_DIR;
    tidesdb_t *db = iterapi_open(db_path);

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, ITERAPI_CF, &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, ITERAPI_CF);
    ASSERT_TRUE(cf != NULL);

    iterapi_put(db, cf, "a", "va");
    iterapi_put(db, cf, "user:1", "v1");
    iterapi_put(db, cf, "user:2", "v2");
    iterapi_put(db, cf, "z", "vz");

    /* delete the prefix at a sequence above every key written so far and at or below the snapshot a
     * scan will draw, so the tombstone is both newer than the data and visible to the scan */
    const uint64_t tomb_seq = tidesdb_mvcc_current_seq(db->clock);
    ASSERT_TRUE(tomb_seq > 0);
    ASSERT_EQ(cf_range_tombstone_add((cf_t *)cf, (const uint8_t *)"user:", 5,
                                     (const uint8_t *)"user;", 5, tomb_seq),
              TDB_SUCCESS);

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &it), TDB_SUCCESS);

    char k[32];

    /* forward, the covered pair is stepped straight over */
    ASSERT_EQ(tidesdb_iter_seek_to_first(it), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_valid(it), 1);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "a") == 0);
    ASSERT_EQ(tidesdb_iter_next(it), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_valid(it), 1);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "z") == 0);
    /* stepping past the last entry reports exhaustion, the same as it would with no tombstone */
    ASSERT_EQ(tidesdb_iter_next(it), TDB_ERR_NOT_FOUND);
    ASSERT_EQ(tidesdb_iter_valid(it), 0);

    /* backward too, since a scan reads either way */
    ASSERT_EQ(tidesdb_iter_seek_to_last(it), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_valid(it), 1);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "z") == 0);
    ASSERT_EQ(tidesdb_iter_prev(it), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_valid(it), 1);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "a") == 0);

    /* a seek landing inside the covered run moves past it rather than sitting on a deleted key */
    ASSERT_EQ(tidesdb_iter_seek(it, (const uint8_t *)"user:", 5), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_valid(it), 1);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "z") == 0);

    tidesdb_iter_free(it);
    ASSERT_EQ(tidesdb_txn_rollback(txn), TDB_SUCCESS);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ITERAPI_DB_DIR);
}

void test_iter_seek_for_prev_lands_at_or_below_target(void)
{
    (void)remove_directory(ITERAPI_DB_DIR);
    char db_path[] = ITERAPI_DB_DIR;
    tidesdb_t *db = iterapi_open(db_path);

    tidesdb_column_family_config_t cc = tidesdb_default_column_family_config();
    ASSERT_EQ(tidesdb_create_column_family(db, ITERAPI_CF, &cc), TDB_SUCCESS);
    tidesdb_column_family_t *cf = tidesdb_get_column_family(db, ITERAPI_CF);
    ASSERT_TRUE(cf != NULL);

    iterapi_put(db, cf, "a", "va");
    iterapi_put(db, cf, "c", "vc");
    iterapi_put(db, cf, "e", "ve");

    tidesdb_txn_t *txn = NULL;
    ASSERT_EQ(tidesdb_txn_begin(db, &txn), TDB_SUCCESS);
    tidesdb_iter_t *it = NULL;
    ASSERT_EQ(tidesdb_iter_new(txn, cf, &it), TDB_SUCCESS);

    char k[32], v[32];

    /* an exact hit stays on the key itself */
    ASSERT_EQ(tidesdb_iter_seek_for_prev(it, (const uint8_t *)"c", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_valid(it), 1);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "c") == 0);
    iterapi_value_at(it, v, sizeof(v));
    ASSERT_TRUE(strcmp(v, "vc") == 0);

    /* a miss falls back to the key below the target rather than up to the one above it, which is
     * exactly where it differs from the forward seek */
    ASSERT_EQ(tidesdb_iter_seek_for_prev(it, (const uint8_t *)"d", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_valid(it), 1);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "c") == 0);
    iterapi_value_at(it, v, sizeof(v));
    ASSERT_TRUE(strcmp(v, "vc") == 0);

    ASSERT_EQ(tidesdb_iter_seek(it, (const uint8_t *)"d", 1), TDB_SUCCESS);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "e") == 0);

    /* past the last key the reverse seek still has somewhere to land */
    ASSERT_EQ(tidesdb_iter_seek_for_prev(it, (const uint8_t *)"z", 1), TDB_SUCCESS);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "e") == 0);

    /* below every key there is nothing to land on */
    ASSERT_TRUE(tidesdb_iter_seek_for_prev(it, (const uint8_t *)"0", 1) != TDB_SUCCESS ||
                tidesdb_iter_valid(it) == 0);

    /* stepping back from a reverse seek keeps walking down the stream */
    ASSERT_EQ(tidesdb_iter_seek_for_prev(it, (const uint8_t *)"e", 1), TDB_SUCCESS);
    ASSERT_EQ(tidesdb_iter_prev(it), TDB_SUCCESS);
    iterapi_key_at(it, k, sizeof(k));
    ASSERT_TRUE(strcmp(k, "c") == 0);

    ASSERT_EQ(tidesdb_iter_value(it, NULL, NULL), TDB_ERR_INVALID_ARGS);

    tidesdb_iter_free(it);
    (void)tidesdb_txn_rollback(txn);
    tidesdb_txn_free(txn);
    ASSERT_EQ(tidesdb_close(db), TDB_SUCCESS);
    (void)remove_directory(ITERAPI_DB_DIR);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_iter_user_timestamp_in_the_key_reads_as_of_a_moment, tests_passed);
    RUN_TEST(test_iter_skips_keys_a_range_tombstone_covers, tests_passed);
    RUN_TEST(test_iter_seek_for_prev_lands_at_or_below_target, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
