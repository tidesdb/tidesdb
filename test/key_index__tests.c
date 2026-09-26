/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdio.h>
#include <string.h>

#include "../src/txn/key_index.h"
#include "db.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

/* keys enough to widen the index several times over */
#define KI_KEYS 2000

/**
 * ki_owner
 * an owner array the index points into, one keyed entry per position unless marked otherwise
 * @param cf the family of each entry
 * @param key the key of each entry
 * @param keyed whether the entry is one the index keys, 0 standing in for an interval delete
 * @param count how many entries there are
 */
typedef struct
{
    uint32_t cf[KI_KEYS];
    char key[KI_KEYS][12];
    int keyed[KI_KEYS];
    int count;
} ki_owner;

static int ki_entry(const void *ctx, int position, uint32_t *cf_index, const uint8_t **key,
                    size_t *key_size)
{
    const ki_owner *o = (const ki_owner *)ctx;
    if (!o->keyed[position]) return 0;
    *cf_index = o->cf[position];
    *key = (const uint8_t *)o->key[position];
    *key_size = strlen(o->key[position]);
    return 1;
}

/* append one entry to the owner and index it, returning the put's result */
static int ki_add(ki_owner *o, tdb_key_index_t *ix, uint32_t cf, const char *key, int keyed)
{
    const int position = o->count;
    o->cf[position] = cf;
    snprintf(o->key[position], sizeof(o->key[position]), "%s", key);
    o->keyed[position] = keyed;
    o->count++;
    return tdb_key_index_put(ix, o, ki_entry, position, o->count);
}

static int ki_find(const tdb_key_index_t *ix, const ki_owner *o, uint32_t cf, const char *key)
{
    return tdb_key_index_find(ix, o, ki_entry, cf, (const uint8_t *)key, strlen(key));
}

/* a key maps to the newest position that wrote it, the same bytes under another family are another
 * key, an entry the owner does not key is skipped, and an unknown key misses */
void test_key_index_newest_position_wins(void)
{
    static ki_owner o;
    memset(&o, 0, sizeof(o));
    tdb_key_index_t ix;
    tdb_key_index_init(&ix);

    ASSERT_EQ(ki_add(&o, &ix, 0, "k", 1), TDB_SUCCESS);
    ASSERT_EQ(ki_add(&o, &ix, 1, "k", 1), TDB_SUCCESS);
    ASSERT_EQ(ki_add(&o, &ix, 0, "range", 0), TDB_SUCCESS);
    ASSERT_EQ(ki_add(&o, &ix, 0, "k", 1), TDB_SUCCESS);
    ASSERT_EQ(ki_find(&ix, &o, 0, "k"), 3);
    ASSERT_EQ(ki_find(&ix, &o, 1, "k"), 1);
    ASSERT_EQ(ki_find(&ix, &o, 0, "range"), -1);
    ASSERT_EQ(ki_find(&ix, &o, 0, "absent"), -1);
    ASSERT_EQ(ki_find(&ix, &o, 2, "k"), -1);
    ASSERT_EQ(ix.occupied, 2);

    tdb_key_index_free(&ix);
}

/* the index widens as positions are added and every key still maps to its newest position, a
 * rebuild over a shorter count forgets the tail, and a clear forgets everything */
void test_key_index_widens_rebuilds_and_clears(void)
{
    static ki_owner o;
    memset(&o, 0, sizeof(o));
    tdb_key_index_t ix;
    tdb_key_index_init(&ix);
    char k[12];
    for (int i = 0; i < KI_KEYS / 2; i++)
    {
        snprintf(k, sizeof(k), "k%05d", i);
        ASSERT_EQ(ki_add(&o, &ix, (uint32_t)(i % 3), k, 1), TDB_SUCCESS);
    }
    for (int i = 0; i < KI_KEYS / 2; i++)
    {
        snprintf(k, sizeof(k), "k%05d", i);
        ASSERT_EQ(ki_add(&o, &ix, (uint32_t)(i % 3), k, 1), TDB_SUCCESS); /* written again */
    }
    ASSERT_TRUE(ix.mask + 1 >= (uint32_t)(KI_KEYS / 2) * 2);
    ASSERT_EQ(ix.occupied, KI_KEYS / 2);
    for (int i = 0; i < KI_KEYS / 2; i++)
    {
        snprintf(k, sizeof(k), "k%05d", i);
        ASSERT_EQ(ki_find(&ix, &o, (uint32_t)(i % 3), k), KI_KEYS / 2 + i);
    }

    /* the owner discards its second half and rebuilds; the first writes answer again */
    o.count = KI_KEYS / 2;
    ASSERT_EQ(tdb_key_index_rebuild(&ix, &o, ki_entry, o.count), TDB_SUCCESS);
    for (int i = 0; i < KI_KEYS / 2; i++)
    {
        snprintf(k, sizeof(k), "k%05d", i);
        ASSERT_EQ(ki_find(&ix, &o, (uint32_t)(i % 3), k), i);
    }

    ASSERT_TRUE(tdb_key_index_bytes(&ix) > 0);
    tdb_key_index_clear(&ix);
    ASSERT_EQ((int)tdb_key_index_bytes(&ix), 0);
    ASSERT_EQ(ki_find(&ix, &o, 0, "k00000"), -1);
    ASSERT_EQ(ki_add(&o, &ix, 0, "k00000", 1), TDB_SUCCESS); /* the next put rebuilds */
    ASSERT_EQ(ki_find(&ix, &o, 0, "k00000"), o.count - 1);
    tdb_key_index_free(&ix);
}

void test_key_index_null_safe(void)
{
    static ki_owner o;
    memset(&o, 0, sizeof(o));
    tdb_key_index_t ix;
    tdb_key_index_init(&ix);
    tdb_key_index_init(NULL);
    tdb_key_index_free(NULL);
    tdb_key_index_clear(NULL);
    ASSERT_EQ((int)tdb_key_index_bytes(NULL), 0);
    ASSERT_EQ(tdb_key_index_find(NULL, &o, ki_entry, 0, (const uint8_t *)"k", 1), -1);
    ASSERT_EQ(tdb_key_index_find(&ix, &o, ki_entry, 0, (const uint8_t *)"k", 1), -1); /* empty */
    ASSERT_EQ(tdb_key_index_put(NULL, &o, ki_entry, 0, 1), TDB_ERR_INVALID_ARGS);
    ASSERT_EQ(tdb_key_index_put(&ix, &o, ki_entry, 1, 1), TDB_ERR_INVALID_ARGS); /* past count */
    ASSERT_EQ(tdb_key_index_rebuild(&ix, NULL, ki_entry, 0), TDB_ERR_INVALID_ARGS);
    tdb_key_index_free(&ix);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    RUN_TEST(test_key_index_newest_position_wins, tests_passed);
    RUN_TEST(test_key_index_widens_rebuilds_and_clears, tests_passed);
    RUN_TEST(test_key_index_null_safe, tests_passed);
    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
