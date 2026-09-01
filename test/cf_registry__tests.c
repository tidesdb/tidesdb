/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/column_family/cf_registry.h"
#include "test_utils.h"

/* the cf registry is the engine's set of live column families, keyed by name and id, owning the
 * handles it holds. these tests drive it with real cfs over a shared vlog/cache/fd manager: add and
 * lookup, duplicate rejection, ownership on remove, id allocation, and locked iteration. */

static int tests_passed = 0;
static int tests_failed = 0;

#define CR_DB_DIR "." PATH_SEPARATOR "test_cf_registry_db"

typedef struct
{
    vlog_t *vlog;
    cache_t *cache;
    fd_manager_t fdm;
} cr_env_t;

static void cr_env_open(cr_env_t *env)
{
    (void)remove_directory(CR_DB_DIR);
    ASSERT_EQ(mkdir(CR_DB_DIR, 0755), 0);
    const vlog_config_t vc = {.sync_mode = BLOCK_MANAGER_SYNC_NONE, .segment_target_bytes = 0};
    ASSERT_EQ(vlog_open(CR_DB_DIR, &vc, &env->vlog), VLOG_OK);
    env->cache = cache_create(NULL);
    ASSERT_EQ(fd_manager_init(&env->fdm, 0), 0);
}

static void cr_env_close(cr_env_t *env)
{
    fd_manager_destroy(&env->fdm);
    cache_destroy(env->cache);
    vlog_close(env->vlog);
    (void)remove_directory(CR_DB_DIR);
}

/* build a real column family with the given id and name over the shared env */
static cf_t *cr_make_cf(cr_env_t *env, uint64_t cf_id, const char *name)
{
    tidesdb_column_family_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.name, sizeof(cfg.name), "%s", name);
    cfg.level_size_ratio = 10;
    cfg.min_levels = 3;
    cfg.btree_klog_block_size = 4096;
    cfg.enable_bloom_filter = 1;
    cfg.bloom_fpr = 0.01;
    cf_t *cf = NULL;
    ASSERT_EQ(
        cf_create(CR_DB_DIR, cf_id, &cfg, NULL, env->vlog, env->cache, &env->fdm, NULL, NULL, &cf),
        0);
    return cf;
}

/* add registers a cf, and lookups resolve it by both name and id while misses return NULL */
void test_cf_registry_add_and_get(void)
{
    cr_env_t env;
    cr_env_open(&env);
    cf_registry_t *reg = cf_registry_create(1);
    ASSERT_TRUE(reg != NULL);

    cf_t *a = cr_make_cf(&env, 1, "alpha");
    cf_t *b = cr_make_cf(&env, 2, "beta");
    ASSERT_EQ(cf_registry_add(reg, a), TDB_SUCCESS);
    ASSERT_EQ(cf_registry_add(reg, b), TDB_SUCCESS);

    ASSERT_TRUE(cf_registry_get_by_name(reg, "alpha") == a);
    ASSERT_TRUE(cf_registry_get_by_name(reg, "beta") == b);
    ASSERT_TRUE(cf_registry_get_by_name(reg, "missing") == NULL);
    ASSERT_TRUE(cf_registry_get_by_id(reg, 1) == a);
    ASSERT_TRUE(cf_registry_get_by_id(reg, 2) == b);
    ASSERT_TRUE(cf_registry_get_by_id(reg, 99) == NULL);

    cf_registry_destroy(reg); /* frees a and b */
    cr_env_close(&env);
}

/* a duplicate name or id is rejected and leaves ownership with the caller */
void test_cf_registry_rejects_duplicate(void)
{
    cr_env_t env;
    cr_env_open(&env);
    cf_registry_t *reg = cf_registry_create(1);

    cf_t *a = cr_make_cf(&env, 1, "alpha");
    ASSERT_EQ(cf_registry_add(reg, a), TDB_SUCCESS);

    cf_t *dup_name = cr_make_cf(&env, 5, "alpha");
    ASSERT_EQ(cf_registry_add(reg, dup_name), TDB_ERR_EXISTS);
    cf_free(dup_name); /* rejected add did not take ownership */

    cf_t *dup_id = cr_make_cf(&env, 1, "zeta");
    ASSERT_EQ(cf_registry_add(reg, dup_id), TDB_ERR_EXISTS);
    cf_free(dup_id);

    ASSERT_TRUE(cf_registry_get_by_name(reg, "zeta") == NULL); /* nothing leaked into the set */

    cf_registry_destroy(reg); /* frees a */
    cr_env_close(&env);
}

/* remove detaches a cf and hands ownership back, or frees it directly when out is NULL */
void test_cf_registry_remove(void)
{
    cr_env_t env;
    cr_env_open(&env);
    cf_registry_t *reg = cf_registry_create(1);

    cf_t *a = cr_make_cf(&env, 1, "alpha");
    cf_t *b = cr_make_cf(&env, 2, "beta");
    ASSERT_EQ(cf_registry_add(reg, a), TDB_SUCCESS);
    ASSERT_EQ(cf_registry_add(reg, b), TDB_SUCCESS);

    cf_t *out = NULL;
    ASSERT_EQ(cf_registry_remove(reg, "alpha", &out), TDB_SUCCESS);
    ASSERT_TRUE(out == a);
    ASSERT_TRUE(cf_registry_get_by_name(reg, "alpha") == NULL);
    cf_free(out); /* caller owns the detached cf */

    ASSERT_EQ(cf_registry_remove(reg, "missing", &out), TDB_ERR_NOT_FOUND);

    ASSERT_EQ(cf_registry_remove(reg, "beta", NULL), TDB_SUCCESS); /* frees b internally */
    ASSERT_TRUE(cf_registry_get_by_name(reg, "beta") == NULL);

    cf_registry_destroy(reg); /* empty */
    cr_env_close(&env);
}

/* the id allocator hands out a monotonic sequence from its seed */
void test_cf_registry_next_id(void)
{
    cf_registry_t *reg = cf_registry_create(100);
    ASSERT_EQ((int)cf_registry_next_cf_id(reg), 100);
    ASSERT_EQ((int)cf_registry_next_cf_id(reg), 101);
    ASSERT_EQ((int)cf_registry_next_cf_id(reg), 102);
    cf_registry_destroy(reg);
}

/* a borrowed view walks every registered family, and a family added after the borrow is not in it
 */
void test_cf_registry_iteration(void)
{
    cr_env_t env;
    cr_env_open(&env);
    cf_registry_t *reg = cf_registry_create(1);

    ASSERT_EQ(cf_registry_add(reg, cr_make_cf(&env, 1, "a")), TDB_SUCCESS);
    ASSERT_EQ(cf_registry_add(reg, cr_make_cf(&env, 2, "b")), TDB_SUCCESS);
    ASSERT_EQ(cf_registry_add(reg, cr_make_cf(&env, 3, "c")), TDB_SUCCESS);

    cf_t **live = NULL;
    int n = 0;
    cf_registry_view_t *view = cf_registry_view_enter(reg, &live, &n);
    ASSERT_EQ(n, 3);
    for (int i = 0; i < n; i++) ASSERT_TRUE(live[i] != NULL);

    /* the borrow is a snapshot, so a family published while it is held belongs to the next one */
    ASSERT_EQ(cf_registry_add(reg, cr_make_cf(&env, 4, "d")), TDB_SUCCESS);
    ASSERT_EQ(n, 3);
    cf_registry_view_leave(reg, view);

    view = cf_registry_view_enter(reg, &live, &n);
    ASSERT_EQ(n, 4);
    cf_registry_view_leave(reg, view);

    /* and with nothing to borrow from, the count is zero rather than an error */
    cf_t **none = NULL;
    int zero = -1;
    cf_registry_view_t *empty = cf_registry_view_enter(NULL, &none, &zero);
    ASSERT_TRUE(none == NULL);
    ASSERT_EQ(zero, 0);
    cf_registry_view_leave(NULL, empty);

    cf_registry_destroy(reg);
    cr_env_close(&env);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_cf_registry_add_and_get, tests_passed);
    RUN_TEST(test_cf_registry_rejects_duplicate, tests_passed);
    RUN_TEST(test_cf_registry_remove, tests_passed);
    RUN_TEST(test_cf_registry_next_id, tests_passed);
    RUN_TEST(test_cf_registry_iteration, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
