/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "../src/base/errors.h"
#include "../src/base/waitstat.h" /* tdb_monotonic_us, to bound the publish */
#include "../src/column_family/cf_registry.h"
#include "../src/platform/platform_fs_sys.h" /* tdb_get_cpu_count, to size the reader load */
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

/* readers per core. the stall this guards against needs readers arriving faster than they can be
 * scheduled, so the load has to outnumber the cores rather than merely be concurrent -- at or below
 * one per core a gap appears on its own and nothing is proven */
#define CR_READERS_PER_CPU 6
#define CR_MAX_READERS     48

/* a membership change has to come back in less than this. the failure being guarded against is
 * unbounded -- minutes, or never -- so the bound only has to be finite, and it is set well above
 * the microseconds a publish actually takes so that a slow or oversubscribed runner cannot fail it.
 * this covers the whole window including the writer thread's first schedule, which on a machine
 * whose cores are all busy spinning is the one part not under the test's control */
#define CR_PUBLISH_BUDGET_US 5000000ull

/* enough publishes to catch one that is only occasionally starved, few enough that a build which
 * fails them all still finishes in seconds */
#define CR_PUBLISH_ROUNDS 4

typedef struct
{
    cf_registry_t *reg;
    cr_env_t *env;
    _Atomic(int) stop;
    _Atomic(long) lookups;
    _Atomic(int) published;
    _Atomic(unsigned long long) worst_us;
    /* a publish that never returns and one that returns an error both leave published short, and
     * they are opposite faults -- so the reason is recorded rather than inferred from the count */
    _Atomic(int) last_rc;
    _Atomic(int) entered;
    /* the handles to publish, built while nothing else is running */
    cf_t *pending[CR_PUBLISH_ROUNDS];
} cr_load_t;

/* the read the engine actually does on this structure: a point lookup by id, which holds the view
 * guard across its scan. every commit and every background sweep goes through one */
static void *cr_reader(void *arg)
{
    cr_load_t *load = (cr_load_t *)arg;
    while (!atomic_load_explicit(&load->stop, memory_order_acquire))
    {
        (void)cf_registry_get_by_id(load->reg, 0);
        atomic_fetch_add_explicit(&load->lookups, 1, memory_order_relaxed);
    }
    return NULL;
}

/* the writer, on its own thread so the wait it is subject to can be given up on. a publish that
 * never returns cannot be bounded by timing it -- the caller is inside it -- so it is watched from
 * outside instead */
static void *cr_publisher(void *arg)
{
    cr_load_t *load = (cr_load_t *)arg;
    for (int i = 0; i < CR_PUBLISH_ROUNDS; i++)
    {
        /* every handle was built before the readers started. building one touches the filesystem,
         * and doing that here put file creation inside the budget rather than the publish -- on a
         * loaded runner the thread spent the whole window in it and never reached an add at all,
         * which reads exactly like the stall this test is for */
        cf_t *cf = load->pending[i];

        const uint64_t started = tdb_monotonic_us();
        atomic_fetch_add_explicit(&load->entered, 1, memory_order_release);
        const int rc = cf_registry_add(load->reg, cf);
        atomic_store_explicit(&load->last_rc, rc, memory_order_release);
        if (rc != TDB_SUCCESS) return NULL;
        const unsigned long long took = tdb_monotonic_us() - started;

        unsigned long long seen = atomic_load_explicit(&load->worst_us, memory_order_relaxed);
        while (took > seen &&
               !atomic_compare_exchange_weak_explicit(&load->worst_us, &seen, took,
                                                      memory_order_relaxed, memory_order_relaxed))
            ;
        atomic_fetch_add_explicit(&load->published, 1, memory_order_release);
    }
    return NULL;
}

/* a membership change completes while readers never stop arriving.
 *
 * this is the shape that has stalled a column family create for minutes: the writer waits for a
 * moment with no reader in flight, and readers outnumbering the cores mean that moment never comes.
 * it has been reachable through a reader-preferring lock, a writer-preferring one, a condition
 * variable and a reader epoch -- the primitive changed each time and the stall did not, because the
 * fault is waiting on readers at all rather than which primitive is waited on.
 *
 * so what is asserted is not a duration but a bound: a writer must come back whatever the readers
 * are doing, and it is watched from another thread because a writer that never comes back cannot
 * report on itself */
void test_cf_registry_publish_under_sustained_readers(void)
{
    cr_env_t env;
    cr_env_open(&env);
    cf_registry_t *reg = cf_registry_create(1);

    /* one family for the readers to find, so a lookup does the work a real one does rather than
     * missing immediately */
    ASSERT_EQ(cf_registry_add(reg, cr_make_cf(&env, 0, "kv")), TDB_SUCCESS);

    int n_readers = tdb_get_cpu_count() * CR_READERS_PER_CPU;
    if (n_readers < CR_READERS_PER_CPU) n_readers = CR_READERS_PER_CPU;
    if (n_readers > CR_MAX_READERS) n_readers = CR_MAX_READERS;

    cr_load_t load;
    load.reg = reg;
    load.env = &env;
    atomic_init(&load.stop, 0);
    atomic_init(&load.lookups, 0);
    atomic_init(&load.published, 0);
    atomic_init(&load.worst_us, 0);
    atomic_init(&load.last_rc, TDB_SUCCESS);
    atomic_init(&load.entered, 0);

    /* built here, before a reader exists, so the writer thread's whole life is the publish */
    for (int i = 0; i < CR_PUBLISH_ROUNDS; i++)
    {
        char name[TDB_MAX_CF_NAME_LEN];
        snprintf(name, sizeof(name), "late%d", i);
        load.pending[i] = cr_make_cf(&env, (uint64_t)(i + 1), name);
    }

    pthread_t *readers = calloc((size_t)n_readers, sizeof(*readers));
    ASSERT_TRUE(readers != NULL);
    for (int i = 0; i < n_readers; i++)
        ASSERT_EQ(pthread_create(&readers[i], NULL, cr_reader, &load), 0);

    /* let the load reach a steady state, so the writer arrives into readers already in flight
     * rather than racing them to start */
    usleep(200000);

    pthread_t writer;
    ASSERT_EQ(pthread_create(&writer, NULL, cr_publisher, &load), 0);

    /* watched rather than joined: a writer stuck in the fault never returns, and joining it would
     * hang the suite instead of failing it */
    const uint64_t deadline = tdb_monotonic_us() + CR_PUBLISH_BUDGET_US;
    while (atomic_load_explicit(&load.published, memory_order_acquire) < CR_PUBLISH_ROUNDS &&
           tdb_monotonic_us() < deadline)
        usleep(1000);

    const int done = atomic_load_explicit(&load.published, memory_order_acquire);
    atomic_store_explicit(&load.stop, 1, memory_order_release);

    printf("  %d readers, %ld lookups, %d entered, %d/%d published, last rc %d, slowest %llu us\n",
           n_readers, atomic_load(&load.lookups), atomic_load(&load.entered), done,
           CR_PUBLISH_ROUNDS, atomic_load(&load.last_rc),
           (unsigned long long)atomic_load(&load.worst_us));
    /* flushed before the assertion, which aborts and would otherwise take the line with it -- the
     * numbers are how a failure says whether the writer was slow or never came back at all */
    fflush(stdout);

    /* an add that came back with an error is a different fault from one that never came back, and
     * only the second is what this test exists for */
    ASSERT_EQ(atomic_load(&load.last_rc), TDB_SUCCESS);

    /* asserted before the joins, since a writer still inside the fault is exactly the case this
     * catches and there is nothing to join it to */
    ASSERT_EQ(done, CR_PUBLISH_ROUNDS);

    pthread_join(writer, NULL);
    for (int i = 0; i < n_readers; i++) pthread_join(readers[i], NULL);
    free(readers);

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
    RUN_TEST(test_cf_registry_publish_under_sustained_readers, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
