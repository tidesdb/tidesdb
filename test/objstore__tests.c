/**
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

#include "../src/objstore.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_OBJSTORE_DIR  "." PATH_SEPARATOR "test_objstore_root"
#define TEST_OBJSTORE_DIR2 "." PATH_SEPARATOR "test_objstore_dl"

static void create_test_file(const char *path, const char *content, size_t size)
{
    FILE *f = fopen(path, "wb");
    ASSERT_TRUE(f != NULL);
    fwrite(content, 1, size, f);
    fclose(f);
}

static void cleanup_dirs(void)
{
    remove_directory(TEST_OBJSTORE_DIR);
    remove_directory(TEST_OBJSTORE_DIR2);
}

void test_objstore_fs_create(void)
{
    cleanup_dirs();

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);
    ASSERT_EQ(store->backend, TDB_BACKEND_FS);
    ASSERT_TRUE(store->put != NULL);
    ASSERT_TRUE(store->get != NULL);
    ASSERT_TRUE(store->range_get != NULL);
    ASSERT_TRUE(store->delete_object != NULL);
    ASSERT_TRUE(store->exists != NULL);
    ASSERT_TRUE(store->list != NULL);
    ASSERT_TRUE(store->destroy != NULL);
    ASSERT_TRUE(store->ctx != NULL);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

void test_objstore_fs_create_null(void)
{
    ASSERT_TRUE(tidesdb_objstore_fs_create(NULL) == NULL);
}

void test_objstore_fs_put_get(void)
{
    cleanup_dirs();
    mkdir(TEST_OBJSTORE_DIR2, 0755);

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);

    /* create a local file to upload */
    const char *content = "hello objstore put/get test data";
    size_t content_len = strlen(content);
    char local_src[256];
    snprintf(local_src, sizeof(local_src), "%s" PATH_SEPARATOR "src_file.dat", TEST_OBJSTORE_DIR2);
    create_test_file(local_src, content, content_len);

    /* put */
    ASSERT_EQ(store->put(store->ctx, "test_key.dat", local_src), 0);

    /* get to a different local path */
    char local_dst[256];
    snprintf(local_dst, sizeof(local_dst), "%s" PATH_SEPARATOR "dst_file.dat", TEST_OBJSTORE_DIR2);
    ASSERT_EQ(store->get(store->ctx, "test_key.dat", local_dst), 0);

    /* verify content matches */
    FILE *f = fopen(local_dst, "rb");
    ASSERT_TRUE(f != NULL);
    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    ASSERT_EQ(n, content_len);
    ASSERT_EQ(memcmp(buf, content, content_len), 0);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

void test_objstore_fs_exists(void)
{
    cleanup_dirs();
    mkdir(TEST_OBJSTORE_DIR2, 0755);

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);

    /* should not exist yet */
    size_t size_out = 0;
    ASSERT_EQ(store->exists(store->ctx, "missing.dat", &size_out), 0);

    /* put a file */
    char local_src[256];
    snprintf(local_src, sizeof(local_src), "%s" PATH_SEPARATOR "exists_src.dat",
             TEST_OBJSTORE_DIR2);
    create_test_file(local_src, "existsdata", 10);
    ASSERT_EQ(store->put(store->ctx, "exists_key.dat", local_src), 0);

    /* should exist now */
    ASSERT_EQ(store->exists(store->ctx, "exists_key.dat", &size_out), 1);
    ASSERT_EQ(size_out, 10);

    /* exists with NULL size_out */
    ASSERT_EQ(store->exists(store->ctx, "exists_key.dat", NULL), 1);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

void test_objstore_fs_delete(void)
{
    cleanup_dirs();
    mkdir(TEST_OBJSTORE_DIR2, 0755);

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);

    char local_src[256];
    snprintf(local_src, sizeof(local_src), "%s" PATH_SEPARATOR "del_src.dat", TEST_OBJSTORE_DIR2);
    create_test_file(local_src, "deletedata", 10);
    ASSERT_EQ(store->put(store->ctx, "del_key.dat", local_src), 0);
    ASSERT_EQ(store->exists(store->ctx, "del_key.dat", NULL), 1);

    /* delete */
    ASSERT_EQ(store->delete_object(store->ctx, "del_key.dat"), 0);
    ASSERT_EQ(store->exists(store->ctx, "del_key.dat", NULL), 0);

    /* delete non-existent should not error */
    ASSERT_EQ(store->delete_object(store->ctx, "never_existed.dat"), 0);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

void test_objstore_fs_range_get(void)
{
    cleanup_dirs();
    mkdir(TEST_OBJSTORE_DIR2, 0755);

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);

    const char *content = "0123456789ABCDEF";
    char local_src[256];
    snprintf(local_src, sizeof(local_src), "%s" PATH_SEPARATOR "range_src.dat", TEST_OBJSTORE_DIR2);
    create_test_file(local_src, content, 16);
    ASSERT_EQ(store->put(store->ctx, "range_key.dat", local_src), 0);

    /* read bytes 4-7 */
    char buf[16] = {0};
    ssize_t nread = store->range_get(store->ctx, "range_key.dat", 4, buf, 4);
    ASSERT_EQ(nread, 4);
    ASSERT_EQ(memcmp(buf, "4567", 4), 0);

    /* read bytes 10-15 */
    memset(buf, 0, sizeof(buf));
    nread = store->range_get(store->ctx, "range_key.dat", 10, buf, 6);
    ASSERT_EQ(nread, 6);
    ASSERT_EQ(memcmp(buf, "ABCDEF", 6), 0);

    /* read from offset 0 */
    memset(buf, 0, sizeof(buf));
    nread = store->range_get(store->ctx, "range_key.dat", 0, buf, 4);
    ASSERT_EQ(nread, 4);
    ASSERT_EQ(memcmp(buf, "0123", 4), 0);

    /* range_get on non-existent key should fail */
    nread = store->range_get(store->ctx, "no_such_key.dat", 0, buf, 4);
    ASSERT_EQ(nread, -1);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

typedef struct
{
    char keys[32][256];
    size_t sizes[32];
    int count;
} list_ctx_t;

static void list_callback(const char *key, size_t size, void *cb_ctx)
{
    list_ctx_t *ctx = (list_ctx_t *)cb_ctx;
    if (ctx->count < 32)
    {
        snprintf(ctx->keys[ctx->count], sizeof(ctx->keys[ctx->count]), "%s", key);
        ctx->sizes[ctx->count] = size;
        ctx->count++;
    }
}

void test_objstore_fs_list(void)
{
    cleanup_dirs();
    mkdir(TEST_OBJSTORE_DIR2, 0755);

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);

    /* put files under a "cf/" prefix */
    char local_src[256];
    snprintf(local_src, sizeof(local_src), "%s" PATH_SEPARATOR "list_src.dat", TEST_OBJSTORE_DIR2);

    create_test_file(local_src, "aaa", 3);
    ASSERT_EQ(store->put(store->ctx, "cf/L1_001.klog", local_src), 0);

    create_test_file(local_src, "bbbbbb", 6);
    ASSERT_EQ(store->put(store->ctx, "cf/L1_002.klog", local_src), 0);

    create_test_file(local_src, "cc", 2);
    ASSERT_EQ(store->put(store->ctx, "cf/L2_001.klog", local_src), 0);

    /* put a file outside the prefix */
    create_test_file(local_src, "xx", 2);
    ASSERT_EQ(store->put(store->ctx, "other/file.dat", local_src), 0);

    /* list under "cf/" prefix */
    list_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    int listed = store->list(store->ctx, "cf/", list_callback, &lctx);
    ASSERT_EQ(listed, 3);
    ASSERT_EQ(lctx.count, 3);

    /* list with empty prefix (should include all files) */
    memset(&lctx, 0, sizeof(lctx));
    listed = store->list(store->ctx, "", list_callback, &lctx);
    ASSERT_EQ(listed, 4);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

void test_objstore_fs_put_get_nonexistent(void)
{
    cleanup_dirs();

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);

    /* put from non-existent local file should fail */
    ASSERT_EQ(store->put(store->ctx, "key.dat", "/no/such/file.dat"), -1);

    /* get of non-existent key should fail */
    ASSERT_EQ(store->get(store->ctx, "no_key.dat", "/tmp/tidesdb_test_out.dat"), -1);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

void test_objstore_fs_overwrite(void)
{
    cleanup_dirs();
    mkdir(TEST_OBJSTORE_DIR2, 0755);

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);

    char local_src[256];
    snprintf(local_src, sizeof(local_src), "%s" PATH_SEPARATOR "ow_src.dat", TEST_OBJSTORE_DIR2);

    /* put initial data */
    create_test_file(local_src, "original", 8);
    ASSERT_EQ(store->put(store->ctx, "ow_key.dat", local_src), 0);

    size_t size_out = 0;
    ASSERT_EQ(store->exists(store->ctx, "ow_key.dat", &size_out), 1);
    ASSERT_EQ(size_out, 8);

    /* overwrite with different data */
    create_test_file(local_src, "updated_content", 15);
    ASSERT_EQ(store->put(store->ctx, "ow_key.dat", local_src), 0);

    ASSERT_EQ(store->exists(store->ctx, "ow_key.dat", &size_out), 1);
    ASSERT_EQ(size_out, 15);

    /* verify content is the updated version */
    char local_dst[256];
    snprintf(local_dst, sizeof(local_dst), "%s" PATH_SEPARATOR "ow_dst.dat", TEST_OBJSTORE_DIR2);
    ASSERT_EQ(store->get(store->ctx, "ow_key.dat", local_dst), 0);

    FILE *f = fopen(local_dst, "rb");
    ASSERT_TRUE(f != NULL);
    char buf[32];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    ASSERT_EQ(n, 15);
    ASSERT_EQ(memcmp(buf, "updated_content", 15), 0);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

void test_objstore_fs_nested_keys(void)
{
    cleanup_dirs();
    mkdir(TEST_OBJSTORE_DIR2, 0755);

    tidesdb_objstore_t *store = tidesdb_objstore_fs_create(TEST_OBJSTORE_DIR);
    ASSERT_TRUE(store != NULL);

    char local_src[256];
    snprintf(local_src, sizeof(local_src), "%s" PATH_SEPARATOR "nested_src.dat",
             TEST_OBJSTORE_DIR2);
    create_test_file(local_src, "nested_data", 11);

    /* put with deeply nested key */
    ASSERT_EQ(store->put(store->ctx, "a/b/c/d/deep.dat", local_src), 0);
    ASSERT_EQ(store->exists(store->ctx, "a/b/c/d/deep.dat", NULL), 1);

    /* get it back */
    char local_dst[256];
    snprintf(local_dst, sizeof(local_dst), "%s" PATH_SEPARATOR "nested_dst.dat",
             TEST_OBJSTORE_DIR2);
    ASSERT_EQ(store->get(store->ctx, "a/b/c/d/deep.dat", local_dst), 0);

    FILE *f = fopen(local_dst, "rb");
    ASSERT_TRUE(f != NULL);
    char buf[32];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    ASSERT_EQ(n, 11);
    ASSERT_EQ(memcmp(buf, "nested_data", 11), 0);

    store->destroy(store->ctx);
    free(store);
    cleanup_dirs();
}

void test_objstore_backend_name(void)
{
    ASSERT_EQ(strcmp(tidesdb_objstore_backend_name(TDB_BACKEND_FS), "fs"), 0);
    ASSERT_EQ(strcmp(tidesdb_objstore_backend_name(TDB_BACKEND_S3), "s3"), 0);
    ASSERT_EQ(strcmp(tidesdb_objstore_backend_name(TDB_BACKEND_UNKNOWN), "unknown"), 0);
    ASSERT_EQ(strcmp(tidesdb_objstore_backend_name(99), "unknown"), 0);
}

void test_objstore_default_config(void)
{
    tidesdb_objstore_config_t cfg = tidesdb_objstore_default_config();
    ASSERT_TRUE(cfg.local_cache_path == NULL);
    ASSERT_EQ(cfg.local_cache_max_bytes, 0);
    ASSERT_EQ(cfg.cache_on_read, 1);
    ASSERT_EQ(cfg.cache_on_write, 1);
    ASSERT_EQ(cfg.max_concurrent_uploads, 4);
    ASSERT_EQ(cfg.max_concurrent_downloads, 8);
    ASSERT_TRUE(cfg.multipart_threshold > 0);
    ASSERT_TRUE(cfg.multipart_part_size > 0);
    ASSERT_EQ(cfg.sync_manifest_to_object, 1);
    ASSERT_EQ(cfg.replicate_wal, 1);
    ASSERT_EQ(cfg.wal_upload_sync, 0);
    ASSERT_TRUE(cfg.wal_sync_threshold_bytes > 0);
    ASSERT_EQ(cfg.wal_sync_on_commit, 0);
    ASSERT_EQ(cfg.replica_mode, 0);
    ASSERT_TRUE(cfg.replica_sync_interval_us > 0);
    ASSERT_EQ(cfg.replica_replay_wal, 1);
}

#ifdef TIDESDB_WITH_S3
void test_objstore_s3_minio(void)
{
    const char *endpoint = getenv("TIDESDB_S3_ENDPOINT");
    const char *bucket = getenv("TIDESDB_S3_BUCKET");
    const char *access_key = getenv("TIDESDB_S3_ACCESS_KEY");
    const char *secret_key = getenv("TIDESDB_S3_SECRET_KEY");

    if (!endpoint || !bucket || !access_key || !secret_key)
    {
        printf("  SKIPPED (S3 env vars not set)\n");
        return;
    }

    tidesdb_objstore_t *store = tidesdb_objstore_s3_create(endpoint, bucket, "test_prefix/",
                                                           access_key, secret_key, NULL, 0, 1);
    ASSERT_TRUE(store != NULL);
    ASSERT_EQ(store->backend, TDB_BACKEND_S3);

    /* create local file for upload */
    mkdir(TEST_OBJSTORE_DIR2, 0755);
    char local_src[256];
    snprintf(local_src, sizeof(local_src), "%s" PATH_SEPARATOR "s3_src.dat", TEST_OBJSTORE_DIR2);
    const char *content = "s3 minio test data 12345";
    size_t content_len = strlen(content);
    create_test_file(local_src, content, content_len);

    /* put */
    ASSERT_EQ(store->put(store->ctx, "s3_test.dat", local_src), 0);

    /* exists */
    size_t size_out = 0;
    ASSERT_EQ(store->exists(store->ctx, "s3_test.dat", &size_out), 1);
    ASSERT_EQ(size_out, content_len);

    /* get */
    char local_dst[256];
    snprintf(local_dst, sizeof(local_dst), "%s" PATH_SEPARATOR "s3_dst.dat", TEST_OBJSTORE_DIR2);
    ASSERT_EQ(store->get(store->ctx, "s3_test.dat", local_dst), 0);

    FILE *f = fopen(local_dst, "rb");
    ASSERT_TRUE(f != NULL);
    char buf[256];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    ASSERT_EQ(n, content_len);
    ASSERT_EQ(memcmp(buf, content, content_len), 0);

    /* range_get */
    char rbuf[8] = {0};
    ssize_t nread = store->range_get(store->ctx, "s3_test.dat", 3, rbuf, 5);
    ASSERT_EQ(nread, 5);
    ASSERT_EQ(memcmp(rbuf, "minio", 5), 0);

    /* list (prefix is "" because the connector already prepends "test_prefix/") */
    list_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    int listed = store->list(store->ctx, "", list_callback, &lctx);
    ASSERT_TRUE(listed >= 1);

    /* delete */
    ASSERT_EQ(store->delete_object(store->ctx, "s3_test.dat"), 0);
    ASSERT_EQ(store->exists(store->ctx, "s3_test.dat", NULL), 0);

    store->destroy(store->ctx);
    free(store);
    remove_directory(TEST_OBJSTORE_DIR2);
}
#endif

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_objstore_backend_name, tests_passed);
    RUN_TEST(test_objstore_default_config, tests_passed);
    RUN_TEST(test_objstore_fs_create, tests_passed);
    RUN_TEST(test_objstore_fs_create_null, tests_passed);
    RUN_TEST(test_objstore_fs_put_get, tests_passed);
    RUN_TEST(test_objstore_fs_exists, tests_passed);
    RUN_TEST(test_objstore_fs_delete, tests_passed);
    RUN_TEST(test_objstore_fs_range_get, tests_passed);
    RUN_TEST(test_objstore_fs_list, tests_passed);
    RUN_TEST(test_objstore_fs_put_get_nonexistent, tests_passed);
    RUN_TEST(test_objstore_fs_overwrite, tests_passed);
    RUN_TEST(test_objstore_fs_nested_keys, tests_passed);
#ifdef TIDESDB_WITH_S3
    RUN_TEST(test_objstore_s3_minio, tests_passed);
#endif

    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
