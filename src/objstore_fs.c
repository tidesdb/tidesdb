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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "objstore.h"

#ifndef _WIN32
#include <dirent.h>
#include <unistd.h>
#else
#include <direct.h>
#include <io.h>
#endif

#define TDB_FS_MAX_PATH 4096
#define TDB_FS_COPY_BUF 65536
#define TDB_FS_DIR_MODE 0755

/* default object store config values */
#define TDB_OBJSTORE_DEFAULT_CACHE_ON_READ         1
#define TDB_OBJSTORE_DEFAULT_CACHE_ON_WRITE        1
#define TDB_OBJSTORE_DEFAULT_MAX_UPLOADS           4
#define TDB_OBJSTORE_DEFAULT_MAX_DOWNLOADS         8
#define TDB_OBJSTORE_DEFAULT_MULTIPART_THRESHOLD   (64 * 1024 * 1024)
#define TDB_OBJSTORE_DEFAULT_MULTIPART_PART_SIZE   (8 * 1024 * 1024)
#define TDB_OBJSTORE_DEFAULT_SYNC_MANIFEST         1
#define TDB_OBJSTORE_DEFAULT_REPLICATE_WAL         1
#define TDB_OBJSTORE_DEFAULT_WAL_UPLOAD_SYNC       0
#define TDB_OBJSTORE_DEFAULT_WAL_SYNC_THRESHOLD    (1024 * 1024) /* 1MB */
#define TDB_OBJSTORE_DEFAULT_WAL_SYNC_ON_COMMIT    0
#define TDB_OBJSTORE_DEFAULT_REPLICA_MODE          0
#define TDB_OBJSTORE_DEFAULT_REPLICA_SYNC_INTERVAL 5000000 /* 5 seconds */
#define TDB_OBJSTORE_DEFAULT_REPLICA_REPLAY_WAL    1

/**
 * fs_ctx_t
 * internal context for the filesystem connector
 * @param root_dir root directory where objects are stored as files
 */
typedef struct
{
    char root_dir[TDB_FS_MAX_PATH];
} fs_ctx_t;

/**
 * fs_mkdir_p
 * create all intermediate directories for a file path
 * @param file_path path to a file whose parent directories should be created
 */
static void fs_mkdir_p(const char *file_path)
{
    char tmp[TDB_FS_MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", file_path);

    /* we find last separator to get directory portion */
    char *last_sep = strrchr(tmp, '/');
#ifdef _WIN32
    char *last_bsep = strrchr(tmp, '\\');
    if (last_bsep && (!last_sep || last_bsep > last_sep)) last_sep = last_bsep;
#endif
    if (!last_sep) return;
    *last_sep = '\0';

    /* we create each directory component */
    for (char *p = tmp + 1; *p; p++)
    {
        if (*p == '/'
#ifdef _WIN32
            || *p == '\\'
#endif
        )
        {
            *p = '\0';
#ifdef _WIN32
            _mkdir(tmp);
#else
            mkdir(tmp, TDB_FS_DIR_MODE);
#endif
            *p = '/';
        }
    }
#ifdef _WIN32
    _mkdir(tmp);
#else
    mkdir(tmp, TDB_FS_DIR_MODE);
#endif
}

/**
 * fs_full_path
 * build full path by joining root_dir and key
 * @param ctx filesystem connector context
 * @param key object key (relative path)
 * @param out output buffer for the full path
 * @param out_size size of the output buffer
 */
static void fs_full_path(const fs_ctx_t *ctx, const char *key, char *out, size_t out_size)
{
    snprintf(out, out_size, "%s/%s", ctx->root_dir, key);
}

/**
 * fs_copy_file
 * copy file contents from src_path to dst_path
 * @param src_path source file path
 * @param dst_path destination file path (parent dirs created if needed)
 * @return 0 on success, -1 on error
 */
static int fs_copy_file(const char *src_path, const char *dst_path)
{
    FILE *src = fopen(src_path, "rb");
    if (!src) return -1;

    fs_mkdir_p(dst_path);

    FILE *dst = fopen(dst_path, "wb");
    if (!dst)
    {
        fclose(src);
        return -1;
    }

    char buf[TDB_FS_COPY_BUF];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
    {
        if (fwrite(buf, 1, n, dst) != n)
        {
            rc = -1;
            break;
        }
    }
    if (ferror(src)) rc = -1;

    fclose(dst);
    fclose(src);

    /** we remove partial destination file on failure so stale corrupt files
     *  do not prevent re-download on subsequent attempts */
    if (rc != 0) unlink(dst_path);

    return rc;
}

/**
 * fs_put
 * upload a local file as an object by copying it to the root directory
 * @param ctx opaque connector context
 * @param key object key (relative path)
 * @param local_path local file to upload
 * @return 0 on success, -1 on error
 */
static int fs_put(void *ctx, const char *key, const char *local_path)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char full[TDB_FS_MAX_PATH * 2];
    fs_full_path(fs, key, full, sizeof(full));
    return fs_copy_file(local_path, full);
}

/**
 * fs_get
 * download an object to a local file by copying from the root directory
 * @param ctx opaque connector context
 * @param key object key (relative path)
 * @param local_path local path to write the downloaded file
 * @return 0 on success, -1 on error (including not found)
 */
static int fs_get(void *ctx, const char *key, const char *local_path)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char full[TDB_FS_MAX_PATH * 2];
    fs_full_path(fs, key, full, sizeof(full));
    return fs_copy_file(full, local_path);
}

/**
 * fs_range_get
 * read a byte range from an object file into a buffer
 * @param ctx opaque connector context
 * @param key object key (relative path)
 * @param offset byte offset to start reading
 * @param buf output buffer (caller allocated)
 * @param size number of bytes to read
 * @return bytes read on success, -1 on error
 */
static ssize_t fs_range_get(void *ctx, const char *key, uint64_t offset, void *buf, size_t size)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char full[TDB_FS_MAX_PATH * 2];
    fs_full_path(fs, key, full, sizeof(full));

    int fd = open(full, O_RDONLY, 0);
    if (fd < 0) return -1;

    ssize_t nread = pread(fd, buf, size, (off_t)offset);
    close(fd);
    return nread;
}

/**
 * fs_delete_object
 * delete an object file. not-found is not an error.
 * @param ctx opaque connector context
 * @param key object key (relative path)
 * @return 0 on success, -1 on error
 */
static int fs_delete_object(void *ctx, const char *key)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char full[TDB_FS_MAX_PATH * 2];
    fs_full_path(fs, key, full, sizeof(full));

#ifdef _WIN32
    _unlink(full);
#else
    unlink(full);
#endif
    return 0;
}

/**
 * fs_exists
 * check if an object file exists and optionally return its size
 * @param ctx opaque connector context
 * @param key object key (relative path)
 * @param size_out if non-NULL, receives the file size in bytes
 * @return 1 if exists, 0 if not, -1 on error
 */
static int fs_exists(void *ctx, const char *key, size_t *size_out)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char full[TDB_FS_MAX_PATH * 2];
    fs_full_path(fs, key, full, sizeof(full));

    struct stat st;
    if (stat(full, &st) != 0)
    {
        if (errno == ENOENT) return 0;
        return -1;
    }

    if (size_out) *size_out = (size_t)st.st_size;
    return 1;
}

/**
 * fs_list_recurse
 * recursively walk a directory and invoke the callback for each regular file
 * @param dir_path directory to walk
 * @param root_dir root directory for computing relative keys
 * @param root_len length of root_dir string
 * @param cb callback invoked for each file (key, size, cb_ctx)
 * @param cb_ctx opaque context passed to callback
 * @param count running count of objects listed
 * @return updated count of objects listed
 */
static int fs_list_recurse(const char *dir_path, const char *root_dir, size_t root_len,
                           void (*cb)(const char *key, size_t size, void *cb_ctx), void *cb_ctx,
                           int count)
{
#ifdef _WIN32
    char pattern[TDB_FS_MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir_path);

    struct _finddata_t fd;
    intptr_t handle = _findfirst(pattern, &fd);
    if (handle == -1) return count;

    do
    {
        if (fd.name[0] == '.') continue;

        char full[TDB_FS_MAX_PATH * 2];
        snprintf(full, sizeof(full), "%s\\%s", dir_path, fd.name);

        if (fd.attrib & _A_SUBDIR)
        {
            count = fs_list_recurse(full, root_dir, root_len, cb, cb_ctx, count);
        }
        else
        {
            const char *relative = full + root_len;
            if (*relative == '/' || *relative == '\\') relative++;

            /** the must normalize backslashes to forward slashes so object keys are
             *  platform-independent (e.g. "cf_name/MANIFEST" not "cf_name\MANIFEST") */
            char normalized[TDB_FS_MAX_PATH];
            strncpy(normalized, relative, sizeof(normalized) - 1);
            normalized[sizeof(normalized) - 1] = '\0';
            for (char *p = normalized; *p; p++)
            {
                if (*p == '\\') *p = '/';
            }

            cb(normalized, (size_t)fd.size, cb_ctx);
            count++;
        }
    } while (_findnext(handle, &fd) == 0);

    _findclose(handle);
#else
    DIR *d = opendir(dir_path);
    if (!d) return count;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (ent->d_name[0] == '.') continue;

        char full[TDB_FS_MAX_PATH * 2];
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (stat(full, &st) != 0) continue;

        if (S_ISDIR(st.st_mode))
        {
            count = fs_list_recurse(full, root_dir, root_len, cb, cb_ctx, count);
        }
        else
        {
            const char *relative = full + root_len;
            if (*relative == '/') relative++;
            cb(relative, (size_t)st.st_size, cb_ctx);
            count++;
        }
    }

    closedir(d);
#endif
    return count;
}

/**
 * fs_list
 * enumerate all objects under a key prefix
 * @param ctx opaque connector context
 * @param prefix key prefix to list (e.g. "cf_name/")
 * @param cb callback invoked for each object (key, size, cb_ctx)
 * @param cb_ctx opaque context passed to callback
 * @return number of objects listed, -1 on error
 */
static int fs_list(void *ctx, const char *prefix,
                   void (*cb)(const char *key, size_t size, void *cb_ctx), void *cb_ctx)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char dir_path[TDB_FS_MAX_PATH + TDB_FS_MAX_PATH];

    snprintf(dir_path, sizeof(dir_path), "%s/%s", fs->root_dir, prefix);

    size_t len = strlen(dir_path);
    while (len > 0 && (dir_path[len - 1] == '/' || dir_path[len - 1] == '\\'))
    {
        dir_path[--len] = '\0';
    }

    return fs_list_recurse(dir_path, fs->root_dir, strlen(fs->root_dir), cb, cb_ctx, 0);
}

/**
 * fs_destroy
 * free connector resources
 * @param ctx opaque connector context
 */
static void fs_destroy(void *ctx)
{
    free(ctx);
}

/**
 * tidesdb_objstore_default_config
 * return default object store configuration with sensible defaults
 * @return default tidesdb_objstore_config_t struct
 */
tidesdb_objstore_config_t tidesdb_objstore_default_config(void)
{
    return (tidesdb_objstore_config_t){
        .local_cache_path = NULL,
        .local_cache_max_bytes = 0,
        .cache_on_read = TDB_OBJSTORE_DEFAULT_CACHE_ON_READ,
        .cache_on_write = TDB_OBJSTORE_DEFAULT_CACHE_ON_WRITE,
        .max_concurrent_uploads = TDB_OBJSTORE_DEFAULT_MAX_UPLOADS,
        .max_concurrent_downloads = TDB_OBJSTORE_DEFAULT_MAX_DOWNLOADS,
        .multipart_threshold = TDB_OBJSTORE_DEFAULT_MULTIPART_THRESHOLD,
        .multipart_part_size = TDB_OBJSTORE_DEFAULT_MULTIPART_PART_SIZE,
        .sync_manifest_to_object = TDB_OBJSTORE_DEFAULT_SYNC_MANIFEST,
        .replicate_wal = TDB_OBJSTORE_DEFAULT_REPLICATE_WAL,
        .wal_upload_sync = TDB_OBJSTORE_DEFAULT_WAL_UPLOAD_SYNC,
        .wal_sync_threshold_bytes = TDB_OBJSTORE_DEFAULT_WAL_SYNC_THRESHOLD,
        .wal_sync_on_commit = TDB_OBJSTORE_DEFAULT_WAL_SYNC_ON_COMMIT,
        .replica_mode = TDB_OBJSTORE_DEFAULT_REPLICA_MODE,
        .replica_sync_interval_us = TDB_OBJSTORE_DEFAULT_REPLICA_SYNC_INTERVAL,
        .replica_replay_wal = TDB_OBJSTORE_DEFAULT_REPLICA_REPLAY_WAL,
    };
}

/**
 * tidesdb_objstore_fs_create
 * create a filesystem-backed connector (for testing and local replication).
 * stores objects as files under root_dir, mirroring the key path structure.
 * @param root_dir directory to store objects in
 * @return connector handle, or NULL on error. caller must eventually call destroy.
 */
tidesdb_objstore_t *tidesdb_objstore_fs_create(const char *root_dir)
{
    if (!root_dir) return NULL;

    fs_ctx_t *fs = calloc(1, sizeof(fs_ctx_t));
    if (!fs) return NULL;

    snprintf(fs->root_dir, sizeof(fs->root_dir), "%s", root_dir);

    /* we create root directory if it does not exist */
#ifdef _WIN32
    _mkdir(root_dir);
#else
    mkdir(root_dir, TDB_FS_DIR_MODE);
#endif

    tidesdb_objstore_t *store = calloc(1, sizeof(tidesdb_objstore_t));
    if (!store)
    {
        free(fs);
        return NULL;
    }

    store->backend = TDB_BACKEND_FS;
    store->put = fs_put;
    store->get = fs_get;
    store->range_get = fs_range_get;
    store->delete_object = fs_delete_object;
    store->exists = fs_exists;
    store->list = fs_list;
    store->destroy = fs_destroy;
    store->ctx = fs;

    return store;
}
