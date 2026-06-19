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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "objstore.h"

#ifndef _WIN32
#include <dirent.h>
#include <sys/file.h> /* flock -- serializes the put_if read-modify-write */
#include <unistd.h>
#else
#include <direct.h>
#include <io.h>
#endif

#define TDB_FS_MAX_PATH 4096
#define TDB_FS_COPY_BUF 65536
#define TDB_FS_DIR_MODE 0755
/* extra bytes reserved for the ".tmp.<pid>.<tid>" suffix on the atomic-put temp path */
#define TDB_FS_TMP_SUFFIX_MAX 64
/* sidecar directory holding put_if ETag/epoch/lock state, isolated from the object
 * keyspace so list() under data prefixes (uwal_, cf/MANIFEST) never sees it */
#define TDB_FS_META_DIR  ".tdb_objmeta"
#define TDB_FS_META_PATH (TDB_FS_MAX_PATH * 2 + 64)

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

static void fs_meta_path(const fs_ctx_t *ctx, const char *key, const char *suffix, char *out,
                         size_t out_size);

/**
 * fs_mkdir_p
 * create all intermediate directories for a file path
 * @param file_path path to a file whose parent directories should be created
 */
static void fs_mkdir_p(const char *file_path)
{
    /* sized to the largest path any caller passes (full object paths and meta sidecars are
     * root + key, up to TDB_FS_META_PATH) so a long key's parent dirs are not truncated */
    char tmp[TDB_FS_META_PATH];
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
 * @param limit when nonzero, copy only the first limit bytes (skips a WAL's preallocated tail)
 * @return 0 on success, -1 on error
 */
static int fs_copy_file(const char *src_path, const char *dst_path, size_t limit)
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
    size_t copied = 0;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
    {
        if (limit && copied + n > limit) n = limit - copied;
        if (fwrite(buf, 1, n, dst) != n)
        {
            rc = -1;
            break;
        }
        copied += n;
        if (limit && copied >= limit) break;
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
 * fs_put_limited
 * write a local file as an object, optionally only its first limit bytes (0 = whole file)
 * @param ctx opaque connector context
 * @param key object key (relative path)
 * @param local_path local file to upload
 * @param limit byte limit (0 = whole file)
 * @return 0 on success, -1 on error
 */
static int fs_put_limited(void *ctx, const char *key, const char *local_path, size_t limit)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char full[TDB_FS_MAX_PATH * 2];
    fs_full_path(fs, key, full, sizeof(full));

    /* copy to a unique temp file then atomically rename into place, so a concurrent
     * reader/list never observes a partially-written object -- the objstore put contract
     * (objstore.h) is "atomic object". the temp lives in the same directory as the target
     * so the rename stays within one filesystem. */
    char tmp[TDB_FS_MAX_PATH * 2 + TDB_FS_TMP_SUFFIX_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld.%lu", full, (long)TDB_GETPID(), TDB_THREAD_ID());

    if (fs_copy_file(local_path, tmp, limit) != 0) return -1;

    if (atomic_rename_file(tmp, full) != 0)
    {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/**
 * fs_put
 * upload a local file as an object (whole file)
 * @param ctx opaque connector context
 * @param key object key (relative path)
 * @param local_path local file to upload
 * @return 0 on success, -1 on error
 */
static int fs_put(void *ctx, const char *key, const char *local_path)
{
    return fs_put_limited(ctx, key, local_path, 0);
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
    return fs_copy_file(full, local_path, 0);
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
static ssize_t fs_range_get(void *ctx, const char *key, const uint64_t offset, void *buf,
                            const size_t size)
{
    const fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char full[TDB_FS_MAX_PATH * 2];
    fs_full_path(fs, key, full, sizeof(full));

    const int fd = open(full, O_RDONLY, 0);
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

    /* drop the put_if sidecars too, or a later create-only would see the key as still present */
    const char *suffixes[] = {".etag", ".epoch", ".lock"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++)
    {
        char meta[TDB_FS_META_PATH];
        fs_meta_path(fs, key, suffixes[i], meta, sizeof(meta));
        tdb_unlink(meta);
    }
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
 * fs_meta_path
 * build the sidecar metadata path for a key under the isolated meta directory:
 * <root>/.tdb_objmeta/<key><suffix>
 * @param ctx connector context
 * @param key object key
 * @param suffix sidecar suffix (".etag", ".epoch", ".lock")
 * @param out output buffer
 * @param out_size size of the output buffer
 */
static void fs_meta_path(const fs_ctx_t *ctx, const char *key, const char *suffix, char *out,
                         size_t out_size)
{
    snprintf(out, out_size, "%s/%s/%s%s", ctx->root_dir, TDB_FS_META_DIR, key, suffix);
}

/**
 * fs_read_text
 * read a short text sidecar, NUL-terminate, and trim a trailing newline.
 * @return 0 on success, -1 if the file is absent or unreadable
 */
static int fs_read_text(const char *path, char *out, size_t out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, out_size - 1, f);
    fclose(f);
    out[n] = '\0';
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = '\0';
    return 0;
}

/**
 * fs_write_text
 * write text to a sidecar atomically (tmp + rename), creating parent dirs.
 * @return 0 on success, -1 on error
 */
static int fs_write_text(const char *path, const char *text)
{
    fs_mkdir_p(path);
    char tmp[TDB_FS_META_PATH + TDB_FS_TMP_SUFFIX_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld.%lu", path, (long)TDB_GETPID(), TDB_THREAD_ID());

    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    int ok = (fputs(text, f) >= 0);
    if (fclose(f) != 0) ok = 0;
    if (!ok)
    {
        tdb_unlink(tmp);
        return -1;
    }
    if (atomic_rename_file(tmp, path) != 0)
    {
        tdb_unlink(tmp);
        return -1;
    }
    return 0;
}

/**
 * fs_put_if
 * conditional upload emulated with ETag/epoch sidecars under a per-key lock, so the
 * single-writer fence is exercised by the test backend without a live S3.
 *
 * the critical section uses flock() rather than the compat.h lock helpers on purpose --
 * those carry whole-DB PID / F_SETLK semantics (same-process re-lock is allowed), whereas
 * a primary and a replica handle in one test process must serialize against each other.
 * flock locks the open file description, so two independent opens contend even in-process.
 * @return 0 on success, TDB_ERR_PRECONDITION on precondition failure, -1 on error
 */
static int fs_put_if(void *ctx, const char *key, const char *local_path, tidesdb_put_cond_t cond,
                     const char *expected_etag, uint64_t meta_epoch, char *etag_out,
                     size_t etag_out_sz, size_t max_bytes)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;

    char etag_path[TDB_FS_META_PATH];
    char epoch_path[TDB_FS_META_PATH];
    char lock_path[TDB_FS_META_PATH];
    fs_meta_path(fs, key, ".etag", etag_path, sizeof(etag_path));
    fs_meta_path(fs, key, ".epoch", epoch_path, sizeof(epoch_path));
    fs_meta_path(fs, key, ".lock", lock_path, sizeof(lock_path));

    fs_mkdir_p(lock_path);
    int lockfd = open(lock_path, O_CREAT | O_RDWR, 0644);
    if (lockfd < 0) return -1;
#ifndef _WIN32
    if (flock(lockfd, LOCK_EX) != 0)
    {
        close(lockfd);
        return -1;
    }
#endif

    char cur_etag[TDB_OBJSTORE_ETAG_MAX] = {0};
    int have = (fs_read_text(etag_path, cur_etag, sizeof(cur_etag)) == 0);

    int precond_fail = 0;
    if (cond == TDB_PUT_IF_NONE_MATCH && have)
        precond_fail = 1;
    else if (cond == TDB_PUT_IF_MATCH &&
             (!have || !expected_etag || strcmp(cur_etag, expected_etag) != 0))
        precond_fail = 1;

    int rc;
    if (precond_fail)
    {
        rc = TDB_ERR_PRECONDITION;
    }
    else if (fs_put_limited(ctx, key, local_path, max_bytes) != 0)
    {
        rc = -1;
    }
    else
    {
        /* a strictly increasing per-object counter -- a fresh ETag on every write so a
         * superseded writer that renews with identical content still sees its old ETag go
         * stale (a content-hash ETag would not change and would defeat the CAS). */
        unsigned long long counter = 0;
        if (have) sscanf(cur_etag, "%llu", &counter);
        counter++;
        char new_etag[TDB_OBJSTORE_ETAG_MAX];
        snprintf(new_etag, sizeof(new_etag), "%llu", counter);

        if (fs_write_text(etag_path, new_etag) != 0)
        {
            rc = -1;
        }
        else
        {
            char epoch_buf[32];
            snprintf(epoch_buf, sizeof(epoch_buf), "%llu", (unsigned long long)meta_epoch);
            fs_write_text(epoch_path, epoch_buf); /* best-effort; 0 reads back as 'absent' */
            if (etag_out) snprintf(etag_out, etag_out_sz, "%s", new_etag);
            rc = 0;
        }
    }

#ifndef _WIN32
    flock(lockfd, LOCK_UN);
#endif
    close(lockfd);
    return rc;
}

/**
 * fs_head
 * return a key's ETag and epoch sidecars without reading the object body.
 * @return 1 if the object exists, 0 if not, -1 on error
 */
static int fs_head(void *ctx, const char *key, char *etag_out, size_t etag_out_sz,
                   uint64_t *meta_epoch_out)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;
    char full[TDB_FS_MAX_PATH * 2];
    fs_full_path(fs, key, full, sizeof(full));

    struct stat st;
    int exists = (stat(full, &st) == 0);
    int stat_errno = errno;

    if (etag_out)
    {
        char etag_path[TDB_FS_META_PATH];
        fs_meta_path(fs, key, ".etag", etag_path, sizeof(etag_path));
        if (fs_read_text(etag_path, etag_out, etag_out_sz) != 0) etag_out[0] = '\0';
    }
    if (meta_epoch_out)
    {
        char epoch_path[TDB_FS_META_PATH];
        char buf[32];
        fs_meta_path(fs, key, ".epoch", epoch_path, sizeof(epoch_path));
        *meta_epoch_out =
            (fs_read_text(epoch_path, buf, sizeof(buf)) == 0) ? strtoull(buf, NULL, 10) : 0;
    }

    if (exists) return 1;
    return (stat_errno == ENOENT) ? 0 : -1;
}

/**
 * fs_list_walk
 * recursively walk abs_dir and invoke cb for each regular file whose
 * relative key starts with prefix. subdirectories whose relative path
 * already diverges from prefix are not descended into.
 * @param abs_dir absolute filesystem path of the directory to walk
 * @param rel_dir relative key path of abs_dir within the store ("" at root)
 * @param rel_dir_len cached strlen(rel_dir)
 * @param prefix target key prefix
 * @param prefix_len cached strlen(prefix)
 * @param cb callback invoked for each matching file (key, size, cb_ctx)
 * @param cb_ctx opaque context passed to callback
 * @param count running count of objects emitted
 * @return updated count
 */
static int fs_list_walk(const char *abs_dir, const char *rel_dir, size_t rel_dir_len,
                        const char *prefix, size_t prefix_len,
                        void (*cb)(const char *key, size_t size, void *cb_ctx), void *cb_ctx,
                        int count)
{
#ifdef _WIN32
    char pattern[TDB_FS_MAX_PATH * 2];
    snprintf(pattern, sizeof(pattern), "%s\\*", abs_dir);

    struct _finddata_t fd;
    intptr_t handle = _findfirst(pattern, &fd);
    if (handle == -1) return count;

    do
    {
        if (fd.name[0] == '.' && (fd.name[1] == '\0' || (fd.name[1] == '.' && fd.name[2] == '\0')))
            continue;

        /* the put_if meta sidecar dir is internal bookkeeping, never an object */
        if (rel_dir_len == 0 && strcmp(fd.name, TDB_FS_META_DIR) == 0) continue;

        char child_rel[TDB_FS_MAX_PATH];
        int n = (rel_dir_len == 0)
                    ? snprintf(child_rel, sizeof(child_rel), "%s", fd.name)
                    : snprintf(child_rel, sizeof(child_rel), "%s/%s", rel_dir, fd.name);
        if (n < 0 || (size_t)n >= sizeof(child_rel)) continue;
        size_t child_rel_len = (size_t)n;

        if (fd.attrib & _A_SUBDIR)
        {
            size_t cmp = child_rel_len < prefix_len ? child_rel_len : prefix_len;
            if (cmp && strncmp(child_rel, prefix, cmp) != 0) continue;

            char child_abs[TDB_FS_MAX_PATH * 2];
            snprintf(child_abs, sizeof(child_abs), "%s\\%s", abs_dir, fd.name);
            count = fs_list_walk(child_abs, child_rel, child_rel_len, prefix, prefix_len, cb,
                                 cb_ctx, count);
            continue;
        }

        if (prefix_len != 0 &&
            (child_rel_len < prefix_len || strncmp(child_rel, prefix, prefix_len) != 0))
            continue;

        cb(child_rel, (size_t)fd.size, cb_ctx);
        count++;
    } while (_findnext(handle, &fd) == 0);

    _findclose(handle);
#else
    DIR *d = opendir(abs_dir);
    if (!d) return count;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
    {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;

        /* the put_if meta sidecar dir is internal bookkeeping, never an object */
        if (rel_dir_len == 0 && strcmp(ent->d_name, TDB_FS_META_DIR) == 0) continue;

        char child_rel[TDB_FS_MAX_PATH];
        int n = (rel_dir_len == 0)
                    ? snprintf(child_rel, sizeof(child_rel), "%s", ent->d_name)
                    : snprintf(child_rel, sizeof(child_rel), "%s/%s", rel_dir, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(child_rel)) continue;
        size_t child_rel_len = (size_t)n;

        /* prefer dirent::d_type; fall back to stat() only when the FS reports DT_UNKNOWN */
        int is_dir = 0, is_reg = 0;
#ifdef DT_DIR
        if (ent->d_type == DT_DIR)
            is_dir = 1;
        else if (ent->d_type == DT_REG)
            is_reg = 1;
        else if (ent->d_type != DT_UNKNOWN)
            continue;
        else
#endif
        {
            char child_abs[TDB_FS_MAX_PATH * 2];
            snprintf(child_abs, sizeof(child_abs), "%s/%s", abs_dir, ent->d_name);
            struct stat st;
            if (stat(child_abs, &st) != 0) continue;
            if (S_ISDIR(st.st_mode))
                is_dir = 1;
            else if (S_ISREG(st.st_mode))
                is_reg = 1;
            else
                continue;
        }

        if (is_dir)
        {
            size_t cmp = child_rel_len < prefix_len ? child_rel_len : prefix_len;
            if (cmp && strncmp(child_rel, prefix, cmp) != 0) continue;

            char child_abs[TDB_FS_MAX_PATH * 2];
            snprintf(child_abs, sizeof(child_abs), "%s/%s", abs_dir, ent->d_name);
            count = fs_list_walk(child_abs, child_rel, child_rel_len, prefix, prefix_len, cb,
                                 cb_ctx, count);
            continue;
        }

        if (!is_reg) continue;

        if (prefix_len != 0 &&
            (child_rel_len < prefix_len || strncmp(child_rel, prefix, prefix_len) != 0))
            continue;

        char child_abs[TDB_FS_MAX_PATH * 2];
        snprintf(child_abs, sizeof(child_abs), "%s/%s", abs_dir, ent->d_name);
        struct stat st;
        if (stat(child_abs, &st) != 0) continue;
        cb(child_rel, (size_t)st.st_size, cb_ctx);
        count++;
    }

    closedir(d);
#endif
    return count;
}

/**
 * fs_list
 * enumerate all objects whose key starts with prefix. matches S3
 * ListObjectsV2(prefix=...) semantics, the prefix is matched byte-wise
 * against the key and need not align to a directory boundary.
 * @param ctx opaque connector context
 * @param prefix key prefix to list (e.g. "cf_name/" or "uwal_")
 * @param cb callback invoked for each object (key, size, cb_ctx)
 * @param cb_ctx opaque context passed to callback
 * @return number of objects listed, -1 on error
 */
static int fs_list(void *ctx, const char *prefix,
                   void (*cb)(const char *key, size_t size, void *cb_ctx), void *cb_ctx)
{
    fs_ctx_t *fs = (fs_ctx_t *)ctx;

    /* descend straight to the deepest directory component embedded in prefix
     * so we don't walk ancestors that cannot contain a matching key */
    const char *last_sep = strrchr(prefix, '/');
#ifdef _WIN32
    {
        const char *bs = strrchr(prefix, '\\');
        if (bs && (!last_sep || bs > last_sep)) last_sep = bs;
    }
#endif

    char start_abs[TDB_FS_MAX_PATH * 2];
    char start_rel[TDB_FS_MAX_PATH];
    size_t start_rel_len = 0;
    if (last_sep && last_sep != prefix)
    {
        size_t dir_len = (size_t)(last_sep - prefix);
        snprintf(start_abs, sizeof(start_abs), "%s/%.*s", fs->root_dir, (int)dir_len, prefix);
        snprintf(start_rel, sizeof(start_rel), "%.*s", (int)dir_len, prefix);
        start_rel_len = dir_len;
    }
    else
    {
        snprintf(start_abs, sizeof(start_abs), "%s", fs->root_dir);
        start_rel[0] = '\0';
    }

    return fs_list_walk(start_abs, start_rel, start_rel_len, prefix, strlen(prefix), cb, cb_ctx, 0);
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
    store->put_if = fs_put_if;
    store->head = fs_head;
    store->destroy = fs_destroy;
    store->ctx = fs;

    return store;
}
