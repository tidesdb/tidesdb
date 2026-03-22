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

#ifdef TIDESDB_WITH_S3

#include "objstore_s3.h"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/* path and buffer size constants */
#define TDB_S3_MAX_PATH      4096
#define TDB_S3_MAX_HEADER    2048
#define TDB_S3_DATE_LEN      9  /* YYYYMMDD + NUL */
#define TDB_S3_TIMESTAMP_LEN 17 /* YYYYMMDDTHHMMSSZ + NUL */
#define TDB_S3_HASH_HEX_LEN  65 /* SHA256 hex + NUL */
#define TDB_S3_SHA256_DIGEST 32 /* SHA256 raw digest bytes */
#define TDB_S3_DIR_MODE      0755

/* context struct buffer sizes */
#define TDB_S3_ENDPOINT_MAX 512
#define TDB_S3_BUCKET_MAX   256
#define TDB_S3_PREFIX_MAX   512
#define TDB_S3_KEY_MAX      128
#define TDB_S3_REGION_MAX   64

/* HTTP status codes */
#define TDB_S3_HTTP_OK       200
#define TDB_S3_HTTP_PARTIAL  206
#define TDB_S3_HTTP_REDIRECT 300

/* signing and response buffers */
#define TDB_S3_SCOPE_BUF      128
#define TDB_S3_STS_BUF        512
#define TDB_S3_HOST_BUF       512
#define TDB_S3_RESPONSE_INIT  4096
#define TDB_S3_CONT_TOKEN_MAX 1024
#define TDB_S3_XML_TAG_BUF    128
#define TDB_S3_SIZE_BUF       32
#define TDB_S3_KEY_DATE_BUF   128

/* default region when none specified */
#define TDB_S3_DEFAULT_REGION "us-east-1"

/**
 * s3_uri_encode
 * URI-encode a string per the SigV4 spec. encodes all bytes except unreserved
 * characters (A-Z, a-z, 0-9, '-', '.', '_', '~'). forward slashes are encoded
 * as %2F since this is used for query parameter values, not object key paths.
 * @param src input string
 * @param dst output buffer
 * @param dst_size size of output buffer
 */
static void s3_uri_encode(const char *src, char *dst, size_t dst_size)
{
    static const char *unreserved =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    size_t pos = 0;
    for (; *src && pos + 3 < dst_size; src++)
    {
        if (strchr(unreserved, *src))
        {
            dst[pos++] = *src;
        }
        else
        {
            snprintf(dst + pos, dst_size - pos, "%%%02X", (unsigned char)*src);
            pos += 3;
        }
    }
    dst[pos] = '\0';
}

/**
 * s3_ctx_t
 * internal context for the S3 connector, holding credentials and endpoint config
 * @param endpoint S3 endpoint hostname
 * @param bucket S3 bucket name
 * @param prefix key prefix prepended to all object keys
 * @param access_key AWS access key ID
 * @param secret_key AWS secret access key
 * @param region AWS region string
 * @param use_ssl 1 for HTTPS, 0 for HTTP
 * @param use_path_style 1 for path-style URLs, 0 for virtual-hosted
 */
typedef struct
{
    char endpoint[TDB_S3_ENDPOINT_MAX];
    char bucket[TDB_S3_BUCKET_MAX];
    char prefix[TDB_S3_PREFIX_MAX];
    char access_key[TDB_S3_KEY_MAX];
    char secret_key[TDB_S3_KEY_MAX];
    char region[TDB_S3_REGION_MAX];
    int use_ssl;
    int use_path_style;
} s3_ctx_t;

/**
 * sha256_hex
 * compute SHA256 hash and output as lowercase hex string
 * @param data input data
 * @param len length of input data
 * @param hex_out output buffer (must be at least TDB_S3_HASH_HEX_LEN bytes)
 */
static void sha256_hex(const void *data, size_t len, char *hex_out)
{
    unsigned char hash[TDB_S3_SHA256_DIGEST];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < 32; i++) sprintf(hex_out + i * 2, "%02x", hash[i]);
    hex_out[64] = '\0';
}

/**
 * hmac_sha256
 * compute HMAC-SHA256
 * @param key HMAC key
 * @param key_len length of key
 * @param data input data
 * @param data_len length of data
 * @param out output buffer (TDB_S3_SHA256_DIGEST bytes)
 * @param out_len receives the output length
 */
static void hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len,
                        unsigned char *out, unsigned int *out_len)
{
    HMAC(EVP_sha256(), key, (int)key_len, (const unsigned char *)data, data_len, out, out_len);
}

/**
 * s3_get_timestamp
 * get current UTC time in AWS SigV4 date and timestamp formats
 * @param date8 output YYYYMMDD (TDB_S3_DATE_LEN bytes)
 * @param timestamp16 output YYYYMMDDTHHMMSSZ (TDB_S3_TIMESTAMP_LEN bytes)
 */
static void s3_get_timestamp(char *date8, char *timestamp16)
{
    time_t now = time(NULL);
    struct tm gm;
    gmtime_r(&now, &gm);
    strftime(date8, TDB_S3_DATE_LEN, "%Y%m%d", &gm);
    strftime(timestamp16, TDB_S3_TIMESTAMP_LEN, "%Y%m%dT%H%M%SZ", &gm);
}

/**
 * s3_signing_key
 * derive the SigV4 signing key via HMAC chain: date -> region -> service -> request
 * @param secret_key AWS secret access key
 * @param date8 date string YYYYMMDD
 * @param region AWS region
 * @param out output signing key (TDB_S3_SHA256_DIGEST bytes)
 * @param out_len receives the output length
 */
static void s3_signing_key(const char *secret_key, const char *date8, const char *region,
                           unsigned char *out, unsigned int *out_len)
{
    char key_date[TDB_S3_KEY_DATE_BUF];
    snprintf(key_date, sizeof(key_date), "AWS4%s", secret_key);

    unsigned char k1[TDB_S3_SHA256_DIGEST], k2[TDB_S3_SHA256_DIGEST], k3[TDB_S3_SHA256_DIGEST];
    unsigned int l;
    hmac_sha256(key_date, strlen(key_date), date8, strlen(date8), k1, &l);
    hmac_sha256(k1, l, region, strlen(region), k2, &l);
    hmac_sha256(k2, l, "s3", 2, k3, &l);
    hmac_sha256(k3, l, "aws4_request", 12, out, out_len);
}

/**
 * s3_build_url
 * construct the full URL for an S3 object request
 * @param ctx S3 connector context
 * @param key object key
 * @param url output URL buffer
 * @param url_size size of the URL buffer
 */
static void s3_build_url(const s3_ctx_t *ctx, const char *key, char *url, size_t url_size)
{
    const char *scheme = ctx->use_ssl ? "https" : "http";
    char full_key[TDB_S3_MAX_PATH];
    if (ctx->prefix[0])
        snprintf(full_key, sizeof(full_key), "%s%s", ctx->prefix, key);
    else
        snprintf(full_key, sizeof(full_key), "%s", key);

    if (ctx->use_path_style)
        snprintf(url, url_size, "%s://%s/%s/%s", scheme, ctx->endpoint, ctx->bucket, full_key);
    else
        snprintf(url, url_size, "%s://%s.%s/%s", scheme, ctx->bucket, ctx->endpoint, full_key);
}

/**
 * s3_build_host
 * construct the Host header value for S3 requests
 * @param ctx S3 connector context
 * @param host output host string
 * @param host_size size of host buffer
 */
static void s3_build_host(const s3_ctx_t *ctx, char *host, size_t host_size)
{
    if (ctx->use_path_style)
        snprintf(host, host_size, "%s", ctx->endpoint);
    else
        snprintf(host, host_size, "%s.%s", ctx->bucket, ctx->endpoint);
}

/**
 * s3_sign_raw
 * create AWS SigV4 signed HTTP headers given explicit canonical URI and query string.
 * this is the low-level signing function used by both object operations and list requests.
 * @param ctx S3 connector context
 * @param method HTTP method (GET, PUT, DELETE, HEAD)
 * @param canonical_uri the URI path component of the request (e.g. "/bucket/key")
 * @param canonical_query_string the query string component (alphabetically sorted, or "")
 * @param content_sha256 hex-encoded SHA256 of the request body
 * @param extra_headers_canonical additional canonical headers (or NULL)
 * @param extra_signed_headers additional signed header names (or NULL)
 * @return curl_slist of signed headers (caller must free with curl_slist_free_all)
 */
static struct curl_slist *s3_sign_raw(const s3_ctx_t *ctx, const char *method,
                                      const char *canonical_uri, const char *canonical_query_string,
                                      const char *content_sha256,
                                      const char *extra_headers_canonical,
                                      const char *extra_signed_headers)
{
    char date8[TDB_S3_DATE_LEN], timestamp[TDB_S3_TIMESTAMP_LEN];
    s3_get_timestamp(date8, timestamp);

    char host[TDB_S3_HOST_BUF];
    s3_build_host(ctx, host, sizeof(host));

    /* canonical request */
    char canonical_request[TDB_S3_MAX_PATH * 4];
    snprintf(canonical_request, sizeof(canonical_request),
             "%s\n%s\n%s\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n%s\n"
             "host;x-amz-content-sha256;x-amz-date%s\n%s",
             method, canonical_uri, canonical_query_string ? canonical_query_string : "", host,
             content_sha256, timestamp, extra_headers_canonical ? extra_headers_canonical : "",
             extra_signed_headers ? extra_signed_headers : "", content_sha256);

    char canonical_hash[TDB_S3_HASH_HEX_LEN];
    sha256_hex(canonical_request, strlen(canonical_request), canonical_hash);

    /* string to sign */
    char scope[TDB_S3_SCOPE_BUF];
    snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request", date8, ctx->region);

    char string_to_sign[TDB_S3_STS_BUF];
    snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s", timestamp,
             scope, canonical_hash);

    /* signature */
    unsigned char signing_key[TDB_S3_SHA256_DIGEST];
    unsigned int sk_len;
    s3_signing_key(ctx->secret_key, date8, ctx->region, signing_key, &sk_len);

    unsigned char sig_raw[TDB_S3_SHA256_DIGEST];
    unsigned int sig_len;
    hmac_sha256(signing_key, sk_len, string_to_sign, strlen(string_to_sign), sig_raw, &sig_len);

    char sig_hex[TDB_S3_HASH_HEX_LEN];
    for (unsigned int i = 0; i < sig_len; i++) sprintf(sig_hex + i * 2, "%02x", sig_raw[i]);
    sig_hex[sig_len * 2] = '\0';

    char auth_header[TDB_S3_MAX_HEADER];
    snprintf(auth_header, sizeof(auth_header),
             "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, "
             "SignedHeaders=host;x-amz-content-sha256;x-amz-date%s, Signature=%s",
             ctx->access_key, scope, extra_signed_headers ? extra_signed_headers : "", sig_hex);

    /* we build curl headers */
    struct curl_slist *headers = NULL;
    char hdr[TDB_S3_MAX_HEADER];

    snprintf(hdr, sizeof(hdr), "Host: %s", host);
    headers = curl_slist_append(headers, hdr);

    snprintf(hdr, sizeof(hdr), "x-amz-date: %s", timestamp);
    headers = curl_slist_append(headers, hdr);

    snprintf(hdr, sizeof(hdr), "x-amz-content-sha256: %s", content_sha256);
    headers = curl_slist_append(headers, hdr);

    headers = curl_slist_append(headers, auth_header);

    return headers;
}

/**
 * s3_sign_request
 * create AWS SigV4 signed HTTP headers for an S3 object request.
 * computes the canonical URI from the key and connector prefix,
 * then delegates to s3_sign_raw with an empty query string.
 * @param ctx S3 connector context
 * @param method HTTP method (GET, PUT, DELETE, HEAD)
 * @param key object key
 * @param content_sha256 hex-encoded SHA256 of the request body
 * @param extra_headers_canonical additional canonical headers (or NULL)
 * @param extra_signed_headers additional signed header names (or NULL)
 * @return curl_slist of signed headers (caller must free with curl_slist_free_all)
 */
static struct curl_slist *s3_sign_request(const s3_ctx_t *ctx, const char *method, const char *key,
                                          const char *content_sha256,
                                          const char *extra_headers_canonical,
                                          const char *extra_signed_headers)
{
    char full_key[TDB_S3_MAX_PATH];
    if (ctx->prefix[0])
        snprintf(full_key, sizeof(full_key), "%s%s", ctx->prefix, key);
    else
        snprintf(full_key, sizeof(full_key), "%s", key);

    char canonical_uri[TDB_S3_MAX_PATH];
    if (ctx->use_path_style)
        snprintf(canonical_uri, sizeof(canonical_uri), "/%s/%s", ctx->bucket, full_key);
    else
        snprintf(canonical_uri, sizeof(canonical_uri), "/%s", full_key);

    return s3_sign_raw(ctx, method, canonical_uri, "", content_sha256, extra_headers_canonical,
                       extra_signed_headers);
}

/**
 * s3_write_ctx_t
 * context for curl write callbacks, supports writing to file or buffer
 * @param fp file pointer for file-based writes (NULL if writing to buffer)
 * @param buf buffer pointer for in-memory writes (NULL if writing to file)
 * @param buf_size total size of the output buffer
 * @param written number of bytes written so far
 */
typedef struct
{
    FILE *fp;
    char *buf;
    size_t buf_size;
    size_t written;
} s3_write_ctx_t;

/**
 * s3_write_to_file
 * curl write callback that writes received data to a file
 * @param ptr pointer to received data
 * @param size size of each element
 * @param nmemb number of elements
 * @param userdata pointer to s3_write_ctx_t with fp set
 * @return number of bytes written
 */
static size_t s3_write_to_file(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3_write_ctx_t *wctx = (s3_write_ctx_t *)userdata;
    return fwrite(ptr, size, nmemb, wctx->fp);
}

/**
 * s3_write_to_buf
 * curl write callback that copies received data into a fixed-size buffer
 * @param ptr pointer to received data
 * @param size size of each element
 * @param nmemb number of elements
 * @param userdata pointer to s3_write_ctx_t with buf and buf_size set
 * @return number of bytes consumed (always size * nmemb to avoid curl error)
 */
static size_t s3_write_to_buf(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3_write_ctx_t *wctx = (s3_write_ctx_t *)userdata;
    size_t bytes = size * nmemb;
    size_t avail = wctx->buf_size - wctx->written;
    size_t to_copy = bytes < avail ? bytes : avail;
    memcpy(wctx->buf + wctx->written, ptr, to_copy);
    wctx->written += to_copy;
    return bytes; /* always consume all data to avoid curl error */
}

/**
 * s3_write_discard
 * curl write callback that discards all received data
 * @param ptr pointer to received data (unused)
 * @param size size of each element
 * @param nmemb number of elements
 * @param userdata unused
 * @return number of bytes consumed (always size * nmemb)
 */
static size_t s3_write_discard(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

/**
 * s3_put
 * upload a local file to S3 as an object
 * @param ctx opaque S3 connector context
 * @param key object key (path-like)
 * @param local_path path to the local file to upload
 * @return 0 on success, -1 on error
 */
static int s3_put(void *ctx, const char *key, const char *local_path)
{
    s3_ctx_t *s3 = (s3_ctx_t *)ctx;

    FILE *fp = fopen(local_path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* we read file into memory for SHA256 */
    void *file_data = malloc(file_size > 0 ? file_size : 1);
    if (!file_data)
    {
        fclose(fp);
        return -1;
    }
    if (file_size > 0) fread(file_data, 1, file_size, fp);
    fclose(fp);

    char content_sha[TDB_S3_HASH_HEX_LEN];
    sha256_hex(file_data, file_size > 0 ? file_size : 0, content_sha);

    struct curl_slist *headers = s3_sign_request(s3, "PUT", key, content_sha, NULL, NULL);

    char url[TDB_S3_MAX_PATH];
    s3_build_url(s3, key, url, sizeof(url));

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_size);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3_write_discard);

    FILE *mem_fp = fmemopen(file_data, file_size > 0 ? file_size : 1, "rb");
    curl_easy_setopt(curl, CURLOPT_READDATA, mem_fp);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    fclose(mem_fp);
    free(file_data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK && http_code >= TDB_S3_HTTP_OK && http_code < TDB_S3_HTTP_REDIRECT)
               ? 0
               : -1;
}

/**
 * s3_get
 * download an S3 object to a local file, creating parent directories as needed
 * @param ctx opaque S3 connector context
 * @param key object key
 * @param local_path path to write the downloaded file
 * @return 0 on success, -1 on error (including not found)
 */
static int s3_get(void *ctx, const char *key, const char *local_path)
{
    s3_ctx_t *s3 = (s3_ctx_t *)ctx;

    char empty_sha[TDB_S3_HASH_HEX_LEN];
    sha256_hex("", 0, empty_sha);

    struct curl_slist *headers = s3_sign_request(s3, "GET", key, empty_sha, NULL, NULL);

    char url[TDB_S3_MAX_PATH];
    s3_build_url(s3, key, url, sizeof(url));

    /* we create parent directories for local_path */
    char dir_buf[TDB_S3_MAX_PATH];
    snprintf(dir_buf, sizeof(dir_buf), "%s", local_path);
    char *sep = strrchr(dir_buf, '/');
    if (sep)
    {
        *sep = '\0';

        for (char *p = dir_buf + 1; *p; p++)
        {
            if (*p == '/')
            {
                *p = '\0';
                mkdir(dir_buf, TDB_S3_DIR_MODE);
                *p = '/';
            }
        }
        mkdir(dir_buf, 0755);
    }

    FILE *fp = fopen(local_path, "wb");
    if (!fp)
    {
        curl_slist_free_all(headers);
        return -1;
    }

    s3_write_ctx_t wctx = {.fp = fp};

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3_write_to_file);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &wctx);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    fclose(fp);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code < TDB_S3_HTTP_OK || http_code >= TDB_S3_HTTP_REDIRECT)
    {
        unlink(local_path);
        return -1;
    }
    return 0;
}

/**
 * s3_range_get
 * download a byte range of an S3 object into a caller-allocated buffer
 * @param ctx opaque S3 connector context
 * @param key object key
 * @param offset byte offset to start reading
 * @param buf output buffer (caller allocated)
 * @param size number of bytes to read
 * @return bytes read on success, -1 on error
 */
static ssize_t s3_range_get(void *ctx, const char *key, uint64_t offset, void *buf, size_t size)
{
    s3_ctx_t *s3 = (s3_ctx_t *)ctx;

    char empty_sha[TDB_S3_HASH_HEX_LEN];
    sha256_hex("", 0, empty_sha);

    /* sign without Range header -- S3/MinIO does not require Range to be signed */
    struct curl_slist *headers = s3_sign_request(s3, "GET", key, empty_sha, NULL, NULL);

    char range_hdr[128];
    snprintf(range_hdr, sizeof(range_hdr), "Range: bytes=%" PRIu64 "-%" PRIu64, offset,
             offset + size - 1);
    headers = curl_slist_append(headers, range_hdr);

    char url[TDB_S3_MAX_PATH];
    s3_build_url(s3, key, url, sizeof(url));

    s3_write_ctx_t wctx = {.buf = (char *)buf, .buf_size = size, .written = 0};

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3_write_to_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &wctx);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || (http_code != TDB_S3_HTTP_OK && http_code != TDB_S3_HTTP_PARTIAL))
        return -1;
    return (ssize_t)wctx.written;
}

/**
 * s3_delete_object
 * delete an object from S3. not-found is not an error.
 * @param ctx opaque S3 connector context
 * @param key object key to delete
 * @return 0 on success, -1 on error
 */
static int s3_delete_object(void *ctx, const char *key)
{
    s3_ctx_t *s3 = (s3_ctx_t *)ctx;

    char empty_sha[TDB_S3_HASH_HEX_LEN];
    sha256_hex("", 0, empty_sha);

    struct curl_slist *headers = s3_sign_request(s3, "DELETE", key, empty_sha, NULL, NULL);

    char url[TDB_S3_MAX_PATH];
    s3_build_url(s3, key, url, sizeof(url));

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3_write_discard);

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    /* 204 No Content or 404 Not Found are both success for delete */
    return (res == CURLE_OK) ? 0 : -1;
}

/**
 * s3_exists
 * check if an S3 object exists and optionally return its size via HEAD request
 * @param ctx opaque S3 connector context
 * @param key object key
 * @param size_out if non-NULL, receives the object size in bytes
 * @return 1 if exists, 0 if not, -1 on error
 */
static int s3_exists(void *ctx, const char *key, size_t *size_out)
{
    s3_ctx_t *s3 = (s3_ctx_t *)ctx;

    char empty_sha[TDB_S3_HASH_HEX_LEN];
    sha256_hex("", 0, empty_sha);

    struct curl_slist *headers = s3_sign_request(s3, "HEAD", key, empty_sha, NULL, NULL);

    char url[TDB_S3_MAX_PATH];
    s3_build_url(s3, key, url, sizeof(url));

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3_write_discard);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (size_out && res == CURLE_OK && http_code == TDB_S3_HTTP_OK)
    {
        curl_off_t cl = 0;
        curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
        *size_out = (size_t)cl;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return -1;
    return (http_code == TDB_S3_HTTP_OK) ? 1 : 0;
}

/**
 * xml_find_tag
 * simple XML tag extraction for ListObjectsV2 response parsing
 * @param xml XML string to search in
 * @param tag tag name to find (without angle brackets)
 * @param value_len receives the length of the tag's text content
 * @return pointer to the start of the tag value, or NULL if not found
 */
static const char *xml_find_tag(const char *xml, const char *tag, size_t *value_len)
{
    char open_tag[TDB_S3_XML_TAG_BUF];
    snprintf(open_tag, sizeof(open_tag), "<%s>", tag);
    const char *start = strstr(xml, open_tag);
    if (!start) return NULL;
    start += strlen(open_tag);

    char close_tag[TDB_S3_XML_TAG_BUF];
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
    const char *end = strstr(start, close_tag);
    if (!end) return NULL;

    *value_len = end - start;
    return start;
}

/**
 * s3_response_buf_t
 * growable buffer for accumulating HTTP response data
 * @param data heap-allocated buffer holding response bytes
 * @param size number of bytes currently stored
 * @param capacity total allocated capacity of data buffer
 */
typedef struct
{
    char *data;
    size_t size;
    size_t capacity;
} s3_response_buf_t;

/**
 * s3_write_to_response
 * curl write callback that appends received data to a growable response buffer
 * @param ptr pointer to received data
 * @param size size of each element
 * @param nmemb number of elements
 * @param userdata pointer to s3_response_buf_t
 * @return number of bytes consumed, or 0 on allocation failure
 */
static size_t s3_write_to_response(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    s3_response_buf_t *buf = (s3_response_buf_t *)userdata;
    size_t bytes = size * nmemb;
    if (buf->size + bytes >= buf->capacity)
    {
        size_t new_cap = (buf->capacity + bytes) * 2;
        char *new_data = realloc(buf->data, new_cap);
        if (!new_data) return 0;
        buf->data = new_data;
        buf->capacity = new_cap;
    }
    memcpy(buf->data + buf->size, ptr, bytes);
    buf->size += bytes;
    buf->data[buf->size] = '\0';
    return bytes;
}

/**
 * s3_list
 * enumerate S3 objects under a key prefix using ListObjectsV2, handling pagination
 * @param ctx opaque S3 connector context
 * @param prefix key prefix to list (e.g. "cf_name/")
 * @param cb callback invoked for each object (key, size, cb_ctx)
 * @param cb_ctx opaque context passed to callback
 * @return number of objects listed, -1 on error
 */
static int s3_list(void *ctx, const char *prefix,
                   void (*cb)(const char *key, size_t size, void *cb_ctx), void *cb_ctx)
{
    s3_ctx_t *s3 = (s3_ctx_t *)ctx;
    int count = 0;
    char continuation_token[TDB_S3_CONT_TOKEN_MAX] = {0};

    do
    {
        char empty_sha[TDB_S3_HASH_HEX_LEN];
        sha256_hex("", 0, empty_sha);

        /* we build full prefix with connector prefix */
        char full_prefix[TDB_S3_MAX_PATH];
        if (s3->prefix[0])
            snprintf(full_prefix, sizeof(full_prefix), "%s%s", s3->prefix, prefix);
        else
            snprintf(full_prefix, sizeof(full_prefix), "%s", prefix);

        /* ListObjectsV2: prefix goes in query string, not in the URL path.
         * the canonical URI is just /<bucket> (path-style) or / (virtual-hosted).
         * the canonical query string must include all query parameters sorted
         * alphabetically with URI-encoded values per the SigV4 spec. */
        char url[TDB_S3_MAX_PATH * 2];
        const char *scheme = s3->use_ssl ? "https" : "http";

        /* URI-encode prefix and continuation token for query string */
        char encoded_prefix[TDB_S3_MAX_PATH * 3];
        s3_uri_encode(full_prefix, encoded_prefix, sizeof(encoded_prefix));

        char encoded_token[TDB_S3_CONT_TOKEN_MAX * 3];
        if (continuation_token[0])
            s3_uri_encode(continuation_token, encoded_token, sizeof(encoded_token));

        /* build canonical query string (params sorted alphabetically) */
        char canonical_qs[TDB_S3_MAX_PATH * 4];
        if (continuation_token[0])
            snprintf(canonical_qs, sizeof(canonical_qs),
                     "continuation-token=%s&list-type=2&prefix=%s", encoded_token, encoded_prefix);
        else
            snprintf(canonical_qs, sizeof(canonical_qs), "list-type=2&prefix=%s", encoded_prefix);

        if (s3->use_path_style)
        {
            snprintf(url, sizeof(url), "%s://%s/%s?%s", scheme, s3->endpoint, s3->bucket,
                     canonical_qs);
        }
        else
        {
            snprintf(url, sizeof(url), "%s://%s.%s/?%s", scheme, s3->bucket, s3->endpoint,
                     canonical_qs);
        }

        /* sign with the correct canonical URI (bucket path only, no object prefix) */
        char canonical_uri[TDB_S3_MAX_PATH];
        if (s3->use_path_style)
            snprintf(canonical_uri, sizeof(canonical_uri), "/%s", s3->bucket);
        else
            snprintf(canonical_uri, sizeof(canonical_uri), "/");

        struct curl_slist *headers =
            s3_sign_raw(s3, "GET", canonical_uri, canonical_qs, empty_sha, NULL, NULL);

        s3_response_buf_t resp = {
            .data = malloc(TDB_S3_RESPONSE_INIT), .size = 0, .capacity = TDB_S3_RESPONSE_INIT};

        CURL *curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, s3_write_to_response);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

        CURLcode res = curl_easy_perform(curl);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK || http_code != TDB_S3_HTTP_OK)
        {
            free(resp.data);
            return count > 0 ? count : -1;
        }

        /* we parse XML response for <Key> and <Size> tags within <Contents> */
        const char *pos = resp.data;
        while ((pos = strstr(pos, "<Contents>")) != NULL)
        {
            const char *end = strstr(pos, "</Contents>");
            if (!end) break;

            size_t key_len = 0, size_len = 0;
            const char *key_val = xml_find_tag(pos, "Key", &key_len);
            const char *size_val = xml_find_tag(pos, "Size", &size_len);

            if (key_val && key_len > 0)
            {
                char key_buf[TDB_S3_MAX_PATH];
                size_t copy_len = key_len < sizeof(key_buf) - 1 ? key_len : sizeof(key_buf) - 1;
                memcpy(key_buf, key_val, copy_len);
                key_buf[copy_len] = '\0';

                /* we strip the connector prefix to get relative key */
                const char *relative = key_buf;
                if (s3->prefix[0] && strncmp(relative, s3->prefix, strlen(s3->prefix)) == 0)
                {
                    relative += strlen(s3->prefix);
                }

                size_t obj_size = 0;
                if (size_val && size_len > 0)
                {
                    char size_buf[TDB_S3_SIZE_BUF];
                    size_t sl = size_len < sizeof(size_buf) - 1 ? size_len : sizeof(size_buf) - 1;
                    memcpy(size_buf, size_val, sl);
                    size_buf[sl] = '\0';
                    obj_size = (size_t)strtoull(size_buf, NULL, 10);
                }

                cb(relative, obj_size, cb_ctx);
                count++;
            }

            pos = end + 1;
        }

        /* we check for truncation (pagination) */
        continuation_token[0] = '\0';
        size_t ct_len = 0;
        const char *ct = xml_find_tag(resp.data, "NextContinuationToken", &ct_len);
        if (ct && ct_len > 0 && ct_len < TDB_S3_CONT_TOKEN_MAX)
        {
            memcpy(continuation_token, ct, ct_len);
            continuation_token[ct_len] = '\0';
        }

        /* we check IsTruncated */
        size_t trunc_len = 0;
        const char *trunc = xml_find_tag(resp.data, "IsTruncated", &trunc_len);
        int is_truncated = (trunc && trunc_len == 4 && memcmp(trunc, "true", 4) == 0);

        free(resp.data);

        if (!is_truncated) break;

    } while (1);

    return count;
}

/**
 * s3_destroy
 * free S3 connector resources
 * @param ctx opaque S3 connector context to free
 */
static void s3_destroy(void *ctx)
{
    free(ctx);
}

tidesdb_objstore_t *tidesdb_objstore_s3_create(const char *endpoint, const char *bucket,
                                               const char *prefix, const char *access_key,
                                               const char *secret_key, const char *region,
                                               int use_ssl, int use_path_style)
{
    if (!endpoint || !bucket || !access_key || !secret_key) return NULL;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    s3_ctx_t *s3 = calloc(1, sizeof(s3_ctx_t));
    if (!s3) return NULL;

    snprintf(s3->endpoint, sizeof(s3->endpoint), "%s", endpoint);
    snprintf(s3->bucket, sizeof(s3->bucket), "%s", bucket);
    if (prefix) snprintf(s3->prefix, sizeof(s3->prefix), "%s", prefix);
    snprintf(s3->access_key, sizeof(s3->access_key), "%s", access_key);
    snprintf(s3->secret_key, sizeof(s3->secret_key), "%s", secret_key);
    snprintf(s3->region, sizeof(s3->region), "%s", region ? region : TDB_S3_DEFAULT_REGION);
    s3->use_ssl = use_ssl;
    s3->use_path_style = use_path_style;

    tidesdb_objstore_t *store = calloc(1, sizeof(tidesdb_objstore_t));
    if (!store)
    {
        free(s3);
        return NULL;
    }

    store->backend = TDB_BACKEND_S3;
    store->put = s3_put;
    store->get = s3_get;
    store->range_get = s3_range_get;
    store->delete_object = s3_delete_object;
    store->exists = s3_exists;
    store->list = s3_list;
    store->destroy = s3_destroy;
    store->ctx = s3;

    return store;
}

#endif /* TIDESDB_WITH_S3 */
