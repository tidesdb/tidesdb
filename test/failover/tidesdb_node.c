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

/*
 * tidesdb_node -- a minimal network node wrapping libtidesdb, the unit under test for the
 * object-store failover harness. one process is one cluster node (primary or replica) pointed
 * at a shared bucket. it speaks a tiny line protocol over TCP so the scenario driver can write,
 * read, promote, flush, and inspect lease state without pulling in a full server.
 *
 * line protocol (one request per line, one reply line):
 *   PING                -> PONG
 *   PUT <key> <value>   -> OK | ERR <code>          (value is the rest of the line)
 *   GET <key>           -> VAL <value> | NF | ERR <code>
 *   DEL <key>           -> OK | ERR <code>
 *   FLUSH               -> OK | ERR <code>          (flush + compact, forces a manifest publish)
 *   PROMOTE             -> OK <epoch> | ERR <code>
 *   STAT                -> replica_mode=<0|1> primary_epoch=<n> fencing=<0|1> seq=<n>
 *   QUIT                -> closes the connection
 *
 * configuration is via environment:
 *   TDB_NODE_PORT                 TCP listen port (required)
 *   TDB_NODE_DATA_DIR             local data directory (required)
 *   TDB_NODE_BUCKET               FS bucket directory (required for the fs backend)
 *   TDB_NODE_BACKEND              fs (default) | s3
 *   TDB_NODE_REPLICA              0 primary (default) | 1 replica
 *   TDB_NODE_CF                   column family name (default "data")
 *   TDB_NODE_WAL_SYNC_ON_COMMIT   0 | 1 (default 1, RPO=0)
 *   TDB_NODE_REPLICA_SYNC_US      replica poll interval (default 500000)
 *   TDB_NODE_ID                   label used in log lines (default the port)
 * for the s3 backend: TIDESDB_S3_ENDPOINT, TIDESDB_S3_BUCKET, TIDESDB_S3_ACCESS_KEY,
 * TIDESDB_S3_SECRET_KEY (matching the existing object-store CI workflow).
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "objstore.h"
#include "tidesdb.h"

#define NODE_LINE_MAX (64 * 1024)

static tidesdb_t *g_db = NULL;
static const char *g_cf_name = "data";
static const char *g_node_id = "node";
static volatile sig_atomic_t g_running = 1;

static void node_log(const char *msg)
{
    fprintf(stderr, "[node %s] %s\n", g_node_id, msg);
    fflush(stderr);
}

static const char *env_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);
    return (v && v[0]) ? v : fallback;
}

/* build the object store connector from the environment, or NULL on misconfiguration */
static tidesdb_objstore_t *node_make_store(void)
{
    const char *backend = env_or("TDB_NODE_BACKEND", "fs");
    if (strcmp(backend, "fs") == 0)
    {
        const char *bucket = getenv("TDB_NODE_BUCKET");
        if (!bucket || !bucket[0])
        {
            node_log("TDB_NODE_BUCKET is required for the fs backend");
            return NULL;
        }
        return tidesdb_objstore_fs_create(bucket);
    }
#ifdef TIDESDB_WITH_S3
    if (strcmp(backend, "s3") == 0)
    {
        return tidesdb_objstore_s3_create(env_or("TIDESDB_S3_ENDPOINT", "localhost:9000"),
                                          env_or("TIDESDB_S3_BUCKET", "tidesdb-test"), "",
                                          env_or("TIDESDB_S3_ACCESS_KEY", "minioadmin"),
                                          env_or("TIDESDB_S3_SECRET_KEY", "minioadmin"), 0, 1);
    }
#endif
    node_log("unsupported TDB_NODE_BACKEND");
    return NULL;
}

/* open the database and ensure the column family exists (a fresh primary creates it; a replica
 * lets cold-start discovery pull it from the bucket, so a missing CF is not fatal there) */
static int node_open(void)
{
    tidesdb_objstore_t *store = node_make_store();
    if (!store) return -1;

    int replica = atoi(env_or("TDB_NODE_REPLICA", "0"));

    static tidesdb_objstore_config_t os_cfg;
    os_cfg = tidesdb_objstore_default_config();
    os_cfg.replica_mode = replica;
    os_cfg.replicate_wal = 1;
    os_cfg.wal_sync_on_commit = atoi(env_or("TDB_NODE_WAL_SYNC_ON_COMMIT", "1"));
    os_cfg.replica_sync_interval_us =
        (uint64_t)strtoull(env_or("TDB_NODE_REPLICA_SYNC_US", "500000"), NULL, 10);

    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = (char *)getenv("TDB_NODE_DATA_DIR");
    config.object_store = store;
    config.object_store_config = &os_cfg;

    /* a small write buffer lets a modest test workload roll over many memtables, so the bucket
     * accrues many sstables and WAL generations to fence and replay (0 = library default) */
    size_t wb = (size_t)strtoull(env_or("TDB_NODE_WRITE_BUFFER", "0"), NULL, 10);
    if (wb > 0) config.unified_memtable_write_buffer_size = wb;

    if (tidesdb_open(&config, &g_db) != 0)
    {
        node_log("tidesdb_open failed");
        return -1;
    }

    if (!replica)
    {
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        if (tidesdb_get_column_family(g_db, g_cf_name) == NULL)
            tidesdb_create_column_family(g_db, g_cf_name, &cf_config);
    }
    return 0;
}

static void reply(int fd, const char *s)
{
    size_t len = strlen(s);
    (void)write(fd, s, len);
    (void)write(fd, "\n", 1);
}

static void handle_put(int fd, char *args)
{
    char *sp = strchr(args, ' ');
    if (!sp)
    {
        reply(fd, "ERR -2");
        return;
    }
    *sp = '\0';
    const char *key = args;
    const char *val = sp + 1;

    tidesdb_column_family_t *cf = tidesdb_get_column_family(g_db, g_cf_name);
    if (!cf)
    {
        reply(fd, "ERR -3");
        return;
    }

    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin(g_db, &txn) != 0)
    {
        reply(fd, "ERR -11");
        return;
    }
    int rc = tidesdb_txn_put(txn, cf, (const uint8_t *)key, strlen(key) + 1, (const uint8_t *)val,
                             strlen(val) + 1, 0);
    if (rc == 0) rc = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);

    if (rc == 0)
        reply(fd, "OK");
    else
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "ERR %d", rc);
        reply(fd, buf);
    }
}

static void handle_get(int fd, const char *key)
{
    tidesdb_column_family_t *cf = tidesdb_get_column_family(g_db, g_cf_name);
    if (!cf)
    {
        reply(fd, "ERR -3");
        return;
    }

    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin(g_db, &txn) != 0)
    {
        reply(fd, "ERR -11");
        return;
    }
    uint8_t *val = NULL;
    size_t val_size = 0;
    int rc = tidesdb_txn_get(txn, cf, (const uint8_t *)key, strlen(key) + 1, &val, &val_size);
    tidesdb_txn_free(txn);

    if (rc == 0 && val)
    {
        char *line = malloc(val_size + 8);
        if (line)
        {
            snprintf(line, val_size + 8, "VAL %s", (char *)val);
            reply(fd, line);
            free(line);
        }
        else
            reply(fd, "ERR -1");
        free(val);
    }
    else if (rc == TDB_ERR_NOT_FOUND)
        reply(fd, "NF");
    else
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "ERR %d", rc);
        reply(fd, buf);
    }
}

static void handle_del(int fd, const char *key)
{
    tidesdb_column_family_t *cf = tidesdb_get_column_family(g_db, g_cf_name);
    if (!cf)
    {
        reply(fd, "ERR -3");
        return;
    }
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin(g_db, &txn) != 0)
    {
        reply(fd, "ERR -11");
        return;
    }
    int rc = tidesdb_txn_delete(txn, cf, (const uint8_t *)key, strlen(key) + 1);
    if (rc == 0) rc = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);

    if (rc == 0)
        reply(fd, "OK");
    else
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "ERR %d", rc);
        reply(fd, buf);
    }
}

/* flush the memtable into a new sstable, which also publishes the fenced manifest. compaction is
 * left to the background engine -- forcing a full compact here only slows the harness. */
static void handle_flush(int fd)
{
    tidesdb_column_family_t *cf = tidesdb_get_column_family(g_db, g_cf_name);
    if (!cf)
    {
        reply(fd, "ERR -3");
        return;
    }
    int rc = tidesdb_flush_memtable(cf);
    if (rc == 0)
        reply(fd, "OK");
    else
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "ERR %d", rc);
        reply(fd, buf);
    }
}

static void handle_promote(int fd)
{
    int rc = tidesdb_promote_to_primary(g_db);
    if (rc == 0)
    {
        /* a promoted node creates the CF locally if cold-start has not surfaced it yet */
        tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();
        if (tidesdb_get_column_family(g_db, g_cf_name) == NULL)
            tidesdb_create_column_family(g_db, g_cf_name, &cf_config);

        tidesdb_db_stats_t st;
        char buf[64];
        if (tidesdb_get_db_stats(g_db, &st) == 0)
            snprintf(buf, sizeof(buf), "OK %llu", (unsigned long long)st.primary_epoch);
        else
            snprintf(buf, sizeof(buf), "OK 0");
        reply(fd, buf);
    }
    else
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "ERR %d", rc);
        reply(fd, buf);
    }
}

static void handle_stat(int fd)
{
    tidesdb_db_stats_t st;
    if (tidesdb_get_db_stats(g_db, &st) != 0)
    {
        reply(fd, "ERR -1");
        return;
    }
    char buf[192];
    snprintf(buf, sizeof(buf),
             "replica_mode=%d primary_epoch=%llu seq=%llu sstables=%d walgen=%llu", st.replica_mode,
             (unsigned long long)st.primary_epoch, (unsigned long long)st.global_seq,
             st.total_sstable_count, (unsigned long long)st.unified_wal_generation);
    reply(fd, buf);
}

static void *conn_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    char *line = malloc(NODE_LINE_MAX);
    if (!line)
    {
        close(fd);
        return NULL;
    }

    size_t used = 0;
    char rbuf[4096];
    for (;;)
    {
        ssize_t n = read(fd, rbuf, sizeof(rbuf));
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++)
        {
            char c = rbuf[i];
            if (c == '\n' || used == NODE_LINE_MAX - 1)
            {
                line[used] = '\0';
                used = 0;

                /* strip a trailing CR so CRLF clients work */
                size_t L = strlen(line);
                if (L && line[L - 1] == '\r') line[L - 1] = '\0';

                char *args = strchr(line, ' ');
                if (args) *args++ = '\0';

                if (strcmp(line, "PING") == 0)
                    reply(fd, "PONG");
                else if (strcmp(line, "PUT") == 0 && args)
                    handle_put(fd, args);
                else if (strcmp(line, "GET") == 0 && args)
                    handle_get(fd, args);
                else if (strcmp(line, "DEL") == 0 && args)
                    handle_del(fd, args);
                else if (strcmp(line, "FLUSH") == 0)
                    handle_flush(fd);
                else if (strcmp(line, "PROMOTE") == 0)
                    handle_promote(fd);
                else if (strcmp(line, "STAT") == 0)
                    handle_stat(fd);
                else if (strcmp(line, "QUIT") == 0)
                    goto done;
                else
                    reply(fd, "ERR -2");
            }
            else if (c != '\r')
            {
                line[used++] = c;
            }
        }
    }
done:
    free(line);
    close(fd);
    return NULL;
}

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    g_cf_name = env_or("TDB_NODE_CF", "data");
    const char *port_s = getenv("TDB_NODE_PORT");
    if (!port_s)
    {
        fprintf(stderr, "TDB_NODE_PORT is required\n");
        return 2;
    }
    g_node_id = env_or("TDB_NODE_ID", port_s);

    if (node_open() != 0) return 1;
    node_log("opened");

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0)
    {
        node_log("socket failed");
        return 1;
    }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)atoi(port_s));

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        node_log("bind failed");
        return 1;
    }
    if (listen(srv, 64) != 0)
    {
        node_log("listen failed");
        return 1;
    }
    node_log("listening");

    while (g_running)
    {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        pthread_t t;
        if (pthread_create(&t, NULL, conn_thread, (void *)(intptr_t)fd) == 0)
            pthread_detach(t);
        else
            close(fd);
    }

    close(srv);
    tidesdb_close(g_db);
    node_log("closed");
    return 0;
}
