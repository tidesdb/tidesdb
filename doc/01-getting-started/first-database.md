---
title: Your First Database
description: A complete program -- open, write in a transaction, read it back, iterate, and close.
slug: getting-started
part: getting-started
sidebar:
  order: 1
---

# Your First Database

This chapter is one working program, built up a piece at a time. Everything here compiles
against the real header — the samples in this manual are compiled as part of the build.

If you have not built TidesDB yet, see [Building](/administration/building). The short version:

```sh
cmake -S . -B build && cmake --build build -j && cmake --install build
```

## The model in five sentences

A **database** is a directory. Inside it are **column families**, each an independent ordered
keyspace. All reads and writes happen inside a **transaction** — there is no non-transactional
path. Keys and values are arbitrary bytes, ordered by `memcmp`. A transaction sees a consistent
snapshot and commits atomically, including across several families.

## Opening

```c
#include <tidesdb/db.h>
#include <stdio.h>

int main(void)
{
    tidesdb_config_t config = tidesdb_default_config();
    config.db_path = "/tmp/mydb";

    tidesdb_t *db = NULL;
    int rc = tidesdb_open(&config, &db);
    if (rc != TDB_SUCCESS)
    {
        fprintf(stderr, "open failed: %d\n", rc);
        return 1;
    }

    tidesdb_close(db);
    return 0;
}
```

Start from `tidesdb_default_config()` and change what you need. Only `db_path` has no default.
The directory is created if it does not exist, and opening an existing one recovers it.

## Creating a column family

```c
tidesdb_column_family_config_t cf_config = tidesdb_default_column_family_config();

int rc = tidesdb_create_column_family(db, "users", &cf_config);
if (rc != TDB_SUCCESS && rc != TDB_ERR_EXISTS) return 1;

tidesdb_column_family_t *cf = tidesdb_get_column_family(db, "users");
```

`TDB_ERR_EXISTS` on the second run is expected, not a failure — creating a family is idempotent
if you treat it that way. The handle is **borrowed**: owned by the database, valid until the
family is dropped or the database closes. Do not free it.

## Writing

```c
tidesdb_txn_t *txn = NULL;
if (tidesdb_txn_begin(db, &txn) != TDB_SUCCESS) return 1;

const char *key = "user:1";
const char *val = "alice";

tidesdb_txn_put(txn, cf, (const uint8_t *)key, 6, (const uint8_t *)val, 5, 0);

int rc = tidesdb_txn_commit(txn);
tidesdb_txn_free(txn);
```

Three things worth noticing:

- The write is **buffered** until commit. Nothing is durable or visible until `commit` returns
  success.
- The final `0` is the expiry: a **lifetime in seconds**, where zero or negative means never.
  To expire in an hour, pass `3600`.
- `tidesdb_txn_free` is required **even after a successful commit**. Committing does not free.

## Handling conflicts

The default isolation level is **read-committed**, which does not check for conflicts. A commit
at that level succeeds if the I/O succeeds, and a write that races another transaction's write to
the same key simply overwrites it. For appending independent records that is exactly what you
want. For read-modify-write — a counter, a balance, anything derived from what you just read — it
silently loses updates.

Ask for the checking by naming the level:

```c
for (int attempt = 0; attempt < MAX_RETRIES; attempt++)
{
    tidesdb_txn_t *txn = NULL;
    if (tidesdb_txn_begin_with_isolation(db, TDB_ISOLATION_SNAPSHOT, &txn) != TDB_SUCCESS) break;

    tidesdb_txn_put(txn, cf, (const uint8_t *)"user:1", 6, (const uint8_t *)"alice", 5, 0);

    int rc = tidesdb_txn_commit(txn);
    tidesdb_txn_free(txn);

    if (rc != TDB_ERR_CONFLICT) break;   /* success, or a real failure */
}
```

At snapshot and serializable, **a commit can fail because another transaction got there first**.
That is not an error to log and move past; it is a normal outcome you retry, and the retry must
redo the reads as well as the writes, since the reads it was validated against are now stale.

Write this loop once, early. Code that ignores `TDB_ERR_CONFLICT` works perfectly in single-
threaded testing and drops writes the moment it is used concurrently.

## Reading

```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin(db, &txn);

uint8_t *value = NULL;
size_t value_size = 0;

int rc = tidesdb_txn_get(txn, cf, (const uint8_t *)"user:1", 6, &value, &value_size);
if (rc == TDB_SUCCESS)
{
    printf("%.*s\n", (int)value_size, value);
    tidesdb_free(value);
}

tidesdb_txn_commit(txn);
tidesdb_txn_free(txn);
```

The value is **yours** and is released with `tidesdb_free` — not your own `free`, because the
engine may be built against a different allocator.

Two error codes to distinguish carefully:

- `TDB_ERR_NOT_FOUND` — the key genuinely is not there.
- `TDB_ERR_LOCKED` — transient contention. **Retry.** Treating it as absent is a correctness
  bug, not a missed optimisation.

## Iterating

```c
tidesdb_txn_t *txn = NULL;
tidesdb_txn_begin(db, &txn);

tidesdb_iter_t *it = NULL;
if (tidesdb_iter_new(txn, cf, &it) == TDB_SUCCESS)
{
    for (tidesdb_iter_seek_to_first(it); tidesdb_iter_valid(it); tidesdb_iter_next(it))
    {
        uint8_t *k = NULL, *v = NULL;
        size_t klen = 0, vlen = 0;

        if (tidesdb_iter_key_value(it, &k, &klen, &v, &vlen) != TDB_SUCCESS) break;

        printf("%.*s = %.*s\n", (int)klen, k, (int)vlen, v);

        tidesdb_free(k);
        tidesdb_free(v);
    }
    tidesdb_iter_free(it);
}

tidesdb_txn_commit(txn);
tidesdb_txn_free(txn);
```

The iterator reads at the transaction's snapshot, so it is stable — concurrent commits,
flushes, and compactions do not disturb it. `tidesdb_iter_valid` is the loop condition; the
return value of `next` is not.

Free the iterator before the transaction it came from.

## Prefix scans

There is no separate prefix API. Seek to the prefix and walk while it still matches:

```c
tidesdb_iter_seek(it, (const uint8_t *)"user:", 5);

while (tidesdb_iter_valid(it))
{
    uint8_t *k = NULL;
    size_t klen = 0;
    if (tidesdb_iter_key(it, &k, &klen) != TDB_SUCCESS) break;

    const int matches = (klen >= 5 && memcmp(k, "user:", 5) == 0);
    tidesdb_free(k);
    if (!matches) break;

    tidesdb_iter_next(it);
}
```

This works because keys are ordered by `memcmp`, so everything sharing a prefix is contiguous.
That same property is why there are no custom comparators: encode your keys to sort correctly
as bytes — big-endian integers, sign-flipped signed values — and ordering follows.

## Rules worth learning now

| Rule | Why |
| --- | --- |
| Free every transaction, even after a successful commit | Commit does not free the handle |
| Free iterators before their transaction | The iterator borrows it |
| Use `tidesdb_free` for engine-returned buffers | The engine may use a different allocator |
| Choose an isolation level deliberately | The default is read-committed, which does not detect conflicts |
| Retry `TDB_ERR_CONFLICT` | It is the normal outcome of a write race at snapshot isolation |
| Retry `TDB_ERR_LOCKED`, never treat it as absent | It means "ask again", not "not there" |
| `ttl` is a lifetime in seconds | The clock starts at the `put`, not at the commit |

## Where to go next

[Concepts](/concepts/data-model) explains the model properly — isolation levels, durability
modes, and key/value separation. The [C API Reference](/reference/database) documents every
function. [Administration](/administration/building) covers running it.
