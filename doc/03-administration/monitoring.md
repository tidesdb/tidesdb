---
title: Monitoring
description: Which of the statistics actually matter, what healthy looks like, and what to alert on.
slug: administration/monitoring
part: administration
sidebar:
  order: 3
---

# Monitoring

The statistics calls expose several dozen fields across seven structures. Most are diagnostic
detail you will look at once while investigating something. A much smaller set tells you whether
the database is healthy, and those are the ones to sample continuously.

Every call fills a caller-owned struct by value. Nothing allocates, nothing needs freeing.

## The five numbers to watch

If you graph nothing else, graph these.

### 1. `write_stall_ceiling_hits` — from `tidesdb_get_db_stats`

**Healthy: zero. Alert on any sustained increase.**

This counts writers admitted *only because the backpressure wait ceiling expired* — the engine
gave up waiting for flush to drain and let the write through anyway, to keep a stuck flush from
becoming a stuck database.

A non-zero value means ingest has outrun flush badly enough that the safety valve is operating.
It is the clearest single signal that the write path is in trouble.

### 2. `immutable_memtable_count` — from `tidesdb_get_db_stats`

**Healthy: near zero, spiking briefly.**

Sealed memtables waiting to be flushed. Brief spikes under load are normal. A count that sits
persistently above zero means flush is not keeping up with ingest, and it is the leading
indicator for the stalls above — you will see this climb before writers start being held.

### 3. Cache `hit_rate` — from `tidesdb_get_cache_stats`

**Healthy: depends on your workload; watch the trend, not the value.**

A falling hit rate on a stable workload means the working set has outgrown the cache. Because
it is cumulative since open, it moves slowly — **compare deltas between two samples** rather
than reading the absolute number.

### 4. `read_amp` — from `tidesdb_get_cf_stats`, per family

**Healthy: low and stable.**

An estimate of how many sstables a point lookup consults. Rising `read_amp` means compaction is
falling behind flush for that family, and it translates directly into read latency.

### 5. `min_snapshot_seq` versus `global_seq` — from `tidesdb_get_db_stats`

**Healthy: a small and stable gap.**

`min_snapshot_seq` is the oldest snapshot any live transaction holds. Compaction may not
reclaim anything above it. A widening gap means a long-running transaction is pinning old
versions, and it is the usual cause of disk usage that will not fall despite deletes.

This is the one people miss, because the symptom — space not reclaiming — looks like a
compaction problem rather than an application one.

A **named snapshot** holds the floor the same way and is not distinguishable from a transaction
here, because it is one. If the gap is wide and no transaction is outstanding, look for a snapshot
that was never released — `tidesdb_snapshot_seq` says which sequence each one is holding, and one
of them will match `min_snapshot_seq`.

If the application cannot guarantee every transaction is resolved, bound them rather than watch
for it: `txn_timeout_seconds` on the database, or
[`tidesdb_txn_set_timeout`](/reference/transaction#tidesdb_txn_set_timeout) on the ones that might
be left open. A bounded transaction is aborted by the next operation on it once its deadline has
passed, which releases the snapshot it was holding.

## Write amplification

From `tidesdb_get_cf_stats`, all cumulative since open:

```
  write_amp = (wal_bytes_written + flush_bytes_written + compaction_bytes_written)
              / user_bytes_written
```

This is the multiplier between what you wrote and what reached the device. An LSM tree always
has some; what matters is the trend and whether it is proportionate to your workload. Rising
write amplification on a stable workload usually means compaction triggers are set too eagerly.

## Backpressure, in full

Four fields, and the order tells a story:

| Field | Meaning |
| --- | --- |
| `writes_throttled` | Writers made to dwell before admission |
| `writes_blocked` | Writers made to wait for the queue to drain |
| `write_stall_us` | Total time writers spent held |
| `write_stall_ceiling_hits` | Writers admitted only because the ceiling expired |

All zero means ingest is comfortably within what flush absorbs. Throttling alone is the system
working as designed. Blocking means it is at the limit. Ceiling hits mean it has been past the
limit long enough that the safety valve fired.

## Space

| Field | From | Watch for |
| --- | --- | --- |
| `total_data_size_bytes` | db stats | Key-log bytes across every family. The value log is separate — add `vlog_file_size` for the whole store |
| `vlog_file_size` vs `vlog_used_bytes` | db stats | The gap is reclaimable value-log space |
| `tombstone_ratio` | cf stats | Persistently high means deletes are outrunning compaction |
| `unflushed_key_count` | cf stats | Distinct keys only in memory — what a crash would replay |

## Sampling

Sample every 10 to 30 seconds. The counters are cumulative, so store deltas as well as values —
`hit_rate` and the write-amplification ratio are meaningless as instantaneous readings.

Samples are taken without stopping the engine, so fields can be very slightly inconsistent with
each other; a flush may land between two of them being read. They are for monitoring and
capacity planning, not for making transactional decisions.

## A minimal health check

```c
/* queue depth above this is a backlog worth reporting, and a snapshot this far behind the
   current sequence means something is holding reclamation back */
#define QUEUE_BACKLOG      4
#define SNAPSHOT_LAG_LIMIT 100000

static uint64_t last_ceiling_hits = 0;

tidesdb_db_stats_t s;
if (tidesdb_get_db_stats(db, &s) == TDB_SUCCESS)
{
    if (s.write_stall_ceiling_hits > last_ceiling_hits)
        fprintf(stderr, "flush is not keeping up with ingest\n");

    if (s.immutable_memtable_count > QUEUE_BACKLOG)
        fprintf(stderr, "flush queue backing up: %d\n", s.immutable_memtable_count);

    if (s.global_seq - s.min_snapshot_seq > SNAPSHOT_LAG_LIMIT)
        fprintf(stderr, "a long-running transaction is holding back reclamation\n");

    last_ceiling_hits = s.write_stall_ceiling_hits;
}
```
