/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "l0_adapter.h"

/* a post-log apply retries a transient failure rather than abandoning an entry the log has already
 * committed; the product bounds the wait so a genuinely stuck apply still surfaces */
#define TDB_L0_APPLY_MAX_ATTEMPTS   100
#define TDB_L0_APPLY_RETRY_STALL_US 100

#include <stdlib.h>

#include "base/errors.h" /* TDB_SUCCESS, TDB_ERR_BUSY */
#include "base/log.h"
#include "compat.h"                             /* usleep */
#include "datastructures/skip_list/skip_list.h" /* SKIP_LIST_FLAG_* */
#include "io/block_manager.h"                   /* the WAL cursor for replay */
#include "wal_record.h"                         /* tidesdb_wal_entry_t and its flag bits */

/* how many entry slots a staged PREPARE's decode buffer starts with before doubling */
#define L0_REPLAY_PREPARE_INIT_ENTRIES 16

/* translate a WAL entry's flags into the skip_list flags the memtable stores */
static uint8_t l0_adapter_flags(uint8_t wal_flags)
{
    uint8_t flags = 0;
    if (wal_flags & TDB_WAL_ENTRY_TOMBSTONE) flags |= SKIP_LIST_FLAG_DELETED;
    if (wal_flags & TDB_WAL_ENTRY_SINGLE_DELETE) flags |= SKIP_LIST_FLAG_SINGLE_DELETE;
    return flags;
}

static tidesdb_source_result_t l0_source_get(void *ctx, uint32_t cf_index, const uint8_t *key,
                                             size_t key_size, uint64_t snapshot,
                                             tidesdb_source_version_t *out)
{
    tidesdb_l0_txn_ctx_t *actx = (tidesdb_l0_txn_ctx_t *)ctx;

    uint8_t *value = NULL;
    size_t value_size = 0;
    uint64_t vlog_id = 0;
    int64_t ttl = -1;
    uint8_t deleted = 0;
    uint64_t seq = 0;
    const int rc = tidesdb_l0_get_at_seq(actx->l0, cf_index, key, key_size, snapshot, &value,
                                         &value_size, &vlog_id, &ttl, &deleted, &seq);
    if (rc == TDB_SUCCESS)
    {
        /* a live value the commit separated is held here as an id, so this source resolves it the
         * way the sstable source resolves its own -- a source hands back bytes, never a reference,
         * so the layers above it see one kind of answer */
        if (!deleted && vlog_id != 0)
        {
            uint8_t *resolved = NULL;
            size_t resolved_len = 0;
            if (!actx->vlog || vlog_read(actx->vlog, vlog_id, &resolved, &resolved_len) != VLOG_OK)
                return TDB_SOURCE_BUSY;
            free(value);
            value = resolved;
            value_size = resolved_len;
        }
        out->seq = seq;
        out->value = value;
        out->value_size = value_size;
        out->ttl = ttl;
        out->deleted = deleted;
        return TDB_SOURCE_FOUND;
    }
    if (rc == TDB_ERR_NOT_FOUND) return TDB_SOURCE_NOT_FOUND;
    /* a busy slot or any transient error is retryable, never a definitive miss */
    return TDB_SOURCE_BUSY;
}

/* pace one writer against L0 fill before its batch is made durable. the L0 queue is db-level and
 * shared by every family, so the cf the write targets does not select the pressure; the l0 owns the
 * queue and does the waiting, leaving the adapter a forward */
static int l0_backend_backpressure(void *ctx, uint32_t cf_index)
{
    (void)cf_index;
    tidesdb_l0_txn_ctx_t *actx = (tidesdb_l0_txn_ctx_t *)ctx;
    return tidesdb_l0_admit_write(actx->l0) == TDB_SUCCESS ? 0 : -1;
}

static int l0_backend_wal_append(void *ctx, const uint8_t *batch, size_t size)
{
    tidesdb_l0_txn_ctx_t *actx = (tidesdb_l0_txn_ctx_t *)ctx;
    /* concurrent commits coalesce in the WAL's append ring, each staging and waiting for its own
     * record, rather than one of them appending for all the others while they wait on it */
    return tidesdb_l0_wal_append_one(actx->l0, batch, size) == TDB_SUCCESS ? 0 : -1;
}

/* apply one decoded entry, dispatching on what kind of write it holds -- a range delete covering
 * an interval, a value the commit separated into the value log, or the bytes carried inline. the
 * range delete is tested first because it also carries the tombstone bit, which is what lets a
 * reader that does not know the bit still see a valueless delete rather than a live put */
static int l0_apply_one(tidesdb_l0_t *l0, const tidesdb_wal_entry_t *e, const int64_t ttl)
{
    /* an interval delete's upper bound rides in the value field, and an empty one is open above */
    if (e->flags & TDB_WAL_ENTRY_RANGE_DELETE)
        return tidesdb_l0_apply_range_tombstone(l0, e->cf_index, e->key, e->key_size, e->value,
                                                e->value_size, e->seq);
    if (e->flags & TDB_WAL_ENTRY_VLOG_REF)
        return tidesdb_l0_apply_reference(l0, e->cf_index, e->key, e->key_size, e->vlog_id,
                                          e->value_size, ttl, e->seq, l0_adapter_flags(e->flags));
    return tidesdb_l0_apply(l0, e->cf_index, e->key, e->key_size, e->value, e->value_size, ttl,
                            e->seq, l0_adapter_flags(e->flags));
}

int tidesdb_l0_apply_entries(tidesdb_l0_t *l0, const tidesdb_wal_entry_t *entries, int count)
{
    if (!l0 || (count > 0 && !entries)) return TDB_ERR_INVALID_ARGS;
    for (int i = 0; i < count; i++)
    {
        const tidesdb_wal_entry_t *e = &entries[i];
        const int64_t ttl = (e->flags & TDB_WAL_ENTRY_HAS_TTL) ? e->ttl : -1;

        /* this batch is already durable in the log when a commit calls it, and replay applies a
         * write batch whole with no commit marker to consult -- so the record's presence is the
         * commitment, and nothing this function does undoes it. an abandoned entry also stays in
         * the skip list where a later reader can see it. both failures are transient by
         * construction, a lost race with rotation or momentary allocation pressure, so the entry is
         * retried rather than abandoned. retrying resumes at the entry that failed, since the ones
         * before it landed. only when every attempt fails does the caller cancel the batch, by
         * appending an abort record naming its sequence and abandoning what landed */
        int rc = TDB_SUCCESS;
        for (int attempt = 0; attempt < TDB_L0_APPLY_MAX_ATTEMPTS; attempt++)
        {
            rc = l0_apply_one(l0, e, ttl);
            if (rc == TDB_SUCCESS) break;
            /* only the transient causes are worth another attempt; a malformed entry fails the same
             * way every time and retrying it just delays the report */
            if (rc != TDB_ERR_BUSY && rc != TDB_ERR_MEMORY) break;
            usleep(TDB_L0_APPLY_RETRY_STALL_US);
        }
        if (rc != TDB_SUCCESS)
        {
            /* the durable and in-memory views have diverged and this entry is the boundary, so it
             * is worth naming rather than folding into the caller's error */
            TDB_DEBUG_LOG(TDB_LOG_ERROR,
                          "apply of a durable batch failed rc=%d at entry %d of %d, seq %llu", rc,
                          i, count, (unsigned long long)e->seq);
            return rc;
        }
    }
    return TDB_SUCCESS;
}

static void l0_backend_abandon(void *ctx, uint64_t seq)
{
    tidesdb_l0_txn_ctx_t *actx = (tidesdb_l0_txn_ctx_t *)ctx;
    if (tidesdb_l0_mark_aborted(actx->l0, seq) != TDB_SUCCESS)
        TDB_DEBUG_LOG(
            TDB_LOG_ERROR,
            "could not hide abandoned batch seq %llu, its entries stay readable until the "
            "next open",
            (unsigned long long)seq);
}

static int l0_backend_apply(void *ctx, const tidesdb_wal_entry_t *entries, int count)
{
    tidesdb_l0_txn_ctx_t *actx = (tidesdb_l0_txn_ctx_t *)ctx;
    return tidesdb_l0_apply_entries(actx->l0, entries, count) == TDB_SUCCESS ? 0 : -1;
}

/* the interval probe over L0, for a commit checking a prefix delete against what the memtables hold
 */
static tidesdb_source_result_t l0_source_range_has_newer(void *ctx, uint32_t cf_index,
                                                         const uint8_t *lo, size_t lo_size,
                                                         const uint8_t *hi, size_t hi_size,
                                                         uint64_t seq_floor, int *newer)
{
    tidesdb_l0_txn_ctx_t *actx = (tidesdb_l0_txn_ctx_t *)ctx;
    const int rc =
        tidesdb_l0_range_has_newer(actx->l0, cf_index, lo, lo_size, hi, hi_size, seq_floor, newer);
    if (rc != TDB_SUCCESS) return TDB_SOURCE_BUSY;
    return *newer ? TDB_SOURCE_FOUND : TDB_SOURCE_NOT_FOUND;
}

int tidesdb_l0_adapter_init(tidesdb_l0_txn_ctx_t *ctx, tidesdb_l0_t *l0, vlog_t *vlog)
{
    if (!ctx || !l0) return -1;
    ctx->l0 = l0;
    ctx->vlog = vlog;
    return 0;
}

void tidesdb_l0_source(tidesdb_l0_txn_ctx_t *ctx, tidesdb_source_t *out)
{
    if (!ctx || !out) return;
    out->name = "l0";
    out->get = l0_source_get;
    /* no single-key probe -- the stack falls back to a full get, which for a memtable is already
     * the cheapest answer there is. the interval probe has no such fallback and is set */
    out->has_newer = NULL;
    out->range_has_newer = l0_source_range_has_newer;
    out->ctx = ctx;
}

void tidesdb_l0_backend(tidesdb_l0_txn_ctx_t *ctx, tdb_txn_backend_t *out)
{
    if (!ctx || !out) return;
    /* cleared first, so a field this adapter has no opinion about is never left holding whatever
     * the caller's stack did -- the separator is the engine's to fill in and stays absent here */
    memset(out, 0, sizeof(*out));
    out->backpressure = l0_backend_backpressure;
    out->wal_append = l0_backend_wal_append;
    out->apply = l0_backend_apply;
    out->abandon = l0_backend_abandon;
    out->ctx = ctx;
}

/* the growth step for the aborted set; aborts are rare, so it starts small and rarely grows */
#define L0_ABORTED_SET_INIT 8

static int l0_aborted_add(tidesdb_l0_aborted_set_t *set, uint64_t seq)
{
    if (set->count == set->capacity)
    {
        const int cap = set->capacity ? set->capacity * 2 : L0_ABORTED_SET_INIT;
        uint64_t *grown = realloc(set->seqs, (size_t)cap * sizeof(*grown));
        if (!grown) return TDB_ERR_MEMORY;
        set->seqs = grown;
        set->capacity = cap;
    }
    set->seqs[set->count++] = seq;
    return TDB_SUCCESS;
}

/* whether a sequence was cancelled; linear because the set holds one entry per failed commit, which
 * is a condition that should essentially never happen and never happen twice */
static int l0_aborted_contains(const tidesdb_l0_aborted_set_t *set, uint64_t seq)
{
    if (!set) return 0;
    for (int i = 0; i < set->count; i++)
        if (set->seqs[i] == seq) return 1;
    return 0;
}

void tidesdb_l0_aborted_set_free(tidesdb_l0_aborted_set_t *set)
{
    if (!set) return;
    free(set->seqs);
    set->seqs = NULL;
    set->count = 0;
    set->capacity = 0;
}

int tidesdb_l0_scan_aborts(block_manager_t *wal, tidesdb_l0_aborted_set_t *out)
{
    if (!wal || !out) return TDB_ERR_INVALID_ARGS;

    block_manager_cursor_t cursor;
    if (block_manager_cursor_init_stack(&cursor, wal) != 0) return TDB_ERR_IO;

    int rc = TDB_SUCCESS;
    block_manager_block_t *block;
    while (rc == TDB_SUCCESS && (block = block_manager_cursor_read_and_advance(&cursor)) != NULL)
    {
        tidesdb_wal_cursor_t wc;
        if (tidesdb_wal_cursor_init(&wc, block->data, block->size) == 0 &&
            wc.kind == TDB_WAL_KIND_ABORT_SEQ && wc.xid && wc.xid_size == TDB_WAL_ABORT_SEQ_SIZE)
            rc = l0_aborted_add(out, tdb_decode_be64(wc.xid));
        block_manager_block_free(block);
    }
    return rc;
}

/* fold one two-phase record into the staging map, applying a COMMIT's batch inline. a COMMIT
 * carries the write set at the sequence phase two drew when it decided, so it replays exactly like
 * an ordinary write batch and lands in this generation, in sequence order with everything around
 * it. only a PREPARE is held back, since an undecided batch has nowhere to land yet.
 *
 * replaying exactly like a write batch means being filtered like one. the log holding a COMMIT is
 * kept for as long as any prepare in its generation is undecided, which is unbounded, so the record
 * outlives the flush that made its batch durable and every reopen in between replays it again. a
 * key some later write superseded then comes back above the sstable holding that newer version, and
 * the read path takes a memtable as newer than any sstable.
 *
 * a generation whose memtable already reached L1 carries that in its name, and a COMMIT decided
 * while it was the active one applied into that same memtable -- so its batch is durable in L1 with
 * everything else the generation held, and re-applying it puts back versions the sstables have
 * since moved on from. the record is still staged, since deciding the prepare is the whole reason
 * the log was kept; only the apply is what the flush already did */
static int l0_replay_two_phase(tidesdb_l0_t *l0, tidesdb_wal_cursor_t *wc, uint64_t generation,
                               uint64_t *max_seq, tdb_prepare_stage_t *stage,
                               const tidesdb_replay_filter_t *filter,
                               const int data_already_durable)
{
    if (!wc->xid || wc->xid_size == 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "wal two-phase record of kind %u carries no transaction id",
                      (unsigned)wc->kind);
        return TDB_ERR_CORRUPTION;
    }

    /* a rollback carries no batch, so there is nothing to read or apply */
    if (wc->kind == TDB_WAL_KIND_ROLLBACK)
        return stage ? tdb_prepare_stage_observe(stage, generation, wc->kind, wc->xid, wc->xid_size,
                                                 NULL, 0)
                     : TDB_SUCCESS;

    tidesdb_wal_entry_t *entries = NULL;
    int count = 0, capacity = 0;
    tidesdb_wal_entry_t e;
    int r;
    while ((r = tidesdb_wal_cursor_next(wc, &e)) == 1)
    {
        if (count == capacity)
        {
            const int grown = capacity ? capacity * 2 : L0_REPLAY_PREPARE_INIT_ENTRIES;
            tidesdb_wal_entry_t *bigger = realloc(entries, (size_t)grown * sizeof(*bigger));
            if (!bigger)
            {
                free(entries);
                return TDB_ERR_MEMORY;
            }
            entries = bigger;
            capacity = grown;
        }
        entries[count++] = e;
    }
    if (r != 0)
    {
        free(entries);
        return TDB_ERR_CORRUPTION;
    }

    int rc = TDB_SUCCESS;
    if (wc->kind == TDB_WAL_KIND_COMMIT && !data_already_durable)
        for (int i = 0; i < count && rc == TDB_SUCCESS; i++)
        {
            const tidesdb_wal_entry_t *pe = &entries[i];
            const int64_t ttl = (pe->flags & TDB_WAL_ENTRY_HAS_TTL) ? pe->ttl : -1;
            /* the sequence still advances the clock whether or not the entry lands, so nothing
             * later reuses it. an interval delete is exempt for the same reason it is in a write
             * batch -- its key is a bound rather than a key, so the probe answers about the wrong
             * thing, and re-applying one costs nothing */
            if (!(pe->flags & TDB_WAL_ENTRY_RANGE_DELETE) && filter && filter->superseded &&
                filter->superseded(filter->ctx, pe->cf_index, pe->key, pe->key_size, pe->seq))
            {
                if (pe->seq > *max_seq) *max_seq = pe->seq;
                continue;
            }
            /* phase two carries its batch in the COMMIT record, so an entry whose value the
             * prepare separated arrives here as a reference like any other */
            rc = l0_apply_one(l0, pe, ttl);
            if (pe->seq > *max_seq) *max_seq = pe->seq;
        }

    /* a batch the flush already made durable still advances the clock, so nothing later reuses the
     * sequences it holds */
    if (wc->kind == TDB_WAL_KIND_COMMIT && data_already_durable)
        for (int i = 0; i < count; i++)
            if (entries[i].seq > *max_seq) *max_seq = entries[i].seq;

    /* the stage still hears about it, so a decided transaction stops being listed as in doubt */
    if (rc == TDB_SUCCESS && stage)
        rc = tdb_prepare_stage_observe(stage, generation, wc->kind, wc->xid, wc->xid_size, entries,
                                       count);
    free(entries); /* the stage copied every key and value it kept */
    return rc;
}

/* apply one decoded WRITE_BATCH block to the active memtable, at the entries' own commit sequences,
 * raising *max_seq to the highest sequence applied */
static int l0_replay_block(tidesdb_l0_t *l0, uint64_t generation, const uint8_t *buf, size_t size,
                           const tidesdb_l0_aborted_set_t *aborted, uint64_t *max_seq,
                           tdb_prepare_stage_t *stage, const tidesdb_replay_filter_t *filter,
                           const int data_already_durable)
{
    tidesdb_wal_cursor_t wc;
    if (tidesdb_wal_cursor_init(&wc, buf, size) != 0)
    {
        TDB_DEBUG_LOG(TDB_LOG_ERROR, "wal block of %zu bytes did not decode as a record", size);
        return TDB_ERR_CORRUPTION;
    }

    /* a PREPARE spans WAL generations and stages for the caller's cross-generation pass; a COMMIT
     * carries its own batch and applies inline, as does a single-phase write batch */
    /* an abort record names a cancelled batch and carries nothing of its own to apply; the scan
     * pass already collected it */
    if (wc.kind == TDB_WAL_KIND_ABORT_SEQ) return TDB_SUCCESS;

    if (wc.kind != TDB_WAL_KIND_WRITE_BATCH)
        return l0_replay_two_phase(l0, &wc, generation, max_seq, stage, filter,
                                   data_already_durable);

    /* this log's memtable reached L1 before the file was kept, so every version in this batch is
     * durable in an sstable. re-applying it would put those versions back above the sstables,
     * where every reader takes them as newer -- and a compaction that has since retired one would
     * hand back a key the caller deleted. the sequences still advance the clock, so nothing later
     * reuses them */
    if (data_already_durable)
    {
        tidesdb_wal_entry_t durable;
        int d;
        while ((d = tidesdb_wal_cursor_next(&wc, &durable)) == 1)
            if (durable.seq > *max_seq) *max_seq = durable.seq;
        return d == 0 ? TDB_SUCCESS : TDB_ERR_CORRUPTION;
    }

    tidesdb_wal_entry_t e;
    int r;
    while ((r = tidesdb_wal_cursor_next(&wc, &e)) == 1)
    {
        /* a batch whose commit failed after it was already durable is left out entirely. its
         * sequence still advances the clock, so nothing later reuses it */
        if (l0_aborted_contains(aborted, e.seq))
        {
            if (e.seq > *max_seq) *max_seq = e.seq;
            continue;
        }
        /* a durable later write may already have retired this entry. that happens when this log
         * outlived the flush that installed its data -- kept because an undecided prepare lives in
         * it, or left behind by a crash between the install and the unlink -- while the log holding
         * the newer write is gone. applying it anyway would put it in a memtable, and every reader
         * takes a memtable as newer than any sstable, so a deleted key would come back.
         *
         * the sequence gate is what keeps this free in an ordinary recovery: the surviving log is
         * the one the active memtable was never flushed from, and its sequences are all above
         * anything on disk, so the probe is never reached */
        /* the probe answers for one key, which a prefix delete does not have -- its key is a bound,
         * and a newer version of the one key that happens to equal that bound retires nothing it
         * covers. re-applying a range tombstone costs nothing, since the same interval at the same
         * sequence folds back into the fragment already holding it */
        if (!(e.flags & TDB_WAL_ENTRY_RANGE_DELETE) && filter && filter->superseded &&
            filter->superseded(filter->ctx, e.cf_index, e.key, e.key_size, e.seq))
        {
            if (e.seq > *max_seq) *max_seq = e.seq;
            continue;
        }
        const int64_t ttl = (e.flags & TDB_WAL_ENTRY_HAS_TTL) ? e.ttl : -1;
        const int rc = l0_apply_one(l0, &e, ttl);
        if (rc != TDB_SUCCESS) return rc;
        if (e.seq > *max_seq) *max_seq = e.seq;
    }
    return r == 0 ? TDB_SUCCESS : TDB_ERR_CORRUPTION;
}

int tidesdb_l0_replay_wal(tidesdb_l0_t *l0, block_manager_t *wal, const uint64_t generation,
                          const tidesdb_l0_aborted_set_t *aborted, uint64_t *out_max_seq,
                          tdb_prepare_stage_t *stage, const tidesdb_replay_filter_t *filter,
                          const int data_already_durable)
{
    if (!l0 || !wal) return TDB_ERR_INVALID_ARGS;

    block_manager_cursor_t cursor;
    if (block_manager_cursor_init_stack(&cursor, wal) != 0) return TDB_ERR_IO;

    uint64_t max_seq = 0;
    int rc = TDB_SUCCESS;
    block_manager_block_t *block;
    while (rc == TDB_SUCCESS && (block = block_manager_cursor_read_and_advance(&cursor)) != NULL)
    {
        rc = l0_replay_block(l0, generation, block->data, block->size, aborted, &max_seq, stage,
                             filter, data_already_durable);
        block_manager_block_free(block);
    }
    if (out_max_seq) *out_max_seq = max_seq;
    return rc;
}
