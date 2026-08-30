/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "datastructures/skip_list/skip_list_internal.h"

/* the "not answered yet" result of one descent, distinct from both a hit and a definitive miss.
 * a real node address is never this value, so it costs nothing to test */
#define SKIP_LIST_FIND_RETRY ((skip_list_node_t *)-1)

static skip_list_node_t *skip_list_find_node_once(skip_list_t *list, const uint8_t *key,
                                                  size_t key_size);

/**
 * skip_list_find_node
 * descends the list to the node whose key equals the search key
 * @param list skip list
 * @param key search key
 * @param key_size length of key in bytes
 * @return the matching node, or NULL when the key is absent
 */
static skip_list_node_t *skip_list_find_node(skip_list_t *list, const uint8_t *key,
                                             const size_t key_size)
{
    /* the level-0 walk below is bounded, and running it out means the gap held more concurrent
     * inserts than the budget covers. that is not an absence, so it must not be reported as one --
     * a fresh descent lands on a predecessor much closer to the key, which is what makes a restart
     * converge rather than merely retry */
    for (int attempt = 0; attempt < SKIP_LIST_MAX_FIND_RESTARTS; attempt++)
    {
        skip_list_node_t *const found = skip_list_find_node_once(list, key, key_size);
        if (found != SKIP_LIST_FIND_RETRY) return found;
    }
    return NULL;
}

/**
 * skip_list_find_node_once
 * one descent to the node whose key equals the search key
 * @param list skip list
 * @param key search key
 * @param key_size length of key in bytes
 * @return the matching node, NULL when the key is absent, or SKIP_LIST_FIND_RETRY when the
 *         level-0 walk ran out of budget and the answer is not yet known
 */
static skip_list_node_t *skip_list_find_node_once(skip_list_t *list, const uint8_t *key,
                                                  const size_t key_size)
{
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    skip_list_node_t *current =
        skip_list_descend(list, header, key, key_size, SKIP_LIST_DESCEND_BELOW);

    /* the descent stopped at the last node before the key, but the hop below is taken after that
     * decision rather than as part of it. an insert that splices a smaller key in between lands
     * there instead of the target, so the hop is walked rather than taken once -- a single load
     * would compare the newcomer's key, miss, and report a key still one step further on as absent.
     *
     * the walk needs one hop per node lying between the predecessor and the key, which is bounded
     * by how many nodes the list holds, plus slack for those spliced in while it runs. deriving the
     * bound from the structure is what makes exhausting it mean the list grew underneath this
     * descent, and nothing else */
    const int entries = atomic_load_explicit(&list->entry_count, memory_order_relaxed);
    const int budget = (entries > 0 ? entries : 0) + SKIP_LIST_FORWARD_HOP_SLACK;

    skip_list_node_t *target = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    for (int hop = 0; hop < budget; hop++)
    {
        if (target == NULL || NODE_IS_SENTINEL(target) || target->key == NULL) return NULL;
        const int cmp = skip_list_key_cmp(target->key, target->key_size, key, key_size);
        if (cmp == 0) return target;

        /* only a key above the search key proves absence. stopping on one below it is the false
         * miss this walk exists to prevent, so the walk continues while it is still below */
        if (cmp > 0) return NULL;
        target = atomic_load_explicit(&target->forward[0], memory_order_acquire);
    }

    /* still below the key with the budget spent, so whether the key is present is simply not known
     * yet. returning absent here would be that same false miss, reached by a different route */
    return SKIP_LIST_FIND_RETRY;
}

/**
 * skip_list_resolve_latest
 * resolves the latest visible version of a found node, applying TTL and tombstone rules
 * @param list skip list
 * @param target node whose version chain to resolve
 * @param out_version receives the value-bearing version, or NULL when deleted/expired
 * @param ttl optional out for the resolved version's ttl
 * @param deleted optional out set to 1 for a deleted/expired key, 0 otherwise
 * @return 0 with *out_version resolved, or -1 when no version exists at all
 */
static int skip_list_resolve_latest(skip_list_t *list, skip_list_node_t *target,
                                    skip_list_version_t **out_version, int64_t *ttl,
                                    uint8_t *deleted)
{
    skip_list_version_t *head_version =
        atomic_load_explicit(&target->versions, memory_order_acquire);
    if (head_version == NULL) return -1;

    const int64_t current_time = skip_list_get_current_time(list);
    const int head_invalid = skip_list_version_is_invalid_with_time(head_version, current_time);

    if (head_invalid && VERSION_IS_DELETED(head_version))
    {
        if (ttl != NULL) *ttl = head_version->ttl;
        if (deleted != NULL) *deleted = 1;
        *out_version = NULL;
        return 0;
    }

    skip_list_version_t *version =
        head_invalid ? skip_list_get_latest_valid_version(target, current_time) : head_version;
    if (version == NULL)
    {
        if (deleted != NULL) *deleted = 1;
        if (ttl != NULL) *ttl = -1;
        *out_version = NULL;
        return 0;
    }

    if (ttl != NULL) *ttl = version->ttl;
    if (deleted != NULL) *deleted = 0;
    *out_version = version;
    return 0;
}

/**
 * skip_list_resolve_at_seq
 * selects the version of a found node visible at snapshot_seq, applying visibility and TTL rules
 * @param list skip list
 * @param target node whose version chain to resolve
 * @param out_version receives the value-bearing version, or NULL when deleted/expired
 * @param ttl optional out for the resolved version's ttl
 * @param deleted optional out set to 1 for a deleted/expired key, 0 otherwise
 * @param seq optional out for the resolved version's sequence number
 * @param snapshot_seq snapshot bound; UINT64_MAX reads the head version with no visibility check
 * @param visibility_check optional predicate telling whether a sequence is committed
 * @param visibility_ctx context passed to visibility_check
 * @return 0 with *out_version resolved, or -1 when no visible version exists
 */
static int skip_list_resolve_at_seq(skip_list_t *list, skip_list_node_t *target,
                                    skip_list_version_t **out_version, int64_t *ttl,
                                    uint8_t *deleted, uint64_t *seq, const uint64_t snapshot_seq,
                                    const skip_list_visibility_check_fn visibility_check,
                                    void *visibility_ctx)
{
    skip_list_version_t *version = atomic_load_explicit(&target->versions, memory_order_acquire);

    if (snapshot_seq == UINT64_MAX)
    {
        /* an unbounded read takes the newest version rather than resolving against a snapshot, but
         * it still honours the visibility predicate. a version can be present and yet not exist as
         * far as any reader is concerned -- the entries a failed commit left behind are the case --
         * and skipping the check here would make an unbounded read the one way to see them */
        while (version != NULL && visibility_check != NULL &&
               !visibility_check(visibility_ctx,
                                 atomic_load_explicit(&version->seq, memory_order_acquire)))
            version = atomic_load_explicit(&version->next, memory_order_acquire);
        if (version == NULL) return -1;
    }
    else
    {
        /* the chain is ordered newest-to-oldest; take the newest committed version whose sequence
         * is within the snapshot bound */
        while (version != NULL)
        {
            const uint64_t version_seq = atomic_load_explicit(&version->seq, memory_order_acquire);
            if (version_seq <= snapshot_seq &&
                (visibility_check == NULL || visibility_check(visibility_ctx, version_seq)))
                break;
            version = atomic_load_explicit(&version->next, memory_order_acquire);
        }
        if (version == NULL) return -1;
    }

    if (ttl != NULL) *ttl = version->ttl;
    if (seq != NULL) *seq = atomic_load_explicit(&version->seq, memory_order_acquire);

    if (version->ttl > 0 && version->ttl <= skip_list_get_current_time(list))
    {
        if (deleted != NULL) *deleted = 1;
        *out_version = NULL;
        return 0;
    }

    const uint8_t is_deleted = VERSION_IS_DELETED(version);
    if (deleted != NULL) *deleted = is_deleted;
    *out_version = is_deleted ? NULL : version;
    return 0;
}

int skip_list_get(skip_list_t *list, const uint8_t *key, const size_t key_size, uint8_t **value,
                  size_t *value_size, int64_t *ttl, uint8_t *deleted)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *target = skip_list_find_node(list, key, key_size);
    if (target == NULL) return -1;

    skip_list_version_t *version = NULL;
    if (skip_list_resolve_latest(list, target, &version, ttl, deleted) != 0) return -1;

    /* this entry point has nowhere to report a value log id, so a referenced value would come
     * back as an empty one. refusing is the only answer it can give truthfully; a caller that may
     * meet a reference reads through skip_list_get_with_seq, which reports the id */
    if (version != NULL && skip_list_version_vlog_id(version) != 0) return -1;

    if (version == NULL || version->value == NULL || version->value_size == 0)
    {
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    *value = (uint8_t *)malloc(version->value_size);
    if (*value == NULL) return -1;
    memcpy(*value, version->value, version->value_size);
    *value_size = version->value_size;
    return 0;
}

int skip_list_get_ref(skip_list_t *list, const uint8_t *key, const size_t key_size,
                      const uint8_t **value, size_t *value_size, int64_t *ttl, uint8_t *deleted)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *target = skip_list_find_node(list, key, key_size);
    if (target == NULL) return -1;

    skip_list_version_t *version = NULL;
    if (skip_list_resolve_latest(list, target, &version, ttl, deleted) != 0) return -1;

    if (version == NULL)
    {
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    /* zero-copy -- return a direct pointer into the version's value */
    if (skip_list_version_vlog_id(version) != 0) return -1; /* see skip_list_get */
    *value = version->value;
    *value_size = version->value_size;
    return 0;
}

int skip_list_delete(skip_list_t *list, const uint8_t *key, const size_t key_size,
                     const uint64_t seq)
{
    if (list == NULL || key == NULL || key_size == 0) return -1;

    skip_list_node_t *target = skip_list_find_node(list, key, key_size);
    if (target == NULL) return 0; /* nothing to delete */

    skip_list_version_t *tombstone =
        skip_list_create_version(list, NULL, 0, 0, -1, SKIP_LIST_FLAG_DELETED, seq);
    if (tombstone == NULL) return -1;

    if (skip_list_insert_version_cas(&target->versions, tombstone, seq, list, 0, 0) != 0) return -1;

    /* a tombstone is an inserted version too -- floor min_seq so compaction never reaps it as
     * older than data still held unflushed, matching skip_list_put_with_seq */
    skip_list_update_min_seq(list, seq);
    return 0;
}

uint64_t skip_list_get_min_seq(skip_list_t *list)
{
    if (list == NULL) return UINT64_MAX;
    return atomic_load_explicit(&list->min_seq, memory_order_acquire);
}

int skip_list_get_max_seq(skip_list_t *list, const uint8_t *key, const size_t key_size,
                          uint64_t *out_seq)
{
    if (list == NULL || key == NULL || key_size == 0 || out_seq == NULL) return -1;

    *out_seq = 0;

    skip_list_node_t *target = skip_list_find_node(list, key, key_size);
    if (target == NULL) return -1;

    skip_list_version_t *version = atomic_load_explicit(&target->versions, memory_order_acquire);
    if (version == NULL) return -1;

    *out_seq = atomic_load_explicit(&version->seq, memory_order_acquire);
    return 0;
}

int skip_list_get_with_seq(skip_list_t *list, const uint8_t *key, const size_t key_size,
                           uint8_t **value, size_t *value_size, uint64_t *vlog_id, int64_t *ttl,
                           uint8_t *deleted, uint64_t *seq, uint64_t snapshot_seq,
                           const skip_list_visibility_check_fn visibility_check,
                           void *visibility_ctx)
{
    if (vlog_id != NULL) *vlog_id = 0;
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *target = skip_list_find_node(list, key, key_size);
    if (target == NULL) return -1;

    skip_list_version_t *version = NULL;
    if (skip_list_resolve_at_seq(list, target, &version, ttl, deleted, seq, snapshot_seq,
                                 visibility_check, visibility_ctx) != 0)
        return -1;

    if (version == NULL)
    {
        *value = NULL;
        *value_size = 0;
        return 0;
    }
    if (vlog_id != NULL) *vlog_id = skip_list_version_vlog_id(version);

    if (version->value == NULL || version->value_size == 0)
    {
        /* a referenced value keeps its logical length here even though its bytes are elsewhere,
         * so the caller can size the read it is about to make against the value log */
        *value = NULL;
        *value_size = version->value_size;
        return 0;
    }

    *value = malloc(version->value_size);
    if (*value == NULL) return -1;
    memcpy(*value, version->value, version->value_size);
    *value_size = version->value_size;
    return 0;
}

int skip_list_get_with_seq_ref(skip_list_t *list, const uint8_t *key, const size_t key_size,
                               const uint8_t **value, size_t *value_size, int64_t *ttl,
                               uint8_t *deleted, uint64_t *seq, uint64_t snapshot_seq,
                               const skip_list_visibility_check_fn visibility_check,
                               void *visibility_ctx)
{
    if (list == NULL || key == NULL || key_size == 0 || value == NULL || value_size == NULL)
        return -1;

    skip_list_node_t *target = skip_list_find_node(list, key, key_size);
    if (target == NULL) return -1;

    skip_list_version_t *version = NULL;
    if (skip_list_resolve_at_seq(list, target, &version, ttl, deleted, seq, snapshot_seq,
                                 visibility_check, visibility_ctx) != 0)
        return -1;

    if (version == NULL)
    {
        *value = NULL;
        *value_size = 0;
        return 0;
    }

    /* zero-copy -- return a direct pointer into the version's value */
    if (skip_list_version_vlog_id(version) != 0) return -1; /* see skip_list_get */
    *value = version->value;
    *value_size = version->value_size;
    return 0;
}
