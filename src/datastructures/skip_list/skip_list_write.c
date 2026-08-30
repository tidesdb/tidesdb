/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include "datastructures/skip_list/skip_list_internal.h"

/* the version-add outcome codes shared by the write paths, kept distinct so a caller can tell a
 * rejected duplicate sequence (skip, not an error) apart from an allocation or cas failure. */
#define SKIP_LIST_ADD_OK   1    /* new version linked onto the node */
#define SKIP_LIST_ADD_DUP  0    /* sequence already present, nothing added */
#define SKIP_LIST_ADD_FAIL (-1) /* version allocation or cas failed */

/**
 * skip_list_update_min_seq
 * lowers the list's tracked minimum sequence toward seq if it is smaller
 * @param list skip list to update
 * @param seq candidate sequence number
 *
 * a compaction reads min_seq to learn the oldest unflushed write still held here, so it never
 * reaps a tombstone newer than it and resurrects the key.
 */
void skip_list_update_min_seq(skip_list_t *list, const uint64_t seq)
{
    uint64_t cur = atomic_load_explicit(&list->min_seq, memory_order_relaxed);
    while (seq < cur && !atomic_compare_exchange_weak_explicit(
                            &list->min_seq, &cur, seq, memory_order_relaxed, memory_order_relaxed))
    {
    }
}

/**
 * skip_list_add_version_to_node
 * validates the sequence and links a new version onto an existing key's version chain
 * @param list skip list owning the node
 * @param node node whose key already matches the write
 * @param e the entry being written, whose value is either inline bytes or a value log id
 * @return SKIP_LIST_ADD_OK on success, SKIP_LIST_ADD_DUP if seq already present,
 *         SKIP_LIST_ADD_FAIL on allocation or cas failure
 */
static int skip_list_add_version_to_node(skip_list_t *list, skip_list_node_t *node,
                                         const skip_list_batch_entry_t *e)
{
    skip_list_version_t *latest = atomic_load_explicit(&node->versions, memory_order_acquire);
    if (skip_list_validate_sequence(latest, e->seq) != 0) return SKIP_LIST_ADD_DUP;

    skip_list_version_t *new_version = skip_list_create_version(
        list, e->value, e->value_size, e->vlog_id, e->ttl, e->flags, e->seq);
    if (new_version == NULL) return SKIP_LIST_ADD_FAIL;

    if (skip_list_insert_version_cas(
            &node->versions, new_version, e->seq, list, e->value_size,
            skip_list_version_tail_bytes(e->value, e->value_size, e->flags)) != 0)
        return SKIP_LIST_ADD_FAIL;

    return SKIP_LIST_ADD_OK;
}

/**
 * skip_list_build_node
 * allocates and initializes a fresh node combining header, forward/backward pointers, and key in
 * one allocation, seeded with an initial version
 * @param list skip list owning the node
 * @param e the entry being written, whose key is copied in and whose value seeds the first version
 * @param new_level top level of the node
 * @return the new node, or NULL on allocation failure
 */
static skip_list_node_t *skip_list_build_node(skip_list_t *list, const skip_list_batch_entry_t *e,
                                              const int new_level)
{
    const uint8_t *key = e->key;
    const size_t key_size = e->key_size;
    const size_t pointers_size =
        SKIP_LIST_NODE_PTR_SLOTS(new_level) * sizeof(_Atomic(skip_list_node_t *));
    skip_list_node_t *new_node =
        skip_list_alloc(list, sizeof(skip_list_node_t) + pointers_size + key_size);
    if (new_node == NULL) return NULL;

    new_node->key = (uint8_t *)new_node + sizeof(skip_list_node_t) + pointers_size;
    memcpy(new_node->key, key, key_size);
    new_node->key_size = key_size;
    new_node->level = (uint8_t)new_level;
    new_node->node_flags = 0;

    skip_list_version_t *initial_version = skip_list_create_version(
        list, e->value, e->value_size, e->vlog_id, e->ttl, e->flags, e->seq);
    if (initial_version == NULL)
    {
        skip_list_dealloc(list, new_node);
        return NULL;
    }
    atomic_init(&new_node->versions, initial_version);

    for (int i = 0; i <= new_level; i++)
    {
        atomic_init(&new_node->forward[i], NULL);
        atomic_init(&BACKWARD_PTR(new_node, i, new_level), NULL);
    }
    return new_node;
}

/**
 * skip_list_link_node_upper_levels
 * links an already level-0-inserted node into levels 1..new_level and fixes backward pointers
 * @param new_node node whose level-0 forward pointer is already published
 * @param update per-level predecessor array captured during traversal
 * @param new_level top level of the node
 */
static void skip_list_link_node_upper_levels(skip_list_node_t *new_node, skip_list_node_t **update,
                                             const int new_level)
{
    atomic_store_explicit(&BACKWARD_PTR(new_node, 0, new_level), update[0], memory_order_release);
    skip_list_node_t *next_after_insert =
        atomic_load_explicit(&new_node->forward[0], memory_order_acquire);
    if (next_after_insert != NULL)
    {
        skip_list_node_t *expected = update[0];
        atomic_compare_exchange_strong_explicit(
            &BACKWARD_PTR(next_after_insert, 0, next_after_insert->level), &expected, new_node,
            memory_order_release, memory_order_acquire);
    }

    for (int i = 1; i <= new_level; i++)
    {
        /* the predecessor was captured before the level-0 insert, so a key smaller than this one
         * may have been linked in front of it since. splicing at the captured predecessor without
         * looking would leave this level out of key order, and a descent through an unordered level
         * hands the level-0 insert a predecessor past its own insertion point, which then splices
         * level 0 out of order too and makes keys unfindable. so the predecessor is walked forward
         * here exactly as it is at level 0 */
        skip_list_node_t *pred = update[i];
        skip_list_node_t *next = NULL;
        int linked = 0;
        for (int attempt = 0; attempt < SKIP_LIST_MAX_CAS_ATTEMPTS && !linked; attempt++)
        {
            next = atomic_load_explicit(&pred->forward[i], memory_order_acquire);
            if (next != NULL && !NODE_IS_SENTINEL(next) &&
                skip_list_key_cmp(next->key, next->key_size, new_node->key, new_node->key_size) < 0)
            {
                pred = next;
                continue;
            }
            atomic_store_explicit(&new_node->forward[i], next, memory_order_relaxed);
            linked = atomic_compare_exchange_weak_explicit(
                &pred->forward[i], &next, new_node, memory_order_release, memory_order_acquire);
        }

        /* the upper levels are only an index onto level 0, where the node is already published, so
         * a level this could not link into costs a slower search and never a lost key */
        if (!linked) break;

        atomic_store_explicit(&BACKWARD_PTR(new_node, i, new_level), pred, memory_order_release);
        if (next != NULL)
        {
            skip_list_node_t *expected = pred;
            atomic_compare_exchange_strong_explicit(&BACKWARD_PTR(next, i, next->level), &expected,
                                                    new_node, memory_order_release,
                                                    memory_order_acquire);
        }
    }
}

/**
 * skip_list_find_update
 * descends from start recording, for each level, the rightmost node whose key is less than the
 * search key
 * @param start node to begin the descent from (header, or a sorted-hint node)
 * @param max_level highest currently populated level of the list
 * @param key search key
 * @param key_size length of key in bytes
 * @param update out array receiving the per-level predecessor of key
 * @return the level-0 predecessor whose forward[0] is where key belongs
 */
static skip_list_node_t *skip_list_find_update(skip_list_node_t *start, const int max_level,
                                               const uint8_t *key, const size_t key_size,
                                               skip_list_node_t **update)
{
    skip_list_node_t *current = start;

    /* traverse with prefetching -- prefetch before sentinel check */
    for (int i = max_level; i >= 0; i--)
    {
        skip_list_node_t *next = atomic_load_explicit(&current->forward[i], memory_order_acquire);

        if (SKIP_LIST_LIKELY(next != NULL))
        {
            PREFETCH_READ(next);
            PREFETCH_READ(next->key);
        }

        while (next != NULL && !NODE_IS_SENTINEL(next))
        {
            int cmp = skip_list_key_cmp(next->key, next->key_size, key, key_size);
            if (cmp >= 0) break;
            current = next;
            next = atomic_load_explicit(&current->forward[i], memory_order_acquire);

            if (SKIP_LIST_LIKELY(next != NULL))
            {
                PREFETCH_READ(next);
                PREFETCH_READ(next->key);
            }
        }
        update[i] = current;
    }
    return current;
}

int skip_list_put_with_seq(skip_list_t *list, const uint8_t *key, size_t key_size,
                           const uint8_t *value, size_t value_size, int64_t ttl, uint64_t seq,
                           uint8_t flags)
{
    return skip_list_put_with_seq_tracked(list, key, key_size, value, value_size, ttl, seq, flags,
                                          NULL);
}

/**
 * skip_list_link_base
 * link one node into level 0 at the position update[] found, walking forward from the predecessor.
 * a concurrent insert of the same key takes the version instead of this node, and a position that
 * stays contended restarts the walk from the header with a fresh budget rather than failing -- a
 * lost write would surface to the caller as an io failure and abort the transaction, when all that
 * happened is contention. update[0] is left at the predecessor the link went in behind
 * @param list the skip list
 * @param header the list header node, the restart point
 * @param e the entry being inserted
 * @param update the per-level predecessor array
 * @param new_node the node built for this entry, freed here on every path that does not link it
 * @param out_rc receives the result the caller returns when this does not link
 * @return 1 when new_node is linked and still owes its upper levels, 0 otherwise
 */
static int skip_list_link_base(skip_list_t *list, skip_list_node_t *header,
                               const skip_list_batch_entry_t *e, skip_list_node_t **update,
                               skip_list_node_t *new_node, int *out_rc)
{
    /* the descent that produced this predecessor passes through the upper levels, so a predecessor
     * already past the insertion point is possible. the loop below only ever walks forward, which
     * would splice this node in front of a larger key and unsort level 0, so a predecessor that is
     * already too far right is discarded for the header and the walk starts over */
    skip_list_node_t *pred = update[0];
    if (pred != header && pred->key != NULL &&
        skip_list_key_cmp(pred->key, pred->key_size, e->key, e->key_size) >= 0)
        pred = header;

    int cas_attempts = 0;
    int restarts = 0;

    for (;;)
    {
        skip_list_node_t *next_at_0 = atomic_load_explicit(&pred->forward[0], memory_order_acquire);

        if (next_at_0 != NULL && !NODE_IS_SENTINEL(next_at_0))
        {
            const int cmp =
                skip_list_key_cmp(next_at_0->key, next_at_0->key_size, e->key, e->key_size);
            if (cmp == 0)
            {
                const int r = skip_list_add_version_to_node(list, next_at_0, e);
                (void)skip_list_free_node_internal(list, new_node);
                *out_rc = r == SKIP_LIST_ADD_OK ? 0 : -1;
                return 0;
            }
            if (cmp < 0)
            {
                pred = next_at_0;
                continue;
            }
        }

        atomic_store_explicit(&new_node->forward[0], next_at_0, memory_order_relaxed);
        if (atomic_compare_exchange_weak_explicit(&pred->forward[0], &next_at_0, new_node,
                                                  memory_order_release, memory_order_acquire))
        {
            update[0] = pred;
            return 1;
        }

        /* the cas lost a race -- the winner may be this key, in which case fold into its versions
         */
        if (next_at_0 != NULL && !NODE_IS_SENTINEL(next_at_0))
        {
            const int cmp =
                skip_list_key_cmp(next_at_0->key, next_at_0->key_size, e->key, e->key_size);
            if (cmp == 0)
            {
                const int r = skip_list_add_version_to_node(list, next_at_0, e);
                (void)skip_list_free_node_internal(list, new_node);
                *out_rc = r == SKIP_LIST_ADD_OK ? 0 : -1;
                return 0;
            }
            if (cmp < 0)
            {
                pred = next_at_0;
                continue;
            }
        }

        if (++cas_attempts > SKIP_LIST_MAX_CAS_ATTEMPTS)
        {
            if (++restarts > SKIP_LIST_MAX_INSERT_RESTARTS)
            {
                (void)skip_list_free_node_internal(list, new_node);
                *out_rc = -1;
                return 0;
            }
            cas_attempts = 0;
            pred = header;
        }
    }
}

/**
 * skip_list_try_fold
 * add this write as a version of a node, when that node is the one holding the key
 * @param list the skip list
 * @param e the entry being written
 * @param node the candidate node, may be NULL or the tail sentinel
 * @param out_rc receives the result the caller returns, set only when the write was folded
 * @return 1 when the write was folded into node, 0 when node does not hold this key
 */
static int skip_list_try_fold(skip_list_t *list, const skip_list_batch_entry_t *e,
                              skip_list_node_t *node, int *out_rc)
{
    if (node == NULL || NODE_IS_SENTINEL(node)) return 0;
    if (skip_list_key_cmp(node->key, node->key_size, e->key, e->key_size) != 0) return 0;

    const int r = skip_list_add_version_to_node(list, node, e);
    *out_rc = r == SKIP_LIST_ADD_OK ? 0 : -1;
    return 1;
}

/**
 * skip_list_fold_existing
 * add this write as a version of a node already holding the key, if the search landed on one
 * @param list the skip list
 * @param e the entry being written
 * @param current the node the descent finished on
 * @param update the per-level predecessor array
 * @param out_rc receives the result the caller returns when the key was already present
 * @return 1 when the write was folded into an existing node, 0 when the key is not there yet
 */
static int skip_list_fold_existing(skip_list_t *list, const skip_list_batch_entry_t *e,
                                   skip_list_node_t *current, skip_list_node_t **update,
                                   int *out_rc)
{
    /* the key may already be present at the found position */
    skip_list_node_t *existing = atomic_load_explicit(&current->forward[0], memory_order_acquire);
    if (skip_list_try_fold(list, e, existing, out_rc)) return 1;

    /* a concurrent insert may have landed between update[0] and existing */
    skip_list_node_t *recheck = atomic_load_explicit(&update[0]->forward[0], memory_order_acquire);
    if (recheck != existing && skip_list_try_fold(list, e, recheck, out_rc)) return 1;

    return 0;
}

static int skip_list_put_entry(skip_list_t *list, const skip_list_batch_entry_t *ep,
                               int *out_created);

int skip_list_put_with_seq_tracked(skip_list_t *list, const uint8_t *key, size_t key_size,
                                   const uint8_t *value, size_t value_size, int64_t ttl,
                                   uint64_t seq, uint8_t flags, int *out_created)
{
    const int is_tombstone = (flags & SKIP_LIST_FLAG_DELETED) != 0;
    /* a live entry may carry no bytes -- an empty value is a value, and the version records it as
     * one. what is still rejected is a caller claiming bytes it did not supply */
    if (!is_tombstone && value == NULL && value_size > 0)
    {
        if (out_created) *out_created = 0;
        return -1;
    }
    const skip_list_batch_entry_t e = {key, key_size, value, value_size, seq, ttl, flags, 0};
    return skip_list_put_entry(list, &e, out_created);
}

int skip_list_put_reference_with_seq(skip_list_t *list, const uint8_t *key, const size_t key_size,
                                     const uint64_t vlog_id, const size_t value_size,
                                     const int64_t ttl, const uint64_t seq, const uint8_t flags,
                                     int *out_created)
{
    /* a tombstone has no bytes to point at, so a reference to one is a caller error rather than a
     * shape the version could hold */
    if (vlog_id == 0 || (flags & SKIP_LIST_FLAG_DELETED))
    {
        if (out_created) *out_created = 0;
        return -1;
    }
    const skip_list_batch_entry_t e = {
        key,    key_size, NULL, value_size, seq, ttl, (uint8_t)(flags | SKIP_LIST_FLAG_VLOG_REF),
        vlog_id};
    return skip_list_put_entry(list, &e, out_created);
}

/* the shared body behind both public puts -- descend, fold into the key's chain when it is already
 * present, otherwise build and link a node */
static int skip_list_put_entry(skip_list_t *list, const skip_list_batch_entry_t *ep,
                               int *out_created)
{
    if (out_created) *out_created = 0;
    if (list == NULL || ep->key == NULL || ep->key_size == 0) return -1;

    skip_list_update_min_seq(list, ep->seq);

    const skip_list_batch_entry_t e = *ep;
    const uint8_t *key = e.key;
    const size_t key_size = e.key_size;
    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);
    const int max_level = atomic_load_explicit(&list->level, memory_order_acquire);

    skip_list_node_t *stack_update[SKIP_LIST_STACK_UPDATE_SIZE];
    skip_list_node_t **update;
    const int use_stack = (list->max_level < SKIP_LIST_STACK_UPDATE_SIZE);
    if (use_stack)
        update = stack_update;
    else
    {
        update = malloc((size_t)(list->max_level + 1) * sizeof(skip_list_node_t *));
        if (!update) return -1;
    }
    for (int i = 0; i <= list->max_level; i++) update[i] = header;

    skip_list_node_t *current = skip_list_find_update(header, max_level, key, key_size, update);

    int rc = -1;
    if (skip_list_fold_existing(list, &e, current, update, &rc))
    {
        if (!use_stack) free(update);
        return rc;
    }

    const int new_level = skip_list_random_level(list);
    const int current_level = atomic_load_explicit(&list->level, memory_order_acquire);
    if (new_level > current_level)
    {
        for (int i = current_level + 1; i <= new_level; i++) update[i] = header;
        atomic_store_explicit(&list->level, new_level, memory_order_release);
    }

    skip_list_node_t *new_node = skip_list_build_node(list, &e, new_level);
    if (new_node == NULL)
    {
        if (!use_stack) free(update);
        return -1;
    }

    if (!skip_list_link_base(list, header, &e, update, new_node, &rc))
    {
        if (!use_stack) free(update);
        return rc;
    }

    skip_list_link_node_upper_levels(new_node, update, new_level);

    atomic_fetch_add_explicit(&list->data_bytes, key_size + e.value_size, memory_order_relaxed);
    atomic_fetch_add_explicit(
        &list->memory_bytes,
        SKIP_LIST_NODE_BYTES(new_level, key_size) +
            SKIP_LIST_VERSION_BYTES(skip_list_version_tail_bytes(e.value, e.value_size, e.flags)),
        memory_order_relaxed);
    atomic_fetch_add_explicit(&list->entry_count, 1, memory_order_relaxed);

    if (out_created)
        *out_created = 1; /* a new distinct key node, not a version added to an existing */
    if (!use_stack) free(update);
    return 0;
}

/**
 * skip_list_batch_hint_t
 * what a batch carries from one entry to the next so a sorted run reuses the previous entry's
 * predecessor positions instead of restarting every search at the header
 * @param key the previous entry's key, NULL before the first entry
 * @param key_size the previous entry's key length in bytes
 * @param max_level the list level the previous entry was positioned against
 */
typedef struct
{
    const uint8_t *key;
    size_t key_size;
    int max_level;
} skip_list_batch_hint_t;

/**
 * skip_list_batch_seek
 * position update[] at the predecessors of one batch entry's key. a key at or after the previous
 * entry's reuses the positions already there and only initializes the levels the list has grown
 * since, which is what makes a sorted batch one walk rather than one per entry
 * @param list the skip list
 * @param header the list header node
 * @param entry the batch entry to position for
 * @param update the per-level predecessor array, filled by this call
 * @param hint the previous entry's position, advanced to this entry's
 * @return the node the search finished on, whose forward[0] is where the key belongs
 */
static skip_list_node_t *skip_list_batch_seek(skip_list_t *list, skip_list_node_t *header,
                                              const skip_list_batch_entry_t *entry,
                                              skip_list_node_t **update,
                                              skip_list_batch_hint_t *hint)
{
    const int max_level = atomic_load_explicit(&list->level, memory_order_acquire);

    /* each update[i] has level >= i, set during traversal at that level, so reusing it and reading
     * update[i]->forward[i] is always safe */
    const int use_hint = hint->key != NULL && skip_list_key_cmp(entry->key, entry->key_size,
                                                                hint->key, hint->key_size) >= 0;

    skip_list_node_t *current;
    if (!use_hint)
    {
        for (int i = 0; i <= list->max_level; i++) update[i] = header;
        current = header;
    }
    else
    {
        for (int i = hint->max_level + 1; i <= max_level; i++) update[i] = header;
        current = update[max_level]; /* the top-level hint, carry-down handles lower levels */
    }

    hint->key = entry->key;
    hint->key_size = entry->key_size;
    hint->max_level = max_level;
    return skip_list_find_update(current, max_level, entry->key, entry->key_size, update);
}

/**
 * skip_list_batch_link_base
 * link one batch entry's node into level 0 at the position update[] found. a concurrent insert of
 * the same key takes the version instead, and sustained contention gives the entry up rather than
 * spin without bound; new_node is freed on both of those paths, so the caller only owns it on a
 * link. update[0] is left at the predecessor the link went in behind
 * @param list the skip list
 * @param entry the batch entry being inserted
 * @param update the per-level predecessor array
 * @param new_node the node built for this entry
 * @param out_added set to 1 when this entry's version reached the list, by either path
 * @return 1 when new_node is linked and still owes its upper levels, 0 otherwise
 */
static int skip_list_batch_link_base(skip_list_t *list, const skip_list_batch_entry_t *entry,
                                     skip_list_node_t **update, skip_list_node_t *new_node,
                                     int *out_added)
{
    skip_list_node_t *pred = update[0];
    int cas_attempts = 0;

    for (;;)
    {
        skip_list_node_t *next_at_0 = atomic_load_explicit(&pred->forward[0], memory_order_acquire);

        if (next_at_0 != NULL && !NODE_IS_SENTINEL(next_at_0))
        {
            const int cmp =
                skip_list_key_cmp(next_at_0->key, next_at_0->key_size, entry->key, entry->key_size);
            if (cmp == 0)
            {
                if (skip_list_add_version_to_node(list, next_at_0, entry) == SKIP_LIST_ADD_OK)
                    *out_added = 1;
                (void)skip_list_free_node_internal(list, new_node);
                return 0;
            }
            if (cmp < 0)
            {
                pred = next_at_0;
                continue;
            }
        }

        atomic_store_explicit(&new_node->forward[0], next_at_0, memory_order_relaxed);
        if (atomic_compare_exchange_weak_explicit(&pred->forward[0], &next_at_0, new_node,
                                                  memory_order_release, memory_order_acquire))
        {
            update[0] = pred;
            *out_added = 1;
            return 1;
        }

        if (++cas_attempts > SKIP_LIST_MAX_CAS_ATTEMPTS)
        {
            (void)skip_list_free_node_internal(list, new_node);
            return 0;
        }
    }
}

int skip_list_put_batch(skip_list_t *list, const skip_list_batch_entry_t *entries,
                        const size_t count)
{
    if (list == NULL || entries == NULL || count == 0) return -1;

    /* the batched commit path bypasses the per-put min_seq bookkeeping, so fold the batch minimum
     * in once up front (a gap here lets a compaction reap a tombstone newer than batched-but-
     * unflushed data and resurrect the key). */
    uint64_t batch_min = UINT64_MAX;
    for (size_t i = 0; i < count; i++)
        if (entries[i].seq < batch_min) batch_min = entries[i].seq;
    skip_list_update_min_seq(list, batch_min);

    skip_list_node_t *header = atomic_load_explicit(&list->header, memory_order_acquire);

    /* a shared update array is reused across batch entries to avoid per-entry allocation */
    skip_list_node_t *stack_update[SKIP_LIST_STACK_UPDATE_SIZE];
    skip_list_node_t **update;
    const int use_stack = (list->max_level < SKIP_LIST_STACK_UPDATE_SIZE);
    if (use_stack)
        update = stack_update;
    else
    {
        update = malloc((size_t)(list->max_level + 1) * sizeof(skip_list_node_t *));
        if (!update) return -1;
    }
    for (int i = 0; i <= list->max_level; i++) update[i] = header;

    skip_list_batch_hint_t hint = {NULL, 0, 0};
    int success_count = 0;
    size_t batch_data_bytes = 0;
    size_t batch_memory_bytes = 0;
    int batch_entry_count = 0;

    for (size_t e = 0; e < count; e++)
    {
        const skip_list_batch_entry_t *entry = &entries[e];

        if (entry->key == NULL || entry->key_size == 0) continue;
        /* as in the single put, only a claim of bytes that were not supplied is skipped; an entry
         * carrying an empty value is applied like any other, and one carrying a value log id
         * supplied its bytes to the value log rather than to this call */
        if (!(entry->flags & (SKIP_LIST_FLAG_DELETED | SKIP_LIST_FLAG_VLOG_REF)) &&
            entry->value == NULL && entry->value_size > 0)
            continue;

        skip_list_node_t *current = skip_list_batch_seek(list, header, entry, update, &hint);

        /* fold into an existing key when the found position already holds it */
        skip_list_node_t *existing =
            atomic_load_explicit(&current->forward[0], memory_order_acquire);
        if (existing != NULL && !NODE_IS_SENTINEL(existing) &&
            skip_list_key_cmp(existing->key, existing->key_size, entry->key, entry->key_size) == 0)
        {
            if (skip_list_add_version_to_node(list, existing, entry) == SKIP_LIST_ADD_OK)
                success_count++;
            continue;
        }

        const int new_level = skip_list_random_level(list);
        const int current_level = atomic_load_explicit(&list->level, memory_order_acquire);
        if (new_level > current_level)
        {
            for (int i = current_level + 1; i <= new_level; i++) update[i] = header;
            atomic_store_explicit(&list->level, new_level, memory_order_release);
        }

        skip_list_node_t *new_node = skip_list_build_node(list, entry, new_level);
        if (new_node == NULL) continue;

        int added = 0;
        const int linked = skip_list_batch_link_base(list, entry, update, new_node, &added);
        if (added) success_count++;
        if (!linked) continue;

        skip_list_link_node_upper_levels(new_node, update, new_level);
        batch_data_bytes += entry->key_size + entry->value_size;
        batch_memory_bytes += SKIP_LIST_NODE_BYTES(new_level, entry->key_size) +
                              SKIP_LIST_VERSION_BYTES(skip_list_version_tail_bytes(
                                  entry->value, entry->value_size, entry->flags));
        batch_entry_count++;
    }

    /* one atomic update for the whole batch instead of per-entry */
    if (batch_entry_count > 0)
    {
        atomic_fetch_add_explicit(&list->data_bytes, batch_data_bytes, memory_order_relaxed);
        atomic_fetch_add_explicit(&list->memory_bytes, batch_memory_bytes, memory_order_relaxed);
        atomic_fetch_add_explicit(&list->entry_count, batch_entry_count, memory_order_relaxed);
    }

    if (!use_stack) free(update);
    return success_count;
}
