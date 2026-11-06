/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "sstable/vlog_internal.h"

#ifdef TDB_FAULT_INJECTION
static void (*vlog_scrub_pin_hook)(vlog_t* v, uint32_t slot);

void vlog_test_set_scrub_pin_hook(void (*hook)(vlog_t* v, uint32_t slot))
{
    vlog_scrub_pin_hook = hook;
}
#endif

/* the ticker is the only cursor owner. file numbers are never reused. keep its reference only
 * through this pass's reads, and check the number under a new reference before resuming. */
static int vlog_scrub_pin(vlog_t* v)
{
    vlog_scrub_t* s = v->scrub;
    if (s->active)
    {
        if (vlog_segment_acquire(v, s->slot))
        {
            if (v->segments[s->slot].number == s->number) return 1;
            vlog_segment_release(v, s->slot);
        }
        s->active = 0;
        return 0;
    }

    const uint32_t high = atomic_load_explicit(&v->seg_high, memory_order_acquire);
    for (uint32_t i = 0; i < high && i < VLOG_SCRUB_SLOT_SCAN_MAX; ++i)
    {
        const uint32_t slot = s->cursor;
        s->cursor = (slot + 1) % high;
        if (!atomic_load_explicit(&s->sealed_extents[slot], memory_order_acquire) ||
            !vlog_segment_acquire(v, slot))
            continue;
        const uint64_t extent =
            atomic_load_explicit(&s->sealed_extents[slot], memory_order_acquire);
        if (extent > BLOCK_MANAGER_HEADER_SIZE)
        {
            s->slot = slot;
            s->number = v->segments[slot].number;
            if (bm_frame_verify_init(&s->frame, s->checksum, BLOCK_MANAGER_HEADER_SIZE, extent) ==
                BM_FRAME_VERIFY_MORE)
            {
                s->active = 1;
                return 1;
            }
        }
        vlog_segment_release(v, slot);
    }
    return 0;
}

static int vlog_scrub_frames(vlog_scrub_t* s, int fd, size_t byte_budget, size_t read_budget,
                             vlog_scrub_pass_t* out)
{
    while (out->bytes_read < byte_budget && out->reads < read_budget)
    {
        out->frame_offset = s->frame.offset;
        size_t bytes = 0, reads = 0;
        const int rc = bm_frame_verify_step(&s->frame, fd, byte_budget - out->bytes_read,
                                            read_budget - out->reads, &bytes, &reads);
        out->bytes_read += bytes;
        out->reads += reads;
        if (rc == BM_FRAME_VERIFY_MORE) return VLOG_OK;
        if (rc != BM_FRAME_VERIFY_DONE)
        {
            if (rc == BM_FRAME_VERIFY_ERR_CORRUPTION) return VLOG_ERR_CORRUPTION;
            if (rc == BM_FRAME_VERIFY_ERR_MEMORY) return VLOG_ERR_MEMORY;
            return VLOG_ERR_IO;
        }

        const uint64_t next = s->frame.offset + block_manager_framed_size(s->frame.payload_size);
        if (next == s->frame.extent_limit)
        {
            out->complete = 1;
            break;
        }
        if (bm_frame_verify_init(&s->frame, s->checksum, next, s->frame.extent_limit) !=
            BM_FRAME_VERIFY_MORE)
            return VLOG_ERR_INVALID;
    }
    return VLOG_OK;
}

int vlog_scrub_pass(vlog_t* v, size_t byte_budget, size_t read_budget, vlog_scrub_pass_t* out)
{
    if (!v || !out || byte_budget < BLOCK_MANAGER_BLOCK_HEADER_SIZE || !read_budget)
        return VLOG_ERR_INVALID;
    *out = (vlog_scrub_pass_t){0};
    if (!v->scrub || !vlog_scrub_pin(v)) return VLOG_OK;

    vlog_scrub_t* s = v->scrub;
    out->frame_offset = s->frame.offset;
    out->segment_number = s->number;
    out->group = v->segments[s->slot].group;
#ifdef TDB_FAULT_INJECTION
    if (vlog_scrub_pin_hook) vlog_scrub_pin_hook(v, s->slot);
#endif
    int fd = -1, owned = 0;
    int rc = vlog_segment_scrub_fd(v, s->slot, &fd, &owned);
    if (rc == VLOG_OK)
    {
        rc = vlog_scrub_frames(s, fd, byte_budget, read_budget, out);
        if (owned)
        {
            if (tdb_file_close(fd) != 0 && rc == VLOG_OK) rc = VLOG_ERR_IO;
            fd_manager_note_close(v->fdm, FD_LABEL_VLOG_SEGMENT);
        }
    }
    vlog_segment_release(v, s->slot);
    if (rc != VLOG_OK || out->complete) s->active = 0;
    return rc;
}
