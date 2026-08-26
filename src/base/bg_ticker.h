/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_BASE_BG_TICKER_H__
#define __TIDESDB_BASE_BG_TICKER_H__

#include "../compat.h"

/* a single background thread that runs a tick callback once per interval, wakeable early. the
 * wal-sync loop and the reaper loops are instances, and the reaper decomposes into several tick
 * tasks on top of this -- the pthread lifecycle (timed wait, wake, stop, join) lives here rather
 * than being hand-rolled per loop. the tick runs first, then the thread waits the interval or until
 * woken. */
typedef struct bg_ticker bg_ticker_t;

/* the periodic work; ctx is the shared context handed to bg_ticker_start */
typedef void (*bg_ticker_fn)(void *ctx);

/**
 * bg_ticker_start
 * start a background thread that calls tick(ctx), then waits interval_us or until woken, and
 * repeats until stopped
 * @param interval_us wait between ticks in microseconds
 * @param tick the periodic callback
 * @param ctx opaque context passed to every tick
 * @return the ticker, or NULL on allocation or thread-creation failure
 */
bg_ticker_t *bg_ticker_start(uint64_t interval_us, bg_ticker_fn tick, void *ctx);

/**
 * bg_ticker_wake
 * nudge the ticker to run its next tick immediately instead of waiting out the interval. never
 * blocks. safe with NULL.
 * @param ticker the ticker to wake
 */
void bg_ticker_wake(bg_ticker_t *ticker);

/**
 * bg_ticker_stop
 * signal the ticker to stop, wake it, join its thread, and free it. a tick already running finishes
 * first. safe with NULL.
 * @param ticker the ticker to stop
 */
void bg_ticker_stop(bg_ticker_t *ticker);

#endif /* __TIDESDB_BASE_BG_TICKER_H__ */
