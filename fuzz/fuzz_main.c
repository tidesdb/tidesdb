/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stddef.h>
#include <stdint.h>

#include "fuzz_harness.h"

/* the libFuzzer entry point: one input drives one model-checked run at the logical (fast) sync mode
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_run(data, size, FUZZ_SYNC_NONE);
}

#ifdef FUZZ_STANDALONE
/* built without libFuzzer (e.g. the gcc ci build), this main replays given input files or, with
 * none, runs a fixed number of deterministic pseudo-random inputs so the harness doubles as a
 * regression test. TIDESDB_FUZZ_ITERS and TIDESDB_FUZZ_SEED tune the generated run. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_STANDALONE_DEFAULT_ITERS 200
#define FUZZ_STANDALONE_MAX_INPUT     4096

/* a small deterministic generator so a seed reproduces the same input stream */
static uint64_t fuzz_rng_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static long fuzz_env_long(const char *name, long fallback)
{
    const char *v = getenv(name);
    return v ? strtol(v, NULL, 10) : fallback;
}

/* the seed needs its own reader rather than the long one above. a seed is a full 64-bit value, and
 * long is 32 bits on plenty of the platforms this builds for -- passing the default through it
 * truncates the constant to something else entirely, so the same command would seed one run
 * differently depending on the machine it ran on */
static uint64_t fuzz_env_u64(const char *name, uint64_t fallback)
{
    const char *v = getenv(name);
    return v ? (uint64_t)strtoull(v, NULL, 0) : fallback;
}

static int fuzz_replay_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        fprintf(stderr, "cannot open %s\n", path);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    const long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n > 0 ? (size_t)n : 1);
    if (!buf)
    {
        fclose(f);
        return 1;
    }
    const size_t got = n > 0 ? fread(buf, 1, (size_t)n, f) : 0;
    fclose(f);
    fprintf(stderr, "replay %s (%zu bytes)\n", path, got);
    fuzz_run(buf, got, FUZZ_SYNC_NONE);
    free(buf);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        int rc = 0;
        for (int i = 1; i < argc; i++) rc |= fuzz_replay_file(argv[i]);
        return rc;
    }

    const long iters = fuzz_env_long("TIDESDB_FUZZ_ITERS", FUZZ_STANDALONE_DEFAULT_ITERS);
    uint64_t state = fuzz_env_u64("TIDESDB_FUZZ_SEED", 0x9e3779b97f4a7c15ULL);
    if (state == 0) state = 0x9e3779b97f4a7c15ULL;

    const char *dump_last = getenv("TIDESDB_FUZZ_DUMP_LAST");

    uint8_t *buf = malloc(FUZZ_STANDALONE_MAX_INPUT);
    if (!buf) return 1;
    for (long it = 0; it < iters; it++)
    {
        const size_t len = (size_t)(fuzz_rng_next(&state) % FUZZ_STANDALONE_MAX_INPUT) + 1;
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)fuzz_rng_next(&state);

        /* cutting a single-iteration repro. bisect the iteration count to the first that fails,
         * then run again with this set to write that iteration's input out and run only it. the
         * earlier iterations still advance the generator, so the input is the one the full run
         * would have produced, and replaying the file afterwards reproduces the failure in seconds
         * instead of minutes -- which is the difference between a case that can be instrumented
         * and one that can only be stared at */
        if (dump_last != NULL)
        {
            if (it != iters - 1) continue;
            FILE *f = fopen(dump_last, "wb");
            if (f)
            {
                (void)fwrite(buf, 1, len, f);
                (void)fclose(f);
            }
        }
        fuzz_run(buf, len, FUZZ_SYNC_NONE);
    }
    free(buf);
    fprintf(stderr, "standalone fuzz: %ld iterations passed\n", iters);
    return 0;
}
#endif /* FUZZ_STANDALONE */
