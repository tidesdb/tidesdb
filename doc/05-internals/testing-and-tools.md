---
title: Testing and Tools
description: The test suite, the four fuzz harnesses and their oracles, and the benchmark driver.
slug: internals/testing-and-tools
part: internals
sidebar:
  order: 18
---

# Testing and Tools

[Building](/administration/building) covers running these to check a build. This chapter is
about what they actually verify, and is written for someone changing the engine rather than
someone installing it.

## The test suite

Around fifty test binaries, one per module, built by default and run with `ctest`. They are
unit tests in the strict sense: each constructs its module directly, with no database anywhere.
That is possible because [no module below the engine takes a `tidesdb_t`](/internals/architecture),
and it is the main practical payoff of that rule.

Two suites are integration-level: `engine_tests` drives the public API end to end, and
`crash_recovery_tests` covers torn-write repair. That one arms a write to tear at a chosen point,
crashes a child the instant it lands, and reopens what was left — swept across every crash point in
three phases: a flush, the writes a commit itself issues, and a merge. The child is the same binary
run again rather than a fork, so it works where there is no `fork`.

Two are unusual. `doc_samples` compiles every C sample in this manual against the real public
header, so a sample that drifts from the API it documents fails the build. It also checks that every
backticked identifier in the prose exists somewhere in the sources, which is what catches a chapter
still naming a function that has been renamed away.

:::note[It builds its corpus by tokenising the sources, escapes included]
A name written only inside a string literal is glued to whatever escape precedes it: a tab followed
by a column heading is two characters plus the name, which a tokeniser reads as one word beginning
with a *t*. So the escapes are blanked before the split. Without that, prose could not name a
tab-separated column that the tool itself prints, and the failure reads as a missing identifier
rather than as a quoting artefact.
:::

`portability_create` and `portability_verify` are a pair. The first writes a database, the second
reopens it and reads every key back. Locally they run back to back as a round trip; in CI the
artifact produced on one architecture is verified on the others, which is what catches a format or
endianness divergence. They are built as ordinary targets rather than embedded in the
workflow, so a public API change breaks the build: a program that lives inside a CI file is seen by
no compiler until the job runs it, and can stop compiling against the API while the jobs keep
reporting success. They are also denied the internal include path, so they prove the public header
alone is sufficient to use the database.

:::caution[Assert on the contract, not on success]
The administrative calls — manual compaction, manual flush, backup, and the column-family
rename, drop and reconfigure paths — take an exclusive claim on a family, and answer
`TDB_ERR_LOCKED` when a compaction already holds it. Reads and writes never see this; a
transaction is unaffected by a compaction running underneath it.

A test that asserts `TDB_SUCCESS` on one of those calls is flaky by construction, and it will
usually pass — the window is narrow until a sanitizer widens it. Retry the way a caller must,
and pause between attempts: the claim is released by a background thread, so a tight retry loop
can exhaust its attempts in the time that thread needs to finish.
:::

## The fuzzers

Four harnesses, none enabled by default:

```sh
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo -DTIDESDB_BUILD_FUZZERS=ON
cmake --build build-fuzz -j
```

Each is **model-based**: the harness maintains an independent model of what the database should
contain and compares the engine against it. That is what makes them able to find wrong answers
rather than only crashes.

### `fuzz_standalone` — the logical model

Generates random operation sequences against both the engine and a versioned in-memory model,
then compares. Catches wrong values, lost writes, resurrected deletes, and visibility errors.

The model is version-aware — it tracks sequences and tombstones, because a model that compares only
latest values reports failures constantly, all of them its own fault rather than the engine's. When
a model disagrees with the engine, suspect the model first.

It also carries each entry's expiry, converted from the lifetime at the put exactly as the engine
converts it, and hides a version that has outlived it. The lifetimes the harness generates are only
ever *never* or a whole day, deliberately: expiry is decided by comparing against a second-granular
published clock, and a lifetime that elapsed part-way through a run would leave the model and the
engine on opposite sides of that boundary, making the oracle the thing that failed. What these
lifetimes do catch is the direction that matters — an expiry the engine loses or brings forward
turns into a key the model still expects and the database no longer has.

The harness now also generates **empty values**, roughly one in sixteen. An empty value is a value,
and the engine must not confuse it with an absent key; this is the oracle that says so under crash
and concurrency rather than only in a unit test.

It generates **interval deletes** too, both the two-bound and the prefix form, with bounds drawn from
the same small alphabet the keys use so an interval actually meets them. Modelling one is what forces
the transaction buffer to be an ordered log rather than a map: an interval hides what was buffered
before it and leaves what was buffered after, so position in the buffer is what decides which of the
two is newer, and a read resolves a key by finding the last entry that either names it or covers it.

The conflict oracle for an interval is **deliberately not symmetric**, because the engine's is not.
An interval is claimed against the other intervals only — there is no one key to hash it under — while
a point write is checked against both the intervals and the point reservations. So a point meeting
either kind must lose, and an interval meeting another interval must lose, but an interval meeting a
held point is allowed through. Mirroring that asymmetry is the difference between an oracle and a
source of false failures.

Alongside the value comparison it carries a **structural** oracle that owes nothing to the model. A
closed database owns no sstables and no level-set layouts, so both counts have to come back to what
they stood at when it opened — and that is checked at **every** close the run performs, not once at
the end. The granularity is the point: a balance checked once per run says only that something
between the first operation and the last leaked, while one checked per close names the twenty-odd
operations since the previous one.

The two counts are worth reading together when it fires. A leaked handle with the layouts balanced
is a reference some reader took and never gave back; a leaked layout means the sstables it lists are
pinned by a structure nothing will reclaim. They fail in the same way and have entirely different
causes, and separating them is what stops an investigation committing to the wrong one.

:::note[Pin a case rather than hope the seed stream finds it again]
A failing run's input is a file, not a seed. Dump it with `TIDESDB_FUZZ_DUMP_LAST` at the iteration
count that first fails, replay it alone with `./fuzz_standalone <file>` — seconds rather than
minutes — and drop it into `fuzz/corpus/model/` once it is understood. Everything there is replayed
by the `fuzz_standalone_corpus` test on every run, so a case found once stays covered whatever the
generator does next.

Cutting the repro before instrumenting anything is the order that works. Reading a 200-iteration
run's trace to find out which of thousands of operations mattered costs hours and usually settles
nothing.
:::

:::caution[The model holds committed state, not per-reader snapshots]
It keeps one latest-committed value per key and has no notion of *which* transaction is asking. A
read issued through a transaction at repeatable-read or above is filtered by that transaction's
snapshot, so the engine can legitimately hide a value the model holds — and the comparison then
reports a lost write that never happened.

The harness avoids this by settling the open transaction before any point where the two views are
compared against fresh commits — `fx_op_iter`, `fx_op_flush`, `fx_op_compact`, `fx_op_reopen` and
`fx_op_commit_prepared` all call `fx_commit_txn` first. Committing a prepared transaction is the
case that makes the omission visible, because it is the only operation that commits a *different*
transaction while leaving the reader's own open; every other commit path ends it. A failure of the
shape "db missed a key the model has", immediately after a `COMMIT_PREPARED` and with a long-lived
transaction open, is this and not an engine fault.

The principled fix is a snapshot-aware model that resolves a read at the asking transaction's
sequence. Until then, settling is what keeps the oracle honest, at the cost of not exercising a
long-lived reader across a prepared commit.
:::

### `fuzz_crash` — durability

Forks a child that commits under a sync barrier, kills it, reopens the database, and checks what
survived.

Its oracle is the sharpest of the four: the recovered state must be an **exact durable prefix**
of what was acknowledged. Not a superset — a torn final record must be discarded, not
half-applied — and not a subset. It fingerprints the model at every plausible prefix and requires
the recovered state to match one of them.

This is the harness that guards the ordering rules in [the write path](/internals/life-of-a-write).

### `fuzz_conc` — concurrency

Worker threads over disjoint key partitions, each with its own exact oracle, while the shared
memtable, write-ahead log, flush, compaction, cache, and value log all race underneath.

Partitioning the keyspace is what keeps the oracle exact under concurrency: each worker knows
precisely what it wrote, so any disagreement is a real engine fault rather than a race in the
checker.

### `fuzz_decode` — untrusted input

Feeds mutated bytes to the decoders — sstable footers, column-family configurations, WAL records,
partition range filters, btree nodes, and manifest batches.

These are the one place untrusted input enters the engine. Everything else operates on data the
engine itself wrote; a decoder operates on whatever is on disk, which after a crash or a bad
disk may be anything. A torn or corrupt file must be *rejected*, never over-read.

Several of them sit behind the block manager's checksum, which is why the bytes are handed to them
directly rather than written to a file first. Going through the file would only ever exercise the
checksum: random damage is caught before the decoder runs. What is left to get wrong is the part a
checksum says nothing about — a record loop walking offsets and lengths that are internally
consistent and still wrong.

### Controlling a run

| Variable | Effect | Honoured by |
| --- | --- | --- |
| `TIDESDB_FUZZ_ITERS` | Iterations to run | all four |
| `TIDESDB_FUZZ_SEED` | Seed, for reproducing a failure | all four |
| `TIDESDB_FUZZ_DIR` | Where databases are created | `fuzz_standalone`, `fuzz_crash`, `fuzz_conc` — `fuzz_decode` opens no database |
| `TIDESDB_FUZZ_DUMP` | Dump the failing input | `fuzz_standalone`, `fuzz_crash` |
| `TIDESDB_FUZZ_DUMP_LAST` | Write the last iteration's input to a file and run only that one, for cutting a single-iteration repro | `fuzz_standalone` |
| `TIDESDB_FUZZ_VERBOSE` | Per-operation tracing | `fuzz_standalone` |
| `TIDESDB_FUZZ_LOG`, `TIDESDB_FUZZ_LOG_FILE` | Engine log level and destination | `fuzz_standalone` |

The last three live in the model harness, which only `fuzz_standalone` and the coverage-guided
`fuzz_tidesdb` link; `fuzz_crash` and `fuzz_conc` build against the model alone and ignore them.

```sh
TIDESDB_FUZZ_DIR=/fast/disk TIDESDB_FUZZ_ITERS=200 ./build-fuzz/fuzz_crash
TIDESDB_FUZZ_SEED=519270 TIDESDB_FUZZ_VERBOSE=1 ./build-fuzz/fuzz_standalone   # reproduce
```

A failure prints its seed. Re-running with that seed reproduces it deterministically, which is
the first step of every investigation.

:::caution[Put fuzz data on fast storage]
Each iteration creates and tears down a database, so the run is dominated by filesystem work. On
spinning disks that is slow enough to read as a hang rather than a slow run. Give each concurrent
sweep its own directory.
:::

### Coverage-guided runs

Under Clang, two additional targets instrument the **whole library** rather than just the
harness, so a guided run explores the engine itself: `fuzz_tidesdb` for the logical model and
`fuzz_decode_guided` for the decoders. The decoders benefit most — they are small and branch
heavily on the input bytes, which is what coverage guidance is good at reaching.

The standalone runners need no instrumentation and build with any compiler, which is why CI uses
them.

## The allocation-failure sweep

An allocation being refused is the one failure a caller cannot arrange from outside, which makes
the code that runs afterwards — the half-built structure freed, the lock dropped, the handle never
published — the least travelled in the engine. `TIDESDB_WITH_ALLOC_FAULT` builds an injector that
counts the library's allocations and refuses a chosen one, and `alloc_fault_tests` measures how many
a small workload makes and then runs it once per allocation, refusing a different one each time.

Only the armed allocation fails, never the ones after it, so what each round exercises is one site's
unwind rather than a cascade in which the cleanup paths are also failing. What a round must show is
that the database still opens and still holds every commit it acknowledged — a refusal may cost a
write that never returned, and may cost the whole round, but never one the caller was told had
landed. Run it under the address sanitizer, which is what turns an abandoned partial structure into
a failure rather than a leak nobody sees.

The workload writes to **two** column families rather than one, which is not incidental. A flush
demuxes the shared memtable into one output per family, so a single-family workload produces a
single output and can never reach the unwind that returns an already-installed output's build
reference when a later one cannot be installed. The reachable set of a sweep like this is bounded by
what the workload actually does, and a path the workload cannot enter is not covered no matter how
many allocations are refused.

It needs a linker that can rewrite a symbol, so it is a build option rather than something always
present; see [Building](/administration/building#development-builds).

## What CI enforces

Beyond the platform matrix, four gates are worth knowing about because they fail builds that
otherwise look fine.

**Zero warnings.** `-Wall -Wextra` are always on but nothing makes them fatal, so a warning can
accumulate unnoticed. One lane compiles the library, the tests, the fuzz harnesses and the
benchmark driver with warnings as errors. It is the only job that fails on one, and it is the only
job that compiles the bench driver at all.

**Formatting.** Every first-party source directory is checked, not just `src` — the public header
and the test, fuzz and bench trees are maintained code too. Only vendored sources are exempt.

**Fuzzing.** All four harnesses run bounded, with the seed drawn from the run number so each build
explores new ground while any failure reproduces from the log.

**Thread sanitizer.** It cannot be combined with the address sanitizer, so without its own lane the
data races it finds have no coverage anywhere.

## The benchmark driver

```sh
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DTIDESDB_BUILD_BENCH=ON
cmake --build build-bench -j
./build-bench/tidesdb_bench --benchmarks=fillrandom --threads=8 --num=1000000 --dir=/fast/disk
```

### Workloads

| Workload | What it does |
| --- | --- |
| `fillseq` | Sequential inserts |
| `fillrandom` | Random inserts |
| `readrandom` | Point reads of present keys |
| `readmissing` | Point reads of absent keys — the filter path |
| `readwrite` | Mixed, split by `--read_ratio` |
| `deleterandom` | Random deletes |
| `deletewhileread` | Deletes concurrent with reads |
| `scan` | Range scans of `--scan_length` |
| `scanrange` | The same scans told their range up front, so the two forms can be compared on one dataset |
| `scanempty` | Bounded scans of a range holding no keys, in the **gap between two written keys** — what it costs to prove a range empty |
| `fillindex` | Builds a table family and an index family together, one row and the index entry pointing at it per transaction. Needs `--cfs=2`; it is what `indexscan` and `indexmixed` read |
| `indexscan` | A secondary-index `ref` join: seek the index family, then a point get on the **table** family per matching entry, which is what the MariaDB plugin's `index_read_secondary` issues. One op per lookup, since the lookup is the unit being measured. `--index_fanout` sets rows per indexed value |
| `indexmixed` | The same lookups running concurrently with writes, split by `--read_ratio`. The one to use for an index measurement that should mean anything — see the caution below |

Several may be given at once: `--benchmarks=fillrandom,readrandom,scan`.

:::caution[`scanempty` probes an interior gap on purpose]
A range past the last key is excluded by every sstable's recorded bounds before a block is read, so
it measures the pruning fast path rather than the question. The probe sits between two adjacent
written keys, where the bounds of every file spanning that point overlap it and none can be pruned.
**Check the cache counters before believing any latency from this workload** — `hits=0 misses=0`
means nothing was read and the fast path ate the experiment.
:::

:::note[Size the cache below the data when measuring the scan path]
`indexscan` and `scanempty` are about what a scan opens and reads. A cache large enough to hold the
store turns every one of those into a hit and the measurement flattens. Run them at a cache well
under the data size, and read `hit_rate` alongside throughput: a change that removes wasted lookups
lowers the hit rate while raising throughput, because the lookups it removed were the cheap hits.
:::

:::danger[Read the level table before believing any scan measurement]
Most of what the merge does costs one step per **source** — per sstable whose key range meets the
scan — so a change to that loop can only show up on a store that opens several. Range pruning makes
that number much smaller than the file count: L2 and beyond hold non-overlapping runs, so a narrow
lookup opens about one file per level however many files the level holds. Only L1 may overlap, and
only L1 contributes many sources.

So the number that decides whether the measurement can see anything is `read_amp` and the `L1=` count
in the per-cf table, **not** `sstables=`. A store at `read_amp 2.00` opens two sources, and against
it every per-source change measures as noise — correctly, because there is nothing there to remove.

Worse, the shape does not hold still. Compaction runs on open, so a store measured repeatedly drains
towards that state between runs while the benchmark is read-only and looks inert. Setting
`--l1_trigger` high at fill time does not prevent it, and neither does passing it again on the read
run. Re-read the level table on **each** run rather than assuming the shape you built is the shape
you measured.

That is why the index workloads come in two forms. A read-only `indexscan` lets compaction finish,
and a finished store has an empty L1 — so it measures the shallow case whatever it was built as.
`indexmixed` keeps writing while it reads, which is what holds L1 populated, and it is the one that
describes a store under live load.

Three more things an A/B needs to be worth anything:

- **A run of seconds, not tenths.** At a fraction of a second, thread ramp and cache warmth dominate
  and run-to-run spread reaches 40%. Use `--seconds`.
- **Interleaved variants** (`A B A B`), not all of A then all of B. Throughput drifts over a session
  and a blocked order aliases that drift onto the variable.
- **An identical starting state per point, restored from a snapshot.** This is the one that bites
  hardest on a sweep, because a store that is being written degrades as it grows, so whichever point
  runs first wins. A thread-count sweep run 1→16 reported throughput *falling* with more threads; the
  same sweep run 16→1 reported it rising fivefold. Copying the store back before each point, and
  scrambling the order, was what finally produced a curve that meant anything.

And profile only once compaction has drained. A profile taken straight after a fill is full of
compaction threads, and it moved the headline number by 30% here.
:::

:::danger[Anything about the store's shape needs `--rate`]
Read amplification, level depth and space amplification are **equilibria** between how fast data
arrives and how fast compaction takes it away. A change that drains faster lets the writers go
faster too, so an unrated run reaches a new balance at higher throughput and can settle at the very
same depth — having bought throughput rather than shallowness.

Comparing the depth of two unrated runs therefore measures nothing: the two ingested different
amounts. Pin the input rate with `--rate` so drain is the only variable, and pick the rate
deliberately — below both configurations' ceilings they will be identical, because both keep up and
there is nothing to see. The interesting rate sits between the two ceilings, where one sustains the
target and the other falls short.

Read `achieved` against the target, and the admission stall beside it. A configuration that misses
its target is the one that could not keep up, and the stall total says how long its writers were
parked for.

And do not compare `read_amp` between runs that were still writing when they ended. It is a snapshot
of wherever the compaction cycle happened to be: a run that has just finished a merge shows an almost
empty flush tier, one caught mid-merge shows a full one. The same configuration, run three times
under saturation, produced `read_amp` of 2, 12 and 2. Depth is comparable only on a settled store, or
as a time series through `cfstats.tsv` rather than as the single figure printed at the end.

Under saturation, ask about **write amplification** instead. It is the ratio of work done to data
stored, so it is meaningful whatever phase the run ends in, and it is what a change that quietly does
more work per byte would show up in. The driver's `write_amp` counts the write-ahead log and the
value log alongside flush and compaction, so it holds for a store that separates its values, where
the key logs are a rounding error and everything else would report a figure below one.
:::

### Options that change what you are measuring

| Option | Effect |
| --- | --- |
| `--threads`, `--num` | Concurrency and operation count |
| `--key_size`, `--value_size` | Record shape. **The single most consequential setting** — a value either side of `value_separation_threshold` exercises entirely different paths |
| `--dist`, `--zipf_theta` | Key distribution: uniform, zipfian, sequential |
| `--sync` | Durability mode; the largest single lever on write throughput |
| `--isolation` | 0–4; snapshot and above add conflict detection |
| `--cfs`, `--txn_ops` | Column families, and operations per transaction |
| `--memtable_size`, `--cache_size`, `--l0_stall` | The engine knobs most worth sweeping |
| `--flush_threads`, `--compaction_threads` | Background pool sizes |
| `--bloom`, `--bloom_fpr` | Filter on or off, and its false-positive target |
| `--seconds` | Run each workload for a wall-clock duration instead of to its operation count. Prefer it: a run bounded by operations takes whatever time it takes, and at high thread counts that is often a fraction of a second |
| `--compression` | The column families' encoding pipeline — `none`, `snappy`, `lz4`, `lz4fast`, `zstd`. **A store that compresses is a different engine from one that does not**: every key-log node is encoded on the way out and decoded on every read that misses the cache, so a benchmark left at `none` does not describe a deployment that sets it |
| `--index_fanout` | Rows sharing one indexed value, for `fillindex` and the index workloads |
| `--rate` | Hold total throughput to N operations per second. **Required for any question about the store's shape** — see below |
| `--seed` | Reproducibility |

### Options that change the tree's shape

These drive the compaction structure itself, which is what a sweep of the layout varies. **Each one
left unset keeps the engine's own default**, so an unswept run stays comparable to a swept one.

| Option | Effect |
| --- | --- |
| `--level_size_ratio` | `T`, the ratio between successive level capacities. Smaller deepens the tree sooner and raises write amplification |
| `--dividing_level_offset` | How far above the largest level the dividing level sits. 1 means `X = L - 2` |
| `--min_levels` | Floor on the level count |
| `--l1_trigger` | Flush-tier runs that make a compaction due |
| `--tombstone_density`, `--tombstone_min_entries` | The density trigger and the entry count below which it is ignored |
| `--value_separation_threshold` | Where values spill to the value log. Pairs with `--value_size` |
| `--btree_block_size` | Target klog node size |
| `--idle_flush_seconds` | Timer that rotates an idle non-empty memtable |
| `--skip_list_max_level`, `--skip_list_probability` | Memtable skip-list shape |

A worked contrast, on the same 2M-key load: the defaults (`T=10`) settle at two levels with read
amplification 2.0 and write amplification near 1.5, while `--level_size_ratio=5 --l1_trigger=2`
reaches three levels but pays read amplification 6-7 and write amplification 4.4. Deepening the tree
is not free, and at a given data size it may buy nothing.

### Time series output

`--sample_interval_ms=N` starts a background sampler writing tab-separated series into the data
directory, one file per stream:

| File | Contents |
| --- | --- |
| `throughput.tsv` | Operations per second over time |
| `resource.tsv` | Process CPU, resident memory, and live heap |
| `dbstats.tsv` | Database statistics, including the backpressure counters |
| `cfstats.tsv` | Per-column-family statistics |
| `cachestats.tsv` | Block cache hits, misses, residency |

Every row is flushed as it is written. A run that is killed -- by the OOM killer, by a watchdog, by
an operator who has seen enough -- is exactly the run whose series matters, and a buffered stream
loses the tail of it, which on a short run is the whole file.

:::caution[`live_mb` is unreliable under threads]
It comes from glibc's `mallinfo2`, which accounts only the main arena. On a multi-threaded run most
allocation happens in per-thread arenas and the figure has been observed reporting more than the
machine holds. Treat `rss_mb` as the measurement and `live_mb` as a hint at best; to separate live
heap from allocator retention, re-run under a different allocator rather than trusting this column.
:::

Each plots directly. The series matter more than the summary for anything involving flush or
compaction, because the interesting behaviour is a stall partway through a run and a single
average hides it.

### Reading the results

Three rules, all learned the hard way:

**Interleave your A/B.** Run baseline and variant alternately in one session. Comparing against a
number from last week measures the machine, not your change.

**Take enough samples for the metric.** Throughput stabilises within a few runs; tail latency
does not. Repeated runs of one unchanged build can spread tail percentiles wide enough that a
two-sample comparison tells you nothing, so take several and compare medians.

**Run long enough to leave the drive's write cache.** A short run on a consumer SSD measures its
write cache rather than the drive, and the two differ by orders of magnitude. Decide which regime
you care about before choosing a size, and before concluding anything about the engine from a
sustained run, write the same volume with `dd` to the same filesystem — that control tells you
whether the device was the limit rather than the engine.

Also: benchmark a **Release** build, never a sanitizer build, and keep the data directory off any
disk something else is using.
