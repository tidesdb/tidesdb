---
title: Invariants
description: The rules the engine must never break, where each comes from, and what would catch a violation.
slug: internals/invariants
part: internals
sidebar:
  order: 16
---

# Invariants

The preceding chapters each end with the rules their subsystem depends on. This chapter
collects them in one place, and adds the column that matters most: **what would catch a
violation.**

An invariant is only as good as the check that enforces it. A rule stated in a comment and
guarded by nothing is not an invariant — it is a hope, and it will be broken by the next person
who has a good reason to restructure the code. So the third column here is not decoration. It
is the audit, and where it says *unguarded*, that is a real gap and a place to add a test.

## How to read this

Each entry names the rule, links to the chapter that motivates it, and states what would fail
if the rule were broken. The enforcement column distinguishes three cases:

- **A named test or fuzzer** — a violation makes something go red.
- **Indirect** — no test targets the rule, but a violation would likely surface through a
  broader test that happens to depend on it. Better than nothing, and worse than it sounds:
  indirect failures point at the symptom, not the rule.
- **Unguarded** — nothing would catch it. These are the entries to act on.

## Durability and ordering

| Invariant | From | Enforcement |
| --- | --- | --- |
| The write-ahead log must contain no gaps — only the contiguous completed run is written | [Block manager](/internals/block-manager) | `fuzz_crash` (exact-prefix oracle); `block_manager` tests cover the ring, not the gap property directly |
| A range tombstone lives exactly as long as a table carrying it, and is honoured by every read that reads that table | [Compaction](/internals/compaction) | `test_engine_range_tombstone_lives_as_long_as_a_table_carries_it`; `test_flush_output_carries_its_memtable_intervals`; `test_cf_source_compaction_carries_input_intervals` |
| A merge leaves an interval behind only when it has finished its work -- largest level, sequence below the reclamation floor, and no sstable outside the merge reaching into its range | [Compaction](/internals/compaction) | `test_cf_source_compaction_drops_an_interval_it_has_finished` -- the bound on what a table accumulates. Every uncertainty in the check counts as reaching in, so it keeps intervals it could have dropped rather than dropping one it could not |
| A read that misses reports absence only if the level shape stood still while it looked | [Life of a read](/internals/life-of-a-read) | `test_engine_read_survives_a_compaction_moving_levels` |
| Data is durable before the manifest names it | [Manifest](/internals/manifest) | `fuzz_crash`; `test_crash_recovery_torn_flush`, and `test_crash_recovery_torn_wal_append` for the writes a commit itself issues |
| A write-ahead log is unlinked only after its data reaches L1 | [Memtable and WAL](/internals/memtable-and-wal) | `test_engine_write_recovery`, `test_engine_prepared_survives_flush` |
| The batch reaches the log before the memtable | [Life of a write](/internals/life-of-a-write) | `fuzz_crash` |
| A separated value reaches the value log before the record naming it | [Life of a write](/internals/life-of-a-write) | `fuzz_crash` — the other order would let a crash leave a record pointing at bytes that are not there, where this one only leaves reclaimable garbage |
| Every holder of a value log reference is either counted or covered by a floor | [Value log](/internals/value-log) | `test_engine_prepared_batch_keeps_its_separated_values`, `test_engine_separated_value_survives_reopen_and_reclaim`, and the pinned `fuzz_standalone` corpus. There are three holders besides the installed tables — a memtable, an in-flight build, and an undecided prepared batch — and each was found by losing data |
| Manifest rollover is write-temp-then-rename | [Manifest](/internals/manifest) | `manifest` tests |
| `ftruncate` is synced explicitly — `O_DSYNC` does not cover it | [Block manager](/internals/block-manager) | **Unguarded** — no test kills a process between a truncation and its sync |
| The value log is durable via `O_DSYNC`, not via a flush-time barrier | [Value log](/internals/value-log) | **Unguarded** — a change to that open would not fail any test, and the comment warning against it is the only guard |
| Closing a block manager drains its staging ring before closing the descriptor | [Memtable and WAL](/internals/memtable-and-wal) | `test_l0_wal_ack_on_stage_survives_close` — under `TDB_SYNC_NONE` nothing else makes a staged record durable, so breaking this loses data on a *clean* shutdown, which no crash test would catch |
| Only `TDB_SYNC_NONE` acknowledges a commit before its record leaves the process | [Durability](/concepts/durability) | `fuzz_crash` runs at `TDB_SYNC_FULL`, so its exact-durable-prefix oracle guards the modes that promise this and deliberately does not exercise the one that does not |

## Visibility and ordering of state

| Invariant | From | Enforcement |
| --- | --- | --- |
| A flush retains a key's version chain against the reclamation floor | [Memtable and WAL](/internals/memtable-and-wal) | `test_engine_frozen_snapshot_survives_a_flush` — a memtable holds the whole chain while a flush writes one sstable, so a flush taking only the newest version dropped everything under it whatever the floor said. A repeatable-read reader below an overwrite then read a live key as absent, which the default isolation level never sees because it re-reads |
| A read at a bare sequence refuses below the oldest readable point | [Transactions and MVCC](/internals/transactions-and-mvcc) | `test_engine_read_at_a_collected_sequence_is_refused`, `test_engine_oldest_readable_seq_resets_on_open` — below it a merge has kept one version per key, so answering would report a key that existed as absent. The watermark rises where a floor is taken rather than where the collection ends, so a merge already running is visible to the check |
| A named snapshot holds the floor by being registered | [Transactions and MVCC](/internals/transactions-and-mvcc) | `test_engine_snapshot_holds_versions_a_compaction_would_have_collected`, `test_engine_snapshot_holds_and_releases_the_reclamation_floor` — a sequence remembered outside the registry protects nothing, and a read there answers from what a merge happened to leave rather than from what was true |
| A directory is held by one handle at a time | [Database](/reference/database#tidesdb_open) | `test_engine_second_open_is_refused` — an exclusive lock file plus a recorded owner pid, since `fcntl` locks are per-process and would otherwise let one caller re-lock a directory it already holds. A second open is refused with `TDB_ERR_LOCKED` rather than being allowed to share the store |
| A rotation takes the prepared log's generation under the same claim the preparer wrote it under | [Memtable and WAL](/internals/memtable-and-wal) | **Unguarded** — taking the spare empties the slot, which lets the next preparer overwrite the generation field before the taker has read it. The memtable would then be named for a log it does not hold, and the flush that asks whether that generation is pinned would ask about the wrong file. Found by ThreadSanitizer under `fuzz_conc`, not by any test asserting it |
| The log a rotation installs is opened before the rotation, off the lock | [Memtable and WAL](/internals/memtable-and-wal) | **Unguarded** — nothing asserts a rotation does no file creation, and opening one inline costs 49 ms with every committer stopped. The engine logs a slow prepare separately from a slow rotation, and times the log open on its own inside both, so a rotation that overran can be read as the open or as the rest rather than as one number covering both |
| The rotation lock is never held across a wait or a device barrier | [Memtable and WAL](/internals/memtable-and-wal) | **Unguarded** — no test measures lock hold time. Two of the three violations found were caught only by capturing stalled commits' stacks under load; the third was the fullness re-check itself, which measured the memtable while holding the lock and so took the memtable's pin and its range tombstone lock, both of which wait. That one was found from a CI stall breakdown showing a rotation far longer than every phase timed inside it, and is why the re-check now compares a rotation marker instead of measuring anything. A reviewer adding a wait under this lock would still see nothing fail |
| Rotation enqueues the sealed memtable before swapping the active slot | [Memtable and WAL](/internals/memtable-and-wal) | `fuzz_conc`; `test_l0_rotate_and_read` covers rotation but not the ordering window |
| Shallower is newer — flush installs are strictly ordered | [Life of a read](/internals/life-of-a-read) | Indirect: `flush`, `test_engine_overwrite_across_recovery` |
| A drawn but uncommitted sequence is invisible | [Transactions and MVCC](/internals/transactions-and-mvcc) | `mvcc` tests |
| A column family configuration is published whole, never written through | [Column family](/reference/column-family) | `column_family` tests; TSan across the suite — a reader takes an immutable snapshot, so no flush or plan ever sees half of one configuration and half of another |
| The memtable's reported size counts every resident version, not every key | [Memtable and WAL](/internals/memtable-and-wal) | `test_skip_list_size_counts_every_version` |
| The rotation threshold reads memory occupied, not key and value bytes | [Memtable and WAL](/internals/memtable-and-wal) | `test_skip_list_memory_bytes_counts_structural_overhead` — a node, its pointer arrays and a version struct are about 100 bytes an entry, so counting only the data lets a memtable of small entries hold several times the memory its configuration asks for |
| A version costs its structure plus its value, so a tombstone is not free | [Memtable and WAL](/internals/memtable-and-wal) | `test_skip_list_size_counts_tombstone_versions` |
| `BUSY` short-circuits the source stack rather than falling through | [Life of a read](/internals/life-of-a-read) | `source` tests |
| A level's candidates come from one layout load, not a count then a collect | [Life of a read](/internals/life-of-a-read) | **Indirect** — `fuzz_conc` would surface the stale answer. Two loads let a flush install between them, leaving the collected set a subset of what the count promised, so the highest sequence among the candidates was not the highest that existed. The collect reports the true overlap count even when more overlap than fit, which is what lets one load do both. A caller that keeps the two loads must read only what the collect wrote, never the array it sized from the count -- a level set that *shrank* between them leaves the tail of that array unwritten, and `ce_resolve_inputs` dereferenced it as an sstable and then unreferenced it, which is a garbage pointer rather than the stale answer this entry used to describe |
| The deep-level candidate window agrees with a scan of the level | [Life of a read](/internals/life-of-a-read) | `test_level_set_deep_level_window_matches_a_full_scan` — L2+ runs are non-overlapping and sorted by min_key, so two binary searches bound the files meeting a range. A window starting one file late drops a file that holds the key and the lookup reports it absent; the test checks every boundary and gap differentially against a brute-force overlap |
| A tombstone or expired entry is a definitive absence, not a fall-through | [Life of a read](/internals/life-of-a-read) | `test_l0_tombstone`, `ttl` tests |
| Phase two draws a fresh sequence | [Transactions and MVCC](/internals/transactions-and-mvcc) | `test_engine_recovered_phase_two_durable_and_ordered`, `test_engine_settled_prepare_lands_above_writes_it_was_in_doubt_through` |
| An sstable's footer sequence bounds every version it holds | [Transactions and MVCC](/internals/transactions-and-mvcc) | **Indirect** — `fuzz_standalone` and `fuzz_conc` would surface a missed conflict, but nothing asserts the footer bound itself. A footer understating its contents would make the commit conflict scan skip an sstable that does hold a newer version, and the write it should have rejected would be accepted |

## Reclamation and lifetime

| Invariant | From | Enforcement |
| --- | --- | --- |
| A memtable is freed only after readers drain | [Memtable and WAL](/internals/memtable-and-wal) | `test_l0_retire_is_observable_to_a_bracketed_read`; TSan across the suite |
| A lookup's level-0 walk reports "not yet known", never "absent" | [Memtable and WAL](/internals/memtable-and-wal) | **Unguarded** -- the skip list's descent settles on a predecessor and then walks level 0 to the key, because an insert can splice a smaller key in between. Stopping that walk on a key *below* the target reports a present key as missing, and so does running its budget out and calling the result absent; the walk therefore continues while it is below, is bounded by the list's own entry count plus slack rather than by a flat constant, and hands back a retry that re-descends rather than an absence. `test_skip_list_lookup_never_misses_a_present_key_under_splicing` guards the coarse form of this, but it does **not** reach the narrow window -- reinstating a single-load hop still passes it, because landing an insert between a descent finishing and its next load needs an interleaving a test cannot force. `fuzz_conc` is the only other cover |
| A reclaim never retires the segment taking appends | [Value log](/internals/value-log) | `test_retire_refuses_the_segment_taking_appends` -- calls retire on the active slot directly, which is the same question the race asks, and asserts the store keeps writing and reading afterwards. A reclaim reads the active slot per segment rather than once per pass, and the retire re-reads it after claiming the eviction window; deciding against one stale reading would let a roll mid-pass hand it the segment taking appends, whose file it would then unlink |
| No engine-internal error code reaches a public caller | [Error codes](/appendix/error-codes) | **Unguarded** -- `tdb_public_rc` in db.c is the single choke point that maps `TDB_ERR_BUSY` to `TDB_ERR_LOCKED`, and nothing fails if a new public function forwards an engine result without it; the code db.h does not define would reach a caller's switch and `tidesdb_strerror` would call it unknown |
| The plan memo is keyed on the shape and the reclamation floor together | [Compaction](/internals/compaction) | `test_engine_scheduler_replans_when_the_gc_floor_moves` -- opens a snapshot transaction and asserts the family is planned again with no write having landed |
| A subdivided merge writes the same files as an undivided one | [Compaction](/internals/compaction) | `test_compaction_subdivided_merge_matches_one_thread` -- runs the same merge with and without permission to split, and requires the same output count and the same value for every key. the split is at the boundaries the sink already rolls on, so the files are the same files; if that stopped holding, a merge's result would depend on how many threads were free, which is not a thing a storage engine may do |
| A plan that produced jobs is never memoized | [Compaction](/internals/compaction) | **Unguarded** -- proving it needs a compaction job to fail while the layout stays put, which the suite has no way to force without fault injection. The failure is silent: the family simply stops being scheduled, and on an idle database that is permanent. Emptiness is read from the plan's job count and from nothing else -- deriving it from whether some allocation succeeded would let a failed `malloc` memoize a family that did have work |
| An idle non-empty memtable is rotated on a timer | [Memtable and WAL](/internals/memtable-and-wal) | `test_engine_idle_flush_rotates_an_unwritten_memtable` -- writes under the rotation threshold and asserts the data reaches L1 with no further write |
| Only the handle that installed the log sink closes it | [Troubleshooting](/administration/troubleshooting) | `test_engine_log_to_file_writes_into_the_database_directory` -- opens a second database without `log_to_file` and asserts the first one's file stopped growing rather than being truncated or reopened |
| An undecided prepare pins its own log generation and no other | [Transactions and MVCC](/internals/transactions-and-mvcc) | `test_engine_undecided_prepare_pins_only_its_own_generation` -- one prepare left in doubt across six flushed generations; keyed on a database-wide count instead it retained all seven |
| A batch recovered in doubt keeps its log across later flushes | [Transactions and MVCC](/internals/transactions-and-mvcc) | `test_engine_recovered_in_doubt_batch_survives_later_flushes` -- reopens, writes and flushes without ever asking for the in-doubt list, then decides the batch |
| A snapshot's references are dropped on every path out, including the mismatch | [Compaction](/internals/compaction) | **Unguarded** -- a layout that *grew* past the caller's array references nothing, but one that **shrank** between sizing and filling is referenced in full and returns a count that does not match, so a caller treating the mismatch as a failure still owes those references. Forcing that race in a test is not currently possible. Every call site now releases across the whole zeroed array, which is the only form that cannot leak; the one that returned early instead leaked a reference per table on each attempt, pinning it for the life of the process |
| A family's reported size counts its key logs exactly once | [Statistics](/reference/statistics) | `test_engine_cf_data_size_counts_key_logs_once` -- asserts it equals both the sum of `level_sizes` and the real bytes on disk; adding the summed value length on top doubles it for any workload whose values stay inline |
| A borrowed root is never released by the descent that used it | [Life of a read](/internals/life-of-a-read) | `test_get_borrows_a_root_held_across_reads` -- reads a tree whose root is internal through a cache too small to hold it, so the root's frame is evicted while pinned and a descent that released the borrowed node would drop the sstable's own reference and free it under the next reader |
| A log that will never be written to is unlinked, not just closed | [Memtable and WAL](/internals/memtable-and-wal) | `test_engine_preparing_a_spare_log_strands_no_file` -- releases sixteen preparers together and asserts at most one log joined the directory; closing the loser's descriptor without unlinking its file stranded one log per losing committer per rotation, and each one is scanned, replayed and given a memtable on every later open |
| An entry lapses wherever it lives, not only in the memtable | [Life of a read](/internals/life-of-a-read) | `test_ttl_expires_after_reaching_an_sstable` -- flushes while the deadline is still ahead, so the entry reaches the sstable live and only lapses there. Expiry has to be evaluated on every source a version can be read from; confining it to the skip list and to the flush that converts a lapsed version to a tombstone would leave any lifetime longer than the flush interval never expiring at all |
| Every source ages an entry against the same published second | [Life of a read](/internals/life-of-a-read) | `test_get_ages_entries_against_the_injected_clock` -- publishes a clock, reads the entry live one second short of its deadline, then advances only that clock and asserts the same read now answers as a tombstone. The memtable's list and every sstable read one value a ticker publishes rather than calling `time(NULL)` per entry; two clocks a second apart would let a key read live from one source and lapsed from another, and the read would fall through to whichever answered |
| A tombstone is the only thing that means absent | [Data model](/concepts/data-model) | `test_engine_an_empty_value_reads_back_as_present` -- stores a zero-length value and requires it present out of the memtable, out of an iterator, out of an sstable after a flush and out of the replayed log after a reopen, while a real delete still reads as not-found. the write path once refused it, and refused it only at apply, after the batch was durable -- so the caller saw an I/O error from commit for what was a legitimate write. the model fuzzers now generate empty values about one time in sixteen |
| A lapsed entry is collected by a merge, not by the read that hides it | [Compaction](/internals/compaction) | `test_ttl_expired_entry_is_collected_by_compaction` -- asserts the family's live key total falls across a forced compaction, so the bytes go rather than the key merely reading as absent forever |
| A lapsed entry shadows an older version rather than reading as absent | [Life of a read](/internals/life-of-a-read) | **Unguarded** -- reading it as absent would let an older version beneath it surface, but the fall-through is not reachable through the public api: a flush triggers a compaction that merges the two versions into one run before any read can observe it, and both mutations of this rule leave the suite green. The sibling case it generalises is guarded at the unit level by `test_compaction_keeps_tombstone_with_sibling` |
| A scan costs its range, not its family | [Iterators](/internals/iterators) | `test_cf_iter_narrow_range_scan_does_not_open_every_sstable` -- 32 disjoint sstables, a four-key scan, and an assertion that fewer than one cache lookup per sstable was taken; unbounded it took 128 for those four keys, which is how concurrent range scans saturated the cores while each wanted almost nothing |
| Pruning sources never drops one a scan needs | [Iterators](/internals/iterators) | `test_cf_iter_full_scan_spans_every_sstable` -- an unbounded scan over the same 32 sstables still returns every key, so a selection rule that dropped a live source would fail rather than silently shorten the stream |
| A merge never targets the flush tier | [Compaction](/internals/compaction) | `test_planner_merge_always_leaves_the_flush_tier` -- a two-level family with its tier over the file trigger, asserting both the chosen target and the emitted job's target sit below L1; targeting L1 consolidates the tier in place and leaves it growing one run per flush |
| The tree gains a level when its largest is full | [Compaction](/internals/compaction) | `test_plan_grows_a_level_when_the_largest_is_full` -- without it a family stops deepening, the dividing level collapses onto the flush tier, and the tier grows a run per flush with nowhere to drain to |
| A partitioned merge fans out only when no input spans a boundary | [Compaction](/internals/compaction) | `test_plan_partitioned` covers the aligned case fanning out into disjoint jobs; `test_plan_partitioned_spanning_input` covers the fallback -- sharing a spanning input across per-partition jobs lets only the first run, dropping a tombstone without the versions it shadows |
| Ingestion is paced against merge progress as well as flush progress | [Memtable and WAL](/internals/memtable-and-wal) | `test_tier_band_paces_against_merge_progress` -- asserts the tier band admits below its slow mark, dwells further past it, blocks at the stall mark, and is inert when told to weigh no tier; without it a burst outruns compaction and leaves a tier every later read merges across |
| A plan's jobs run concurrently and the last one out tears the plan down | [Compaction](/internals/compaction) | **Indirect** -- ASan and TSan across the suite. The claim is released only when the final job finishes, which is what a family drop waits on, and a queue drain pays the same count through `engine_job_group_release` |
| A chunk is sized to the object it holds | [Block cache](/internals/block-cache) | **Indirect** -- `ENGINE_NODE_ARENA_CHUNK_SIZE` is defined from `TDB_DEFAULT_CF_BTREE_BLOCK_SIZE` so the two cannot drift, but nothing fails if they do. they had already drifted sixteen-fold, and the only symptom was a cache holding a thirty-second of its budget in useful data -- no test covers the ratio of a frame's chunk to the node inside it |
| The cache charges a frame what it reserves, not what it uses | [Block cache](/internals/block-cache) | `test_arena_reserved_counts_whole_chunks_not_bytes_used` -- asserts one small object still reserves a whole chunk and that reserved never reads below allocated. a cached node is decoded into its own arena, so the memory a frame holds is the chunk it took; charging the bytes the node used let a 64 MiB cache sit resident at 908 MiB, and nothing reported the gap. worst on a small budget, which is why the capacity test -- entries near the nominal size, nothing to round -- kept passing |
| The block cache's frame count follows its byte budget | [Block cache](/internals/block-cache) | `test_cache_reaches_its_configured_capacity` -- fills past the budget and asserts the cache settles within a few percent of it; a frame ceiling that binds first leaves it at a fraction, silently |
| Each class of file accounts its own device work | [Statistics](/reference/statistics) | `test_engine_io_stats_attribute_device_work` -- asserts a fresh database reports zero, that committing moves the log class and flushing moves the sstable class, and that no class reports fewer bytes than writes |
| Every point a writer can wait at reports count, total and longest | [Statistics](/reference/statistics) | `test_engine_stall_stats_attribute_writer_waits` -- asserts a fresh database reports zero, that the log wait counts after writes, and that no total is less than the longest wait inside it |
| A finished sstable occupies its data, not its preallocated extent | [Block manager](/internals/block-manager) | `test_engine_finished_sstable_is_trimmed_to_its_data` -- measures the klog while the database is open, since closing trims it either way and hides the defect |
| A key log the manifest does not name is swept at open | [Recovery](/internals/recovery) | `test_engine_open_sweeps_orphaned_sstables` -- plants an unnamed klog and a staging file, then asserts both are gone and every named klog survived |
| The orphan sweep is skipped after a self-heal | [Recovery](/internals/recovery) | `test_engine_open_keeps_sstables_when_manifest_self_healed` -- plants a klog the rebuild cannot adopt, so the guard is what keeps it; without the guard the sweep deletes it |
| A merged-away compaction input is unlinked when its last reference drops | [Compaction](/internals/compaction) | `test_engine_compaction_unlinks_merged_inputs`, `test_engine_compaction_leaves_no_orphans_under_load` -- both compare the klog files on disk against the live sstable count, which is the only way the leak is visible; nothing else fails when the files pile up |
| A flush waits for its install ticket before taking the registry read lock, never under it | [Architecture](/internals/architecture) | `test_engine_create_completes_under_sustained_flush` -- holding it across the wait both starves family create and deadlocks against the worker holding the earlier ticket |
| No reader takes the family registry lock again while holding it | [Architecture](/internals/architecture) | **Unguarded** -- nothing detects re-entry. Such a reader waits on its own writer's announcement and never reaches the acquire that would release it, so it deadlocks rather than failing |
| A writer waiting on the registry, the commit gate or the manifest holds off arriving readers | [Architecture](/internals/architecture) | `test_engine_create_completes_under_sustained_flush` -- a create competing with continuous background readers. The lock kind that does this is a glibc extension, so relying on it left the guarantee holding on one platform; the announcement replaces it and holds everywhere |
| A committer that finds another rotating does not queue behind it | [Memtable and WAL](/internals/memtable-and-wal) | **Unguarded** -- nothing asserts the acquire is a try rather than a wait. A mutex that hands off by barging starves one waiter for as long as the others keep arriving, and the waiter gains nothing the holder finishing does not already give it |
| A timed wait is taken on a clock the wall clock cannot move | [Thread manager](/internals/thread-manager) | **Unguarded** -- nothing asserts the condvar's clock. Every background worker parks in the same place, so a wall clock step leaves all of them waiting for a time that has moved away and they stop together for its length; the tell is a burst of work landing when they finally wake |
| A flush never waits out a reader to free a memtable | [Memtable and WAL](/internals/memtable-and-wal) | `test_l0_reclaim_defers_rather_than_blocking` -- it holds an immutable pinned across a retire and asserts the retire returns, which hangs outright if the wait is unbounded |
| A pinned memtable keeps its write-ahead log alive | [Memtable and WAL](/internals/memtable-and-wal) | `test_memtable_free_leaves_wal_open` |
| Cache frames are never freed; only payloads are reclaimed | [Block cache](/internals/block-cache) | `cache` tests; ASan across the suite |
| A cache payload is reclaimed exactly once, by the last reference dropped | [Block cache](/internals/block-cache) | `cache` tests; ASan would catch a double free |
| A sstable is freed by whoever drops the last reference | [SSTable](/internals/sstable) | `level_set`, `sstable` tests; ASan |
| Sources stay pinned for an iterator's life | [Iterators](/internals/iterators) | `cf_iter`, `iter_api_tests`; TSan |
| Ingest is paced before the staging ring fills, not when it is full | [Memtable and WAL](/internals/memtable-and-wal) | `backpressure` tests cover the band, its graduation and its cap; that the append path actually consults it is **unguarded**, and a regression would show only as a latency tail |
| A copy freezes nothing; it claims what removes files and snapshots the rest | [Memtable and WAL](/internals/memtable-and-wal) | `fuzz_standalone` and `fuzz_conc` drive backup and clone against concurrent flush and compaction; nothing asserts the absence of a freeze, so a reviewer reintroducing one would see no failure |
| A caller that mutates the catalogue and cannot finish puts it back | [Compaction](/internals/compaction), [Memtable and WAL](/internals/memtable-and-wal) | `test_manifest_an_abandoned_half_batch_lands_on_the_next_commit` — buffered records are not discarded when a caller gives up, they wait for the next commit from any path. Both installs name their outputs in a loop and so both must undo a partial one: a compaction that stopped partway would disown its inputs durably with the replacement never named, and the orphan sweep would unlink their files on the next open; a flush would leave the catalogue naming outputs no level set ever took. The clone and the recovery rebuild reach the same end differently — the clone's failure path drops the destination and the drop cascades those records away, and a failed rebuild aborts the open, whose manifest close discards the batch. The undo itself is **unguarded**: reaching it needs a refused allocation inside the install's own window, which `test_alloc_failure_through_a_compaction_keeps_every_commit` walks the path of but cannot land in |
| An interval delete covering no key is refused where it is buffered | [Transactions and MVCC](/internals/transactions-and-mvcc) | `test_engine_range_delete_refuses_an_interval_covering_nothing` — an interval ending where it starts, or before it, was taken when buffered and met only at the apply, which runs after the batch is durable and treats every failure as transient. So it burned the retries and cancelled the whole transaction with an I/O error, losing the writes that shared it, for a bound the caller could still have fixed. The same shape as the empty value above. The rule lives in `range_tombstone_interval_valid`, which both the API and the tombstone set ask, so the two cannot come to disagree about what an interval is |
| An interval reservation is given back once its batch is visible | [Transactions and MVCC](/internals/transactions-and-mvcc) | `test_engine_repeated_range_deletes_do_not_exhaust_the_reservations` — a key reservation is renamed rather than released, so an interval delete is the one claim that has to be handed back explicitly. the table has a fixed number of slots, so leaking one per commit ends with every later interval delete refused as a conflict no retry could clear; the test commits far more than there are slots |
| A copy measures the manifest and reads it inside one hold | [Manifest](/internals/manifest) | `test_manifest_hold_keeps_the_log_still` — a commit past the rollover bound renames a fresh snapshot over the same path, so a length measured outside the hold can be applied to a different file, leaving a catalogue that names klogs the copy does not hold. the test asserts both halves: that the hold blocks every commit, and that those commits really do replace the file once it lifts |
| A descriptor is reclaimed only at the idle reference count | [fd manager](/internals/fd-manager) | `reaper`, `fdmanager` tests |
| Every labelled descriptor open pairs with a labelled close | [fd manager](/internals/fd-manager) | `test_engine_wal_descriptor_accounting_balances` — the gate and the reaper both read the cross-label total, so a label that only decrements drives it negative and silently disables the budget while the reported per-label statistic still looks correct |
| A value-log segment is unlinked only after every reader inside it leaves | [Value log](/internals/value-log) | `test_concurrent_reads_writes_and_reclaim`; TSan across the suite |
| A sealed value-log segment is never modified | [Value log](/internals/value-log) | `test_reclaim_leaves_the_active_segment_alone`, `test_recover_appends_to_a_fresh_segment` |
| A value id names one block for its whole life | [Value log](/internals/value-log) | `test_builder_records_vlog_segment_references` — nothing is copied within the store, so an id cannot exist in two segments and a crash leaves no duplicate to resolve |
| Value-log liveness comes from what the installed tables report, not the index | [Value log](/internals/value-log) | `test_reclaim_drops_dead_values` — the index names every value whose segment has not been dropped, so counting it alone reports garbage as live and reclamation stops silently |
| A segment a builder may have written to is never reclaimed | [Value log](/internals/value-log) | `test_reclaim_spares_what_a_builder_may_have_written` — values are written before the table naming them is installed, and dropping that segment in the window loses them |
| A value in a segment being emptied is rewritten, not carried | [Value log](/internals/value-log) | `test_builder_respills_a_value_out_of_a_draining_segment` — carrying the reference leaves the output table holding the old segment, and it could never reach zero |
| A value is never split across segments | [Value log](/internals/value-log) | `test_a_value_larger_than_a_segment_is_not_split` — the segment target is a roll threshold, so an oversized value overshoots it whole rather than being divided |
| A segment with a reader inside it is never closed by the reaper | [Value log](/internals/value-log) | `test_idle_segments_give_back_their_descriptors` and the concurrent reclaim test, which evicts while readers are in flight; TSan across the suite |

## Compaction correctness

| Invariant | From | Enforcement |
| --- | --- | --- |
| Versions are dropped only below `min_snapshot_seq` | [Compaction](/internals/compaction) | `compaction_exec`; `fuzz_standalone` model comparison |
| A tombstone drops only when every sstable holding the key is in the merge | [Compaction](/internals/compaction) | `compaction_exec`; `fuzz_standalone` |
| Tombstone safety is evaluated over the whole job, not a sub-range | [Compaction](/internals/compaction) | `compaction_pipeline_tests`; this class of bug has escaped unit tests before and was found by `fuzz_standalone` |
| Outputs and input removals commit in one manifest batch | [Compaction](/internals/compaction) | `compaction_pipeline_tests`, `manifest`; `test_crash_recovery_torn_compaction` tears each write a merge issues and requires every key back, which is what a half-committed batch would cost |
| The planner performs no I/O and reads no clock | [Compaction](/internals/compaction) | `compaction_planner` — the tests pass it plain numbers, so an I/O dependency would not link |
| A read resolves against its snapshot; a compaction reads raw and retains for itself | [Iterators](/internals/iterators) | `merge_iter`, `merge_sources` — both scan the same sources twice, once resolving and once raw, and require the tombstones to appear only in the second |

## Recovery

| Invariant | From | Enforcement |
| --- | --- | --- |
| The clock resumes above the highest of four durable high-water marks | [Recovery](/internals/recovery) | `test_engine_cf_id_not_reused_after_drop_reopen` covers the family-id mark; the sstable and prepared marks are **indirect** |
| Replay applies at the record's own sequence, not its file position | [Recovery](/internals/recovery) | `test_engine_overwrite_across_recovery` |
| The prepared-transaction staging map spans generations | [Recovery](/internals/recovery) | `test_engine_prepared_survives_flush` |
| Families are rebuilt before log records naming them are applied | [Recovery](/internals/recovery) | `test_engine_cf_recovery` |
| A damaged manifest is rebuilt from the sstables on disk | [Manifest](/internals/manifest) | `manifest` tests cover discarding the log; `test_engine_rebuilds_catalogue_from_sstables` covers the readopt, and asserts the data reads back rather than only that the open succeeded |
| A torn sstable is truncated to its last valid block | [Recovery](/internals/recovery) | `test_crash_recovery_torn_flush` |

## Structural

| Invariant | From | Enforcement |
| --- | --- | --- |
| Zero-length blocks are rejected at write | [Block manager](/internals/block-manager) | `block_manager` tests |
| The trailing size must match the leading one | [Block manager](/internals/block-manager) | `block_manager`, `fuzz_decode` |
| The footer records the geometry the file was written with | [SSTable](/internals/sstable) | `sstable`, `fuzz_decode` |
| The footer's encoding pipeline is the one the nodes were encoded with | [SSTable](/internals/sstable) | `fuzz_standalone` — its families draw real pipelines and it reconfigures them mid-run, which is what caught the builder reading the family's pipeline twice and straddling a reconfigure |
| Every value-log block carries the encoding chain it was written through | [Value log](/internals/value-log) | `fuzz_standalone` — a value carried forward by compaction into an sstable recording a different pipeline decodes by its own chain or not at all |
| The filter directory holds full first keys — no false negatives | [SSTable](/internals/sstable) | `pr_filter` tests |
| A snapshot carries `SEQ` and `CF_SEQ` | [Manifest](/internals/manifest) | `test_engine_cf_id_not_reused_after_drop_reopen` |
| High-water marks are raised, never stored | [Manifest](/internals/manifest) | `manifest` tests |
| No module below the engine takes a `tidesdb_t` | [Architecture](/internals/architecture) | Structural: every subsystem test constructs its module without a database, so a violation would not compile |

## Process and shutdown

| Invariant | From | Enforcement |
| --- | --- | --- |
| Background processes stop in reverse registration order | [Thread manager](/internals/thread-manager) | `threadmanager` tests |
| A pool never owns the queue it drains | [Thread manager](/internals/thread-manager) | `bg_pool`, `queue` |
| Every stop signals, wakes, and joins | [Thread manager](/internals/thread-manager) | `bg_pool`, `bg_ticker` — a missed wake hangs the test |
| Blocking on backpressure has a ceiling | [Memtable and WAL](/internals/memtable-and-wal) | `backpressure` tests |
| The budget plus the untracked reserve fits the process limit | [fd manager](/internals/fd-manager) | `test_fd_manager_budget_for_process` -- the cut is pure arithmetic so every case is asked directly rather than through whatever ceiling the machine running the suite has, including the default pairing that made it necessary: a 1024 budget against the usual 1024 POSIX ceiling. Bounds one database; several in one process cut against the same ceiling independently and can still exceed it together, which is the operator's to size and the `EMFILE` retry's to absorb |
| Reader-gate rechecks and `EMFILE`/`ENFILE` retries are bounded, and to the same bound | [fd manager](/internals/fd-manager) | `test_fd_manager_reader_gate_wait_is_bounded` — drives the gate to its bound with a budget nothing can free, and times it: a gate that refuses without waiting and one that retries past its bound each fail a different assertion. A `_Static_assert` covers the two bounds matching, since when they did not, reads failed on a shortage the open path was about to clear. What is still untested is the real `EMFILE` path, which needs the process ceiling genuinely exhausted |

## The gaps

Eighteen entries above are unguarded, incomplete, or only indirectly guarded — thirteen marked
unguarded, four only **Indirect**, and one **Partly implemented**. The ones worth stating plainly
rather than leaving in a table:

1. **The value log's `O_DSYNC` open.** Nothing fails if someone "optimises" it away. The result
   would be a durable key log referencing value bytes that never landed — visible only as a
   rare wrong-value read after a crash. Today the only guard is a comment.
2. **Truncation syncing.** No test kills a process between an `ftruncate` and its sync.
3. **The genuine `EMFILE` path.** The reader gate's bound is now tested directly, but by
   exhausting the engine's own budget rather than the process ceiling. Nothing drives the process
   out of descriptors, so the `EMFILE`/`ENFILE` retry in the open path is still only covered by
   sharing its bound with the gate.
4. **The sstable and prepared high-water marks in the clock reseed.** The family-id mark has a
   direct test; the other two are covered only by broader recovery tests that would fail for
   many reasons.
5. **The two rotation rules** — that the log is opened before the rotation and off the lock, and
   that the lock is never held across a wait or a device barrier. Neither has a test; a breach of
   either surfaces as stalled commits' stacks under load, which is evidence you have to go looking
   for rather than a failure that reports itself.
6. **That the append path consults the backpressure policy at all.** The policy's own band,
   graduation and cap are tested; the call site is not, and a regression there shows only as a
   latency tail.
7. **That a copy freezes nothing.** Backup and clone run against concurrent flush and compaction
   in the fuzzers, but nothing asserts the absence of a freeze, so reintroducing one would fail
   nothing.

The first is the most serious, because the failure is silent, arrives long after the change
that caused it, and looks like data corruption rather than a durability bug.

:::note[This audit is a snapshot]
It reflects what the suite covered when this chapter was written. Adding an invariant to a
subsystem chapter without adding its row here — and without adding the check that fills the
third column — is how this chapter rots into the same hopeful comments it exists to replace.
:::
