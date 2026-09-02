# Code Rules

1. **Simple control flow.** No `goto`, `setjmp`/`longjmp`, or recursion.
2. **Fixed loop bounds.** Every loop must have a statically verifiable upper bound.
3. **No dynamic allocation after init.** All memory is allocated up front; no `malloc`/`free` in steady-state operation.
4. **Smallest possible scope.** Declare data objects at the tightest scope that works.
5. **Check every return value.** Validate all function parameters; never ignore a non-void return.
6. **Minimal preprocessor use.** Macros limited to file inclusion and simple constants - no token pasting, no conditional compilation that hides code from the compiler.
7. **Restricted pointer use.** At most one level of dereference; no function pointers.
8. **Zero-warning compilation.** All warnings enabled, all warnings fixed, and the code passes static analysis clean before release.
9. **No magic numbers or strings.** Every literal with meaning gets a named constant or macro instead of a bare number or string appearing inline.
10. **Functions should be unit and integration testable** 
11. Comments are primarily **lowercase**.
12. Before commiting code be sure to test it thoroughly locally and prove it, if on linux with ASAN, UBSAN and TSAN, all possible flags on your running platform.
13. Attempt to keep source and header files under **1000** lines of code. A small number of files are
    graced from this and are listed below; a graced file still has a hard ceiling, and nothing else
    may exceed 1000 lines without being added to the list.

    | File | Ceiling | Why |
    | --- | --- | --- |
    | `include/db.h` | 10000 | The public header is deliberately self-contained: one include gives a consumer or an FFI binding the whole API, with every type, error code and doc comment in one place. Splitting it would trade that for a header set callers have to assemble. |
14. Functions should be attempted to be no greater than **100** lines.
15. When writing system modules, be sure your code it unit and integration tested, similar style as to whats under /test

## Documentation Style

Comments should explain *why* and *what for*, not restate the code. Skip comments that
just repeat a variable or type name. Every public struct and function gets a doc comment
in this format:

### Structs

```c
/**
 * flush_ctx_t
 * the shared, read-only context a flush runs against; the engine builds one and the flush pool reuses
 * it across immutables
 * @param l0 the L0 subsystem, for reclaiming an immutable once its data is durable in L1
 * @param cfs the column family registry indexed by cf-index; a NULL slot is a dropped family whose
 *            entries are discarded
 * @param n_cfs the length of cfs
 * @param manifest the db-level manifest every output sstable is recorded in
 * @param manifest_path the path the manifest commits to
 * @param next_sstable_id the db-global sstable id allocator, fetch-added per output
 * @param fdm the db-global descriptor budget, for releasing a flushed immutable's WAL descriptor, or
 *            NULL when the immutables carry no WAL
 * @param sync_mode the block-manager sync mode driving the klog and manifest durability barriers
 */
```

### Functions

```c
/**
 * flush_immutable
 * flush one dequeued immutable to L1 -- demux its skip_list into per-column-family sstables, record
 * them in one atomic manifest commit, install them into the level sets, then mark the immutable flushed
 * and reclaim it. on any failure before the commit the built sstables are closed and the immutable is
 * left for a retry, its data still durable in its WAL
 * @param fx the flush context
 * @param immutable the dequeued immutable memtable, owned by this call on success
 * @return TDB_SUCCESS, TDB_ERR_INVALID_ARGS, TDB_ERR_IO on a klog or manifest failure, TDB_ERR_MEMORY,
 *         or TDB_ERR_CORRUPTION on a malformed skip_list key
 */
```

**Conventions:**

- First line: the identifier name.
- Second line: one-sentence purpose, lowercase, no trailing period.
- `@param` / `@name`-style fields: one line per parameter or struct field, stating type constraints and nullability where relevant.
- `@return`: what each outcome means, not just "returns int."
- No inline comments duplicating the doc comment's information inside the function body.