# Versioning

Follows [SemVer](https://semver.org/) (MAJOR.MINOR.PATCH). The on-disk format
is a separate, first-class contract - see the compatibility matrix below.

**Public API** is `include/db.h` - the single self-contained public header, and
the types, constants and functions it declares. Nothing else carries a
compatibility guarantee.

"Internal" means *not reachable in a supported way* - if a symbol is reachable
(exported, or accessible via a plugin/extension seam), treat it as public
regardless of intent.

The install ships exactly that surface - `db.h`, the generated
`tidesdb_version.h`, and `xxhash.h` - and nothing else. The engine's own headers
under `src/` are not installed, so there is no way to reach one in a supported
build and no exception to carve out of the rule above.

## Major
- On-disk format changes.
- Disk-rewriting algorithm changes that are not gracefully handled and
  can affect data outcomes.
- Breaking public API changes.
- Ships with migration tooling in the same release, where an in-place upgrade
  is possible at all. 10.0.0 is the one exception on record: it opens a new
  format line rather than migrating an old one, so a 9.x database moves across
  by dump and reload.

## Minor
- Backward-compatible **public** API additions.
- Must read all data written by prior minors in the same major.
- Any new on-disk format is opt-in and default-off, so downgrade stays possible.

## Patch
- Bug and security fixes.
- Internal API changes (symbols not part of the supported public surface).
- Must not change the on-disk format or observable write behavior
  (safe to apply without reading release notes).
- Backported to every supported release line.

## Compatibility matrix

<!-- Records the durability guarantees operators check before touching production. -->

The on-disk format is one number across all four file kinds - the block frame,
the write-ahead log record, the sstable footer and the manifest batch all carry
it, and each is checked for **exact equality** on read. A file of any other
version is rejected; there is no best-effort path.

| Release | Format read | Format written | Rollback boundary |
|---------|-------------|----------------|-------------------|
| 10.0.x  | 10          | 10             | any 10.x          |

- **10.0.0 opens the v10 format line.** It does not read anything written by
  9.x, and no migration tooling ships for that step - a 9.x database is
  migrated by dumping and reloading through the API.
- **Rollback within 10.x is unrestricted** while every 10.x minor writes format
  10. A minor that introduces a new format must make it opt-in and default-off,
  which is what keeps that column true; the release that changes it updates this
  table in the same commit.

Add a row per release. A release that does not move any of the three columns
still gets a row, because "unchanged" is the answer an operator is looking for.