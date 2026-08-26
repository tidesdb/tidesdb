#!/usr/bin/env python3
"""Turn the C samples in the manual into one compilable translation unit, and check that every
identifier the prose names actually exists.

The manual's samples are the part most likely to rot: a renamed function or a changed
signature leaves prose that still reads plausibly. Compiling every sample against the real
header turns that class of rot into a build failure.

Each fenced ``c`` block under doc/ becomes one function body, nested inside a block so a
sample may redeclare a name the shared preamble already provides. A block tagged
``c,no-compile`` is skipped, for samples that are deliberately not valid on their own.

Lives under doc/ because it exists only to serve the manual; it is not part of the library
build in any other sense. It only walks the numbered part directories, so nothing in doc/tools
can be mistaken for content.

The samples are checked by compiling them. Prose is not compiled, so a backticked identifier that
drifts -- a renamed function, a misremembered field -- reads perfectly and is wrong. The second
pass here catches that: an identifier that appears nowhere in the source tree is a typo. It is
deliberately loose about *where* a name is defined, because the internals chapters legitimately
name engine-internal symbols that never appear in the public header.

usage: extract_doc_samples.py <doc-dir> <output.c> [source-root]
"""

import re
import sys
from pathlib import Path

# the info string must be exactly "c", or "c" followed by a separator and tags. without the
# separator the tag group swallows the rest of the word and ```cmake / ```cpp / ```console are
# all read as C
FENCE = re.compile(r"^```c(?P<tags>|[,;\s][^\n]*)\n(?P<body>.*?)^```", re.M | re.S)

# a backticked token worth checking: snake_case with at least one underscore, or a SHOUTY macro.
# anything with a dot, slash or hyphen is a filename or prose, not an identifier
# a sample that defines its own entry point is a whole program, not a fragment
MAIN = re.compile(r"^int\s+main\s*\(\s*(?:void)?\s*\)", re.M)

IDENT = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
IDENT_SHAPE = re.compile(r"^(?:[a-z][a-z0-9]*(?:_[a-z0-9]+)+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)$")

# names that are real but live outside the sources scanned. kept as an explicit list rather than a
# pattern, so naming a foreign symbol in the manual is a deliberate act and a typo in one is still
# caught -- a misspelt kernel symbol is exactly as misleading as a misspelt tidesdb one
ALLOWED = {
    # standard types
    "size_t", "time_t", "uint8_t", "uint32_t", "uint64_t", "int64_t",
    # this tool and what it produces
    "doc_samples", "extract_doc_samples", "no_compile",
    # linux kernel symbols quoted from perf profiles
    "copy_user_enhanced_fast_string", "filemap_read", "filemap_get_read_batch",
    "native_queued_spin_lock_slowpath", "try_to_wake_up",
    # rocksdb options named when comparing behaviour
    "level0_slowdown_writes_trigger", "level0_stop_writes_trigger",
    # innodb and berkeley db durability settings, named when mapping the sync modes onto theirs
    "innodb_flush_log_at_trx_commit", "DB_TXN_NOSYNC", "DB_TXN_WRITE_NOSYNC",
}

# trees searched for a definition or use of an identifier the prose names
SOURCE_GLOBS = ("include/**/*.h", "src/**/*.c", "src/**/*.h", "src/**/*.h.in",
                "bench/**/*.c", "bench/**/*.h", "fuzz/**/*.c", "fuzz/**/*.h",
                "test/**/*.c", "test/**/*.h", "CMakeLists.txt")


def source_corpus(root):
    """every identifier that appears anywhere in the sources, as one set"""
    seen = set()
    for pattern in SOURCE_GLOBS:
        for path in Path(root).glob(pattern):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # an escape inside a string literal is two characters in the source, so a name that
            # follows one is glued to it -- "\trss_mb" tokenizes as trss_mb and the real name is
            # invisible. that is how every tab-separated column heading is written, so blank the
            # escapes first or the prose cannot name a column the tool itself prints
            text = re.sub(r"\\[a-zA-Z0-9]", " ", text)
            seen.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text))
    return seen


def check_identifiers(doc_dir, root):
    """report every backticked identifier in the manual that exists nowhere in the sources"""
    known = source_corpus(root)
    if not known:
        sys.stderr.write("doc identifiers: no sources found under {}, check skipped\n".format(root))
        return 0

    bad = {}
    for path in sorted(Path(doc_dir).rglob("*.md")):
        for name in set(IDENT.findall(path.read_text(encoding="utf-8", errors="replace"))):
            if name in known or name in ALLOWED:
                continue
            if not IDENT_SHAPE.match(name):
                continue
            bad.setdefault(name, []).append(str(path))

    for name in sorted(bad):
        sys.stderr.write("doc identifier not found in any source: {} ({})\n".format(
            name, ", ".join(sorted(bad[name]))))
    return len(bad)

PREAMBLE = r"""/* GENERATED by scripts/extract_doc_samples.py -- do not edit.
 *
 * One function per C sample in the manual. Nothing here runs; the point is that it
 * compiles, so a sample that drifts from the public header stops the build. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tidesdb/db.h>

/* a retry bound the samples refer to without defining */
#define MAX_RETRIES 3
"""

# names samples use without declaring, provided once per function and shadowable
LOCALS = r"""    tidesdb_t *db = NULL;
    tidesdb_column_family_t *cf = NULL;
    tidesdb_txn_t *txn = NULL;
    tidesdb_iter_t *it = NULL;
    const uint8_t *key = NULL;
    size_t key_size = 0;
    size_t klen = 0;
    uint8_t *val = NULL;
    size_t vlen = 0;
    /* non-const: samples pass this both into a put (which takes const) and as a get's
       out-parameter, and only the non-const form satisfies both */
    uint8_t *value = NULL;
    size_t value_size = 0;

    (void)db; (void)cf; (void)txn; (void)it;
    (void)key; (void)key_size; (void)klen;
    (void)val; (void)vlen; (void)value; (void)value_size;
"""


def samples(doc_dir):
    """yield (source_path, index_in_file, code) for every compilable c sample"""
    for path in sorted(Path(doc_dir).rglob("*.md")):
        # only the numbered manual parts; anything still at the top of doc/ predates the
        # rewrite and is not expected to compile
        if not re.match(r"^\d\d-", path.parent.name):
            continue
        text = path.read_text(encoding="utf-8")
        for i, m in enumerate(FENCE.finditer(text)):
            if "no-compile" in m.group("tags"):
                continue
            yield path, i, m.group("body")


def main():
    if len(sys.argv) not in (3, 4):
        sys.stderr.write(__doc__)
        return 2

    doc_dir, out_path = sys.argv[1], sys.argv[2]
    root = sys.argv[3] if len(sys.argv) > 3 else str(Path(doc_dir).parent)

    unknown = check_identifiers(doc_dir, root)
    if unknown:
        sys.stderr.write("doc identifiers: {} name(s) the sources do not define\n".format(unknown))
        return 1

    parts = [PREAMBLE]
    names = []
    for path, i, code in samples(doc_dir):
        name = "doc_sample_{}_{}".format(
            re.sub(r"[^A-Za-z0-9]", "_", str(path.stem)), i
        )
        names.append(name)
        if MAIN.search(code):
            # a self-contained program. wrapping it would nest a function definition, which only
            # compiles as a gnu extension -- emit it at file scope with main renamed instead
            body = MAIN.sub("static int {}(void)".format(name), code.rstrip(), count=1)
            parts.append("\n/* {}: sample {} (complete program) */\n{}\n".format(path, i, body))
        else:
            parts.append(
                "\n/* {}: sample {} */\nstatic int {}(void)\n{{\n{}\n    {{\n{}\n    }}\n    return 0;\n}}\n".format(
                    path, i, name, LOCALS, code.rstrip()
                )
            )

    # reference every sample so none is dropped as unused, and keep a real entry point
    parts.append("\nint main(void)\n{\n    int (*const samples[])(void) = {\n")
    parts.extend("        {},\n".format(n) for n in names)
    parts.append(
        "    };\n"
        "    /* never executed -- the samples operate on null handles */\n"
        "    return (int)(sizeof(samples) / sizeof(samples[0])) > 0 ? 0 : 1;\n"
        "}\n"
    )

    Path(out_path).write_text("".join(parts), encoding="utf-8")
    sys.stderr.write("doc samples: {} extracted from {}\n".format(len(names), doc_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
