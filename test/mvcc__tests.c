/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#include <stdlib.h>
#include <string.h>

#include "../src/txn/mvcc.h"
#include "test_utils.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define CC_THREADS    8
#define CC_PER_THREAD 2000
#define CC_TOTAL_SEQS (CC_THREADS * CC_PER_THREAD)

/* the family every claim in these tests belongs to */
#define CLAIM_CF 0

/* the FNV-1a constants, for a hash the claim set compares by bytes behind anyway */
#define CLAIM_HASH_OFFSET 14695981039346656037ULL
#define CLAIM_HASH_PRIME  1099511628211ULL

/* a hash over a key's bytes, so equal keys chain from one bucket; the set never trusts it alone */
static uint64_t claim_hash(const char *key)
{
    uint64_t h = CLAIM_HASH_OFFSET;
    for (const char *p = key; *p; p++) h = (h ^ (uint8_t)*p) * CLAIM_HASH_PRIME;
    return h;
}

/* fill one claim over a NUL-terminated key */
static void claim(tidesdb_mvcc_claim_t *c, const char *key, uint8_t kind)
{
    tidesdb_mvcc_claim_init(c, CLAIM_CF, (const uint8_t *)key, (uint32_t)strlen(key), kind,
                            claim_hash(key));
}

/* the sequence counter starts at 1 and hands out monotonically increasing seqs */
void test_mvcc_seq_counter(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(m) == 1);
    ASSERT_TRUE(tidesdb_mvcc_draw(m, NULL) == 1);
    ASSERT_TRUE(tidesdb_mvcc_draw(m, NULL) == 2);
    ASSERT_TRUE(tidesdb_mvcc_draw(m, NULL) == 3);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(m) == 4);
    tidesdb_mvcc_destroy(m);
}

/* the watermark follows decisions in sequence order. it waits on the oldest drawn sequence still in
 * flight however many later ones decide, passes an aborted one as it passes a committed one, and a
 * sequence marked without having been drawn does not move it */
void test_mvcc_watermark_follows_decisions(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(m) == 0);
    const uint64_t s1 = tidesdb_mvcc_draw(m, NULL);
    const uint64_t s2 = tidesdb_mvcc_draw(m, NULL);
    const uint64_t s3 = tidesdb_mvcc_draw(m, NULL);

    tidesdb_mvcc_mark(m, s2, 1);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(m) == 0); /* s1 still in flight */
    tidesdb_mvcc_mark(m, s1, 1);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(m) == s2); /* s1 and s2 both decided */
    tidesdb_mvcc_mark_aborted(m, s3);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(m) == s3);

    tidesdb_mvcc_mark(m, s3 + 5, 1); /* never drawn */
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(m) == s3);
    const uint64_t s4 = tidesdb_mvcc_draw(m, NULL);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(m) == s3);
    tidesdb_mvcc_mark(m, s4, 1);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(m) == s4);
    tidesdb_mvcc_destroy(m);
}

/* reseed advances the counter past the recovered max and stands the watermark at it, so every
 * recovered version is readable from the first begin, whether the recovered max is inside the ring
 * or far beyond it */
void test_mvcc_reseed(void)
{
    tidesdb_mvcc_t *s = tidesdb_mvcc_create();
    ASSERT_TRUE(s != NULL);
    tidesdb_mvcc_reseed(s, 1000);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(s) == 1001);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(s) == 1000);
    ASSERT_TRUE(tidesdb_mvcc_draw(s, NULL) == 1001);
    tidesdb_mvcc_destroy(s);

    tidesdb_mvcc_t *l = tidesdb_mvcc_create();
    ASSERT_TRUE(l != NULL);
    const uint64_t big = TDB_MVCC_COMMIT_RING_SIZE + 34464;
    tidesdb_mvcc_reseed(l, big);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(l) == big + 1);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(l) == big);
    const uint64_t next = tidesdb_mvcc_draw(l, NULL);
    tidesdb_mvcc_mark(l, next, 1);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(l) == next);
    tidesdb_mvcc_destroy(l);
}

/* a writer promising first-committer-wins is refused a key another commit holds in flight, and
 * takes it once that commit lets go; nothing of a refused claim is left behind */
void test_mvcc_claim_refuses_a_writer_in_flight(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    tidesdb_mvcc_claim_t ca[1], cb[2];
    tidesdb_mvcc_commit_t a, b;
    claim(&ca[0], "k", TDB_MVCC_CLAIM_WRITE);
    claim(&cb[0], "j", TDB_MVCC_CLAIM_WRITE);
    claim(&cb[1], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&a, ca, 1);
    tidesdb_mvcc_commit_init(&b, cb, 2);

    ASSERT_EQ(tidesdb_mvcc_claim(m, &a, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &b, 1), 0); /* k is held */

    /* b's j was let go with the refusal, so a third commit takes it freely */
    tidesdb_mvcc_claim_t cc[1];
    tidesdb_mvcc_commit_t c;
    claim(&cc[0], "j", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&c, cc, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &c, 1), 1);
    tidesdb_mvcc_unclaim(m, &c);

    tidesdb_mvcc_unclaim(m, &a);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &b, 1), 1);
    tidesdb_mvcc_unclaim(m, &b);
    tidesdb_mvcc_destroy(m);
}

/* repeatable read makes no first-committer promise, so its write claim joins another writer's,
 * while a writer at snapshot or above still yields to it; and no claim survives a refused commit */
void test_mvcc_repeatable_read_registers_without_refusing(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    tidesdb_mvcc_claim_t ca[1], cb[1], cc[1];
    tidesdb_mvcc_commit_t a, b, c;
    claim(&ca[0], "k", TDB_MVCC_CLAIM_WRITE);
    claim(&cb[0], "k", TDB_MVCC_CLAIM_WRITE);
    claim(&cc[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&a, ca, 1);
    tidesdb_mvcc_commit_init(&b, cb, 1);
    tidesdb_mvcc_commit_init(&c, cc, 1);

    ASSERT_EQ(tidesdb_mvcc_claim(m, &a, 0), 1); /* repeatable read */
    ASSERT_EQ(tidesdb_mvcc_claim(m, &b, 0), 1); /* another, beside it */
    ASSERT_EQ(tidesdb_mvcc_claim(m, &c, 1), 0); /* snapshot yields to a writer in flight */
    tidesdb_mvcc_unclaim(m, &a);
    tidesdb_mvcc_unclaim(m, &b);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &c, 1), 1);
    tidesdb_mvcc_unclaim(m, &c);
    tidesdb_mvcc_destroy(m);
}

/* a prepared reader's read claim refuses every writer of the key, at repeatable read included,
 * until the prepare is decided; it refuses no reader, and validation finds it for a writer that
 * claimed before the reader did */
void test_mvcc_read_claim_refuses_writers(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    tidesdb_mvcc_claim_t cp[1], cw[1], cr[1], ce[1];
    tidesdb_mvcc_commit_t p, w, r, early;
    claim(&ce[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&early, ce, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &early, 1), 1); /* a writer already holding k */
    (void)tidesdb_mvcc_draw(m, &early);

    claim(&cp[0], "k", TDB_MVCC_CLAIM_READ);
    tidesdb_mvcc_commit_init(&p, cp, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &p, 1), 1); /* a read claim is never refused */
    tidesdb_mvcc_commit_prepared(&p);

    /* the earlier writer meets the read claim when it validates its writes */
    ASSERT_EQ(tidesdb_mvcc_write_blocked(m, &early, CLAIM_CF, (const uint8_t *)"k", 1,
                                         claim_hash("k"), 1),
              1);
    tidesdb_mvcc_unclaim(m, &early);

    claim(&cw[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&w, cw, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 0); /* snapshot writer refused */
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 0), 0); /* repeatable read writer refused too */

    claim(&cr[0], "k", TDB_MVCC_CLAIM_READ);
    tidesdb_mvcc_commit_init(&r, cr, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &r, 1), 1); /* another reader is not */
    tidesdb_mvcc_unclaim(m, &r);

    tidesdb_mvcc_unclaim(m, &p);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 1);
    tidesdb_mvcc_unclaim(m, &w);
    tidesdb_mvcc_destroy(m);
}

/* a read is stale when a write claim on the key belongs to a commit drawn below the reader; one
 * drawn above it, one not yet drawn, and one prepared all leave the read standing */
void test_mvcc_read_stale_orders_by_sequence(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    tidesdb_mvcc_claim_t ca[1], cc[1];
    tidesdb_mvcc_commit_t a, b, c;
    const uint8_t *k = (const uint8_t *)"k";

    claim(&ca[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&a, ca, 1);
    tidesdb_mvcc_commit_init(&b, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &a, 1), 1);
    const uint64_t seq_a = tidesdb_mvcc_draw(m, &a);
    const uint64_t seq_b = tidesdb_mvcc_draw(m, &b);
    ASSERT_TRUE(seq_a < seq_b);
    ASSERT_EQ(tidesdb_mvcc_read_stale(m, &b, CLAIM_CF, k, 1, claim_hash("k")), 1);
    ASSERT_EQ(tidesdb_mvcc_read_stale(m, &b, CLAIM_CF, (const uint8_t *)"j", 1, claim_hash("j")),
              0);

    /* prepared, the same claim is a future commit and the read stands */
    tidesdb_mvcc_commit_prepared(&a);
    ASSERT_EQ(tidesdb_mvcc_read_stale(m, &b, CLAIM_CF, k, 1, claim_hash("k")), 0);
    tidesdb_mvcc_unclaim(m, &a);

    /* a writer claimed after the reader drew is above it; not yet drawn it is above it too */
    claim(&cc[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&c, cc, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &c, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_read_stale(m, &b, CLAIM_CF, k, 1, claim_hash("k")), 0);
    (void)tidesdb_mvcc_draw(m, &c);
    ASSERT_EQ(tidesdb_mvcc_read_stale(m, &b, CLAIM_CF, k, 1, claim_hash("k")), 0);
    tidesdb_mvcc_unclaim(m, &c);
    tidesdb_mvcc_destroy(m);
}

/* claims are taken in one order whatever order the caller listed them in, so two commits sharing
 * keys meet at the same first key */
void test_mvcc_claims_are_sorted(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    tidesdb_mvcc_claim_t c[3];
    tidesdb_mvcc_commit_t commit;
    claim(&c[0], "zz", TDB_MVCC_CLAIM_WRITE);
    claim(&c[1], "a", TDB_MVCC_CLAIM_WRITE);
    claim(&c[2], "m", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&commit, c, 3);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &commit, 1), 1);
    ASSERT_EQ((int)c[0].key[0], 'a');
    ASSERT_EQ((int)c[1].key[0], 'm');
    ASSERT_EQ((int)c[2].key[0], 'z');
    tidesdb_mvcc_unclaim(m, &commit);
    tidesdb_mvcc_destroy(m);
}

/* a prepared batch's claims outlive the handle that took them: the clock keeps copies in its
 * place, they refuse what the originals refused, and the clock frees them with itself */
void test_mvcc_orphaned_claims_keep_holding(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    char key[] = "held";
    tidesdb_mvcc_claim_t *cp = calloc(1, sizeof(*cp));
    tidesdb_mvcc_commit_t p;
    ASSERT_TRUE(cp != NULL);
    claim(cp, key, TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&p, cp, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &p, 1), 1);
    tidesdb_mvcc_commit_prepared(&p);

    ASSERT_EQ(tidesdb_mvcc_orphan_claims(m, &p), 1);
    ASSERT_TRUE(p.claims == NULL && p.n_claims == 0);
    free(cp);            /* the handle's memory goes */
    memset(key, 'x', 4); /* and so may the bytes its claims pointed at */

    tidesdb_mvcc_claim_t cw[1];
    tidesdb_mvcc_commit_t w;
    claim(&cw[0], "held", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&w, cw, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 0); /* still held, by the copy */
    claim(&cw[0], "xxxx", TDB_MVCC_CLAIM_WRITE);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 1); /* the overwritten bytes hold nothing */
    tidesdb_mvcc_unclaim(m, &w);
    tidesdb_mvcc_destroy(m);
}

/* an interval and the point writers inside it refuse each other whichever comes first, when the
 * writer promises first-committer-wins; a repeatable-read writer is recorded beside it instead, and
 * a writer outside the interval is never in its way. an interval also yields to a prepared reader
 * inside it and to another interval meeting it */
void test_mvcc_interval_claims_meet_point_claims_both_ways(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    const uint8_t *b = (const uint8_t *)"b", *y = (const uint8_t *)"y";

    /* the interval first: a snapshot writer inside is refused, one outside and one at repeatable
     * read are not */
    tidesdb_mvcc_commit_t d;
    tidesdb_mvcc_commit_init(&d, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &d, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_holds(&d), 1);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, &d, CLAIM_CF, b, 1, y, 1, 1), 1);

    tidesdb_mvcc_claim_t cw[1], co[1], cr[1];
    tidesdb_mvcc_commit_t w, outside, rr;
    claim(&cw[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&w, cw, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 0);
    ASSERT_EQ(tidesdb_mvcc_holds(&w), 0);
    claim(&co[0], "z", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&outside, co, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &outside, 1), 1);
    tidesdb_mvcc_unclaim(m, &outside);
    claim(&cr[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&rr, cr, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &rr, 0), 1);
    tidesdb_mvcc_unclaim(m, &rr);

    /* another interval meeting it is refused, a disjoint one is not */
    tidesdb_mvcc_commit_t d2;
    tidesdb_mvcc_commit_init(&d2, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &d2, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, &d2, CLAIM_CF, (const uint8_t *)"c", 1,
                                       (const uint8_t *)"d", 1, 1),
              0);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, &d2, CLAIM_CF, y, 1, NULL, 0, 1), 1);
    tidesdb_mvcc_unclaim(m, &d2);

    /* at repeatable read an interval is recorded beside whatever it meets, and a snapshot writer
     * inside it then yields to it as it yields to a repeatable-read write claim */
    tidesdb_mvcc_commit_t rrd;
    tidesdb_mvcc_commit_init(&rrd, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &rrd, 0), 1);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, &rrd, CLAIM_CF, (const uint8_t *)"c", 1,
                                       (const uint8_t *)"d", 1, 0),
              1);
    tidesdb_mvcc_claim_t cs[1];
    tidesdb_mvcc_commit_t snap;
    claim(&cs[0], "c", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&snap, cs, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &snap, 1), 0);
    tidesdb_mvcc_unclaim(m, &rrd);

    /* released, the interval no longer stands in the writer's way */
    tidesdb_mvcc_unclaim(m, &d);
    ASSERT_EQ(tidesdb_mvcc_holds(&d), 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 1);

    /* the point first: the interval is refused while the writer holds a key inside it */
    tidesdb_mvcc_commit_init(&d, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &d, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, &d, CLAIM_CF, b, 1, y, 1, 1), 0);
    tidesdb_mvcc_unclaim(m, &w);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, &d, CLAIM_CF, b, 1, y, 1, 1), 1);
    tidesdb_mvcc_unclaim(m, &d);

    /* and while a prepared reader holds a key inside it */
    tidesdb_mvcc_claim_t cp[1];
    tidesdb_mvcc_commit_t p;
    claim(&cp[0], "k", TDB_MVCC_CLAIM_READ);
    tidesdb_mvcc_commit_init(&p, cp, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &p, 1), 1);
    tidesdb_mvcc_commit_prepared(&p);
    tidesdb_mvcc_commit_init(&d, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &d, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, &d, CLAIM_CF, b, 1, y, 1, 1), 0);
    tidesdb_mvcc_unclaim(m, &d);
    tidesdb_mvcc_unclaim(m, &p);
    tidesdb_mvcc_destroy(m);
}

/* a scanned interval is stale when a write claim inside it, or an interval meeting it, belongs to a
 * commit drawn below the scanner; one drawn above, one not yet drawn and one prepared leave it
 * standing. a read of one key inside a lower interval is stale the same way, and a writer at
 * snapshot or above of a key under a lower interval is blocked */
void test_mvcc_range_stale_orders_by_sequence(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    const uint8_t *a = (const uint8_t *)"a", *z = (const uint8_t *)"z", *k = (const uint8_t *)"k";

    tidesdb_mvcc_claim_t cw[1];
    tidesdb_mvcc_commit_t w, scan;
    claim(&cw[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&w, cw, 1);
    tidesdb_mvcc_commit_init(&scan, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &scan, 1), 1);
    const uint64_t seq_w = tidesdb_mvcc_draw(m, &w);
    const uint64_t seq_scan = tidesdb_mvcc_draw(m, &scan);
    ASSERT_TRUE(seq_w < seq_scan);
    ASSERT_EQ(tidesdb_mvcc_range_stale(m, &scan, CLAIM_CF, a, 1, z, 1, 0), 1);
    ASSERT_EQ(tidesdb_mvcc_range_stale(m, &scan, CLAIM_CF, (const uint8_t *)"l", 1, z, 1, 0), 0);
    tidesdb_mvcc_commit_prepared(&w); /* a future commit leaves the scan standing */
    ASSERT_EQ(tidesdb_mvcc_range_stale(m, &scan, CLAIM_CF, a, 1, z, 1, 0), 0);
    tidesdb_mvcc_unclaim(m, &w);

    /* a writer claiming after the scanner drew is above it, drawn or not */
    tidesdb_mvcc_commit_t late;
    tidesdb_mvcc_claim_t cl[1];
    claim(&cl[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&late, cl, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &late, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_range_stale(m, &scan, CLAIM_CF, a, 1, z, 1, 0), 0);
    (void)tidesdb_mvcc_draw(m, &late);
    ASSERT_EQ(tidesdb_mvcc_range_stale(m, &scan, CLAIM_CF, a, 1, z, 1, 0), 0);
    tidesdb_mvcc_unclaim(m, &late);
    tidesdb_mvcc_unclaim(m, &scan);

    /* an interval drawn below: stale for a scan meeting it, for a read of a key under it, and a
     * block for a snapshot writer of that key, though not for a repeatable-read one */
    tidesdb_mvcc_commit_t d, reader;
    tidesdb_mvcc_commit_init(&d, NULL, 0);
    tidesdb_mvcc_commit_init(&reader, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &d, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, &d, CLAIM_CF, (const uint8_t *)"b", 1,
                                       (const uint8_t *)"y", 1, 1),
              1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &reader, 0), 1);
    (void)tidesdb_mvcc_draw(m, &d);
    (void)tidesdb_mvcc_draw(m, &reader);
    ASSERT_EQ(tidesdb_mvcc_range_stale(m, &reader, CLAIM_CF, a, 1, z, 1, 0), 1);
    ASSERT_EQ(tidesdb_mvcc_range_stale(m, &reader, CLAIM_CF, (const uint8_t *)"y", 1, z, 1, 0), 0);
    ASSERT_EQ(tidesdb_mvcc_read_stale(m, &reader, CLAIM_CF, k, 1, claim_hash("k")), 1);
    ASSERT_EQ(tidesdb_mvcc_read_stale(m, &reader, CLAIM_CF, z, 1, claim_hash("z")), 0);
    ASSERT_EQ(tidesdb_mvcc_write_blocked(m, &reader, CLAIM_CF, k, 1, claim_hash("k"), 1), 1);
    ASSERT_EQ(tidesdb_mvcc_write_blocked(m, &reader, CLAIM_CF, k, 1, claim_hash("k"), 0), 0);
    tidesdb_mvcc_unclaim(m, &reader);
    tidesdb_mvcc_unclaim(m, &d);
    tidesdb_mvcc_destroy(m);
}

/* a prepared batch's intervals outlive the handle that held them as its claims do: the clock owns
 * them in its place, and a writer inside one is still refused */
void test_mvcc_orphaned_intervals_keep_holding(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    tidesdb_mvcc_commit_t *d = calloc(1, sizeof(*d));
    ASSERT_TRUE(d != NULL);
    tidesdb_mvcc_commit_init(d, NULL, 0);
    ASSERT_EQ(tidesdb_mvcc_claim(m, d, 1), 1);
    ASSERT_EQ(tidesdb_mvcc_claim_range(m, d, CLAIM_CF, (const uint8_t *)"b", 1,
                                       (const uint8_t *)"y", 1, 1),
              1);
    tidesdb_mvcc_commit_prepared(d);
    ASSERT_EQ(tidesdb_mvcc_orphan_claims(m, d), 1);
    ASSERT_EQ(tidesdb_mvcc_holds(d), 0);
    free(d);

    tidesdb_mvcc_claim_t cw[1];
    tidesdb_mvcc_commit_t w;
    claim(&cw[0], "k", TDB_MVCC_CLAIM_WRITE);
    tidesdb_mvcc_commit_init(&w, cw, 1);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 0); /* still held, by the clock */
    claim(&cw[0], "z", TDB_MVCC_CLAIM_WRITE);
    ASSERT_EQ(tidesdb_mvcc_claim(m, &w, 1), 1);
    tidesdb_mvcc_unclaim(m, &w);
    tidesdb_mvcc_destroy(m);
}

/* per-seq occurrence counters, indexed by the drawn sequence number (1..CC_TOTAL_SEQS) */
static _Atomic(int) g_seq_hits[CC_TOTAL_SEQS + 2];

static void *cc_seq_worker(void *arg)
{
    tidesdb_mvcc_t *m = (tidesdb_mvcc_t *)arg;
    for (int i = 0; i < CC_PER_THREAD; i++)
    {
        const uint64_t s = tidesdb_mvcc_draw(m, NULL);
        if (s >= 1 && s <= CC_TOTAL_SEQS) atomic_fetch_add(&g_seq_hits[s], 1);
    }
    return NULL;
}

/* under contention the sequence counter hands out every seq in 1..N exactly once -- no duplicates,
 * no gaps. exercises the atomic fetch_add path (run under TSan) */
void test_mvcc_seq_concurrent_unique(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    for (int i = 0; i <= CC_TOTAL_SEQS + 1; i++) atomic_store(&g_seq_hits[i], 0);

    pthread_t threads[CC_THREADS];
    for (int t = 0; t < CC_THREADS; t++)
        ASSERT_EQ(pthread_create(&threads[t], NULL, cc_seq_worker, m), 0);
    for (int t = 0; t < CC_THREADS; t++) pthread_join(threads[t], NULL);

    int ok = 1;
    for (int s = 1; s <= CC_TOTAL_SEQS; s++)
        if (atomic_load(&g_seq_hits[s]) != 1) ok = 0;
    ASSERT_TRUE(ok);
    ASSERT_TRUE(tidesdb_mvcc_current_seq(m) == (uint64_t)CC_TOTAL_SEQS + 1);
    tidesdb_mvcc_destroy(m);
}

/* rounds two neighbouring committers run in lockstep, and the spins one waits on the other before
 * giving up */
#define CC_NEIGHBOUR_ROUNDS  200000
#define CC_LOCKSTEP_SPIN_MAX (1L << 30)

/**
 * cc_neighbour_arg
 * one of two committers deciding neighbouring sequences at the same instant
 * @param m the clock
 * @param arrivals the count both increment at each step, so a step begins only once both are there
 * @param seqs the sequence each drew this round, read by the checker after both have marked
 * @param stalls rounds the watermark stood below the higher sequence once both had marked it
 * @param id 0 or 1, which checks and which slot of seqs is its own
 */
typedef struct
{
    tidesdb_mvcc_t *m;
    _Atomic(int) *arrivals;
    _Atomic(uint64_t) *seqs;
    int stalls;
    int id;
} cc_neighbour_arg;

/* both committers pass every step together; the count only rises, so the n-th step waits for 2n */
static void cc_lockstep(_Atomic(int) *arrivals, const int step)
{
    atomic_fetch_add_explicit(arrivals, 1, memory_order_seq_cst);
    for (long spins = 0; atomic_load_explicit(arrivals, memory_order_seq_cst) < 2 * step; spins++)
        ASSERT_TRUE(spins < CC_LOCKSTEP_SPIN_MAX);
}

static void *cc_neighbour_worker(void *arg)
{
    cc_neighbour_arg *a = (cc_neighbour_arg *)arg;
    int step = 0;
    for (int round = 0; round < CC_NEIGHBOUR_ROUNDS; round++)
    {
        const uint64_t seq = tidesdb_mvcc_draw(a->m, NULL);
        atomic_store_explicit(&a->seqs[a->id], seq, memory_order_seq_cst);
        cc_lockstep(a->arrivals, ++step);
        tidesdb_mvcc_mark(a->m, seq, 1);
        cc_lockstep(a->arrivals, ++step);
        if (a->id == 0)
        {
            const uint64_t other = atomic_load_explicit(&a->seqs[1], memory_order_seq_cst);
            const uint64_t highest = seq > other ? seq : other;
            if (tidesdb_mvcc_visible_seq(a->m) < highest) a->stalls++;
        }
        cc_lockstep(a->arrivals, ++step);
    }
    return NULL;
}

/* two committers holding neighbouring sequences mark them at the same instant, and nobody else
 * commits after them. each publishes its own decision and then reads the other's, so if both reads
 * could miss both writes the watermark would stop below the higher sequence with no third commit
 * left to carry it, and that committer would wait on a publication that never comes. every round
 * must end with the watermark at the higher of the two */
void test_mvcc_two_neighbours_publish_each_other(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);
    _Atomic(int) arrivals;
    atomic_init(&arrivals, 0);
    _Atomic(uint64_t) seqs[2];
    atomic_init(&seqs[0], 0);
    atomic_init(&seqs[1], 0);
    cc_neighbour_arg args[2] = {
        {.m = m, .arrivals = &arrivals, .seqs = seqs, .stalls = 0, .id = 0},
        {.m = m, .arrivals = &arrivals, .seqs = seqs, .stalls = 0, .id = 1}};
    pthread_t threads[2];
    for (int t = 0; t < 2; t++)
        ASSERT_EQ(pthread_create(&threads[t], NULL, cc_neighbour_worker, &args[t]), 0);
    for (int t = 0; t < 2; t++) pthread_join(threads[t], NULL);
    printf("  %d rounds of two neighbouring commits: %d left the watermark behind\n",
           CC_NEIGHBOUR_ROUNDS, args[0].stalls);
    ASSERT_EQ(args[0].stalls, 0);
    tidesdb_mvcc_destroy(m);
}

/**
 * cc_claim_arg
 * one committer of the herd racing to claim the same key
 * @param m the clock
 * @param claim the one claim
 * @param commit its record
 * @param held what the claim call answered
 */
typedef struct
{
    tidesdb_mvcc_t *m;
    tidesdb_mvcc_claim_t claim;
    tidesdb_mvcc_commit_t commit;
    int held;
} cc_claim_arg;

static void *cc_claim_worker(void *arg)
{
    cc_claim_arg *a = (cc_claim_arg *)arg;
    a->held = tidesdb_mvcc_claim(a->m, &a->commit, 1);
    return NULL;
}

/* a thundering herd of committers racing to claim the SAME key -- first-committer-wins means
 * exactly one holds it and every other is refused. exercises the striped chain under a real race
 * (run under TSan) */
void test_mvcc_claim_single_winner(void)
{
    tidesdb_mvcc_t *m = tidesdb_mvcc_create();
    ASSERT_TRUE(m != NULL);

    pthread_t threads[CC_THREADS];
    cc_claim_arg args[CC_THREADS];
    for (int t = 0; t < CC_THREADS; t++)
    {
        args[t].m = m;
        claim(&args[t].claim, "k", TDB_MVCC_CLAIM_WRITE);
        tidesdb_mvcc_commit_init(&args[t].commit, &args[t].claim, 1);
        args[t].held = -1;
        ASSERT_EQ(pthread_create(&threads[t], NULL, cc_claim_worker, &args[t]), 0);
    }
    for (int t = 0; t < CC_THREADS; t++) pthread_join(threads[t], NULL);

    int winners = 0;
    for (int t = 0; t < CC_THREADS; t++)
    {
        if (args[t].held == 1) winners++;
        if (args[t].held == 1) tidesdb_mvcc_unclaim(m, &args[t].commit);
    }
    ASSERT_EQ(winners, 1);
    tidesdb_mvcc_destroy(m);
}

/* the accessors tolerate a NULL clock */
void test_mvcc_null_safe(void)
{
    tidesdb_mvcc_commit_t commit;
    tidesdb_mvcc_commit_init(&commit, NULL, 0);
    ASSERT_TRUE(tidesdb_mvcc_visible_seq(NULL) == 0);
    ASSERT_TRUE(tidesdb_mvcc_draw(NULL, &commit) == 0);
    ASSERT_EQ(tidesdb_mvcc_claim(NULL, &commit, 1), 0);
    ASSERT_EQ(tidesdb_mvcc_read_stale(NULL, &commit, CLAIM_CF, (const uint8_t *)"k", 1, 0), 0);
    ASSERT_EQ(tidesdb_mvcc_write_blocked(NULL, &commit, CLAIM_CF, (const uint8_t *)"k", 1, 0, 1),
              0);
    ASSERT_EQ(
        tidesdb_mvcc_claim_range(NULL, &commit, CLAIM_CF, (const uint8_t *)"a", 1, NULL, 0, 1), 0);
    ASSERT_EQ(
        tidesdb_mvcc_range_stale(NULL, &commit, CLAIM_CF, (const uint8_t *)"a", 1, NULL, 0, 0), 0);
    ASSERT_EQ(tidesdb_mvcc_holds(NULL), 0);
    ASSERT_EQ(tidesdb_mvcc_orphan_claims(NULL, &commit), 1);
    tidesdb_mvcc_unclaim(NULL, &commit);
    tidesdb_mvcc_mark(NULL, 5, 1);
    tidesdb_mvcc_mark_aborted(NULL, 5);
    tidesdb_mvcc_wait_visible(NULL, 5);
    tidesdb_mvcc_reseed(NULL, 5);
    tidesdb_mvcc_destroy(NULL);
    ASSERT_TRUE(1);
}

int main(int argc, char **argv)
{
    INIT_TEST_FILTER(argc, argv);
    RUN_TEST(test_mvcc_seq_counter, tests_passed);
    RUN_TEST(test_mvcc_watermark_follows_decisions, tests_passed);
    RUN_TEST(test_mvcc_reseed, tests_passed);
    RUN_TEST(test_mvcc_claim_refuses_a_writer_in_flight, tests_passed);
    RUN_TEST(test_mvcc_repeatable_read_registers_without_refusing, tests_passed);
    RUN_TEST(test_mvcc_read_claim_refuses_writers, tests_passed);
    RUN_TEST(test_mvcc_read_stale_orders_by_sequence, tests_passed);
    RUN_TEST(test_mvcc_claims_are_sorted, tests_passed);
    RUN_TEST(test_mvcc_orphaned_claims_keep_holding, tests_passed);
    RUN_TEST(test_mvcc_interval_claims_meet_point_claims_both_ways, tests_passed);
    RUN_TEST(test_mvcc_range_stale_orders_by_sequence, tests_passed);
    RUN_TEST(test_mvcc_orphaned_intervals_keep_holding, tests_passed);
    RUN_TEST(test_mvcc_seq_concurrent_unique, tests_passed);
    RUN_TEST(test_mvcc_two_neighbours_publish_each_other, tests_passed);
    RUN_TEST(test_mvcc_claim_single_winner, tests_passed);
    RUN_TEST(test_mvcc_null_safe, tests_passed);
    PRINT_TEST_RESULTS(tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
