/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_TXN_CF_SOURCE_H__
#define __TIDESDB_TXN_CF_SOURCE_H__

#include "../column_family/column_family.h"
#include "source.h"

/* the read source over one column family's on-disk sstable levels -- the deepest tier in a
 * transaction's source stack, consulted after the write buffer and the shared L0. it is the sstable
 * analog of tidesdb_l0_source: it walks the cf's level_set top-down for the newest version of a key
 * visible at the reader's snapshot and resolves a spilled value through the cf's shared value log.
 */

/**
 * cf_source
 * bind a read source to one column family's sstable levels. the source borrows the cf for its
 * lifetime, so the cf and its level_set and vlog must outlive any read through it. bound to a
 * single cf, so the get's cf_index argument is ignored -- the composer routes only this cf's keys
 * to this source.
 * @param cf the column family to read, borrowed
 * @param out receives the source, its ctx set to cf
 */
void cf_source(cf_t *cf, tidesdb_source_t *out);

#endif /* __TIDESDB_TXN_CF_SOURCE_H__ */
