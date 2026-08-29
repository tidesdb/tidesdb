/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __TIDESDB_CF_CONFIG_H__
#define __TIDESDB_CF_CONFIG_H__

#include "base/encoding/encoding.h" /* tidesdb_encoding_registry_t for validation */
#include "db.h"                     /* tidesdb_column_family_config_t */

/* cf_config is a standalone serialize/validate service over the public column family config. it
 * turns a config into the opaque blob the manifest persists on a cf record and back, and validates
 * a config against the encoding registry. it owns no engine and is unit-testable with a stack
 * config. keys are ordered byte-wise so no config field affects sstable mergeability -- every field
 * is runtime-mutable and there is no immutable subset. */

/* on-disk version leading a serialized blob; a hard break (v10), so a blob whose version is not the
 * current one is refused rather than misread */
#define CF_CONFIG_BLOB_VERSION 10

/* the fixed portion of a serialized blob (version byte through the encoding-count byte); the
 * variable encoding-id array of encoding_count bytes follows */
#define CF_CONFIG_BLOB_FIXED_SIZE 60

/* the highest encoding id a pipeline entry may carry, named from the enum it is cast to rather than
 * written as a number so adding an algorithm cannot leave this behind */
#define CF_CONFIG_MAX_ENCODING_ID TDB_COMPRESS_LZ4_FAST

/* the klog node size a family is created with unless it asks for another. it lives here rather than
 * beside the other public defaults because the engine sizes the pool a decoded node draws its arena
 * from against it -- those two numbers describe the same object and drifting apart makes every
 * cached node reserve a chunk many times its own size */
#define TDB_DEFAULT_CF_BTREE_BLOCK_SIZE 4096

/**
 * cf_config_value_threshold
 * resolve the size at or above which this family's values are separated into the value log, which
 * is the database-wide threshold unless the family opted out of separation entirely
 * @param cfg the family config
 * @param db_threshold the database's value_separation_threshold
 * @return the threshold to hand the sstable builder, SIZE_MAX when the family keeps values inline
 */
size_t cf_config_value_threshold(const tidesdb_column_family_config_t *cfg, size_t db_threshold);

/**
 * cf_config_validate
 * check a column family config is well-formed -- name length, encoding pipeline bounds, that every
 * encoding id names a real algorithm and (when a registry is given) that it is registered, and a
 * sane bloom false-positive rate
 * @param cfg the config to validate
 * @param reg the encoding registry to resolve pipeline ids against, or NULL to skip that check
 * @return 0 if valid, -1 otherwise
 */
int cf_config_validate(const tidesdb_column_family_config_t *cfg,
                       const tidesdb_encoding_registry_t *reg);

/**
 * cf_config_warn_layout
 * log a warning when a config inlines values so large that they crowd the klog nodes holding them.
 * this is deliberately advisory rather than part of cf_config_validate -- a validate failure also
 * refuses a persisted config on the way back in, which would stop a database that already carries
 * this setting from opening at all, and the setting costs read performance rather than correctness.
 * the threshold is database level and the node size is not, so this is called where both are in
 * hand rather than from cf_create
 * @param cfg the config to inspect, may be NULL
 * @param db_threshold the database's value_separation_threshold
 */
void cf_config_warn_layout(const tidesdb_column_family_config_t *cfg, size_t db_threshold);

/**
 * cf_config_serialize
 * encode a config's persisted fields into a freshly allocated blob the caller frees. the name (held
 * on the manifest cf record) and the runtime-only commit hook are not persisted here.
 * @param cfg the config to serialize
 * @param out out -- newly allocated blob on success, owned by the caller
 * @param out_len out -- length of the blob in bytes
 * @return 0 on success, -1 on a bad argument or allocation failure
 */
int cf_config_serialize(const tidesdb_column_family_config_t *cfg, uint8_t **out, size_t *out_len);

/**
 * cf_config_deserialize
 * decode a blob into a config's persisted fields; the caller sets name and the commit hook
 * separately
 *
 * only the fields the blob carries are written, so out must be zeroed first. what is left untouched
 * is not merely stale but read -- the validation below measures the name, and the commit hook would
 * be installed from whatever the caller's memory held
 * @param data the blob bytes
 * @param len length of data in bytes
 * @param out the config to fill, zeroed by the caller; persisted fields only
 * @return 0 on success, -1 on a bad argument, a wrong version, a truncated blob, or a blob whose
 *         decoded values are ones the create path would itself have refused
 */
int cf_config_deserialize(const uint8_t *data, size_t len, tidesdb_column_family_config_t *out);

#endif /* __TIDESDB_CF_CONFIG_H__ */
