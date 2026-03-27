/**
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef _OBJSTORE_S3_H_
#define _OBJSTORE_S3_H_

#include "objstore.h"

/**
 * tidesdb_objstore_s3_create
 * create an S3-compatible object store connector.
 * works with AWS S3, MinIO, etc.
 *
 * @param endpoint      S3 endpoint (e.g. "s3.amazonaws.com" or "minio.local:9000")
 * @param bucket        bucket name
 * @param prefix        key prefix (e.g. "production/db1/"), can be NULL
 * @param access_key    AWS access key ID
 * @param secret_key    AWS secret access key
 * @param region        AWS region (e.g. "us-east-1"), NULL for MinIO
 * @param use_ssl       1 for HTTPS, 0 for HTTP
 * @param use_path_style 1 for path-style URLs (MinIO), 0 for virtual-hosted (AWS)
 * @return connector handle, or NULL on error
 */
tidesdb_objstore_t *tidesdb_objstore_s3_create(const char *endpoint, const char *bucket,
                                               const char *prefix, const char *access_key,
                                               const char *secret_key, const char *region,
                                               int use_ssl, int use_path_style);

#endif /* _OBJSTORE_S3_H_ */
