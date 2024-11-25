/*
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
#ifndef SERIALIZE_H
#define SERIALIZE_H

#include <zstd.h>

#include "bloomfilter.h"
#include "serializable_structures.h"

/*
 * serialize_key_value_pair
 * serialize a key value pair
 * @param kvp the key value pair to serialize
 * @param buffer the buffer to write the serialized data to
 * @param encoded_size the size of the encoded data
 * @param compress whether to compress the data
 * @return whether the operation was successful
 */
bool serialize_key_value_pair(const key_value_pair* kvp, uint8_t** buffer, size_t* encoded_size,
                              bool compress);

/*
 * deserialize_key_value_pair
 * deserialize a key value pair
 * @param buffer the buffer to read the serialized data from
 * @param buffer_size the size of the buffer
 * @param kvp the key value pair to deserialize
 * @param decompress whether to decompress the data
 * @return whether the operation was successful
 */
bool deserialize_key_value_pair(const uint8_t* buffer, size_t buffer_size, key_value_pair** kvp,
                                bool decompress);

/*
 * serialize_operation
 * serialize an operation
 * @param op the operation to serialize
 * @param buffer the buffer to write the serialized data to
 * @param encoded_size the size of the encoded data
 * @param compress whether to compress the data
 * @return whether the operation was successful
 */
bool serialize_operation(const operation* op, uint8_t** buffer, size_t* encoded_size,
                         bool compress);

/*
 * deserialize_operation
 * deserialize an operation
 * @param buffer the buffer to read the serialized data from
 * @param buffer_size the size of the buffer
 * @param op the operation to deserialize
 * @param decompress whether to decompress the data
 * @return whether the operation was successful
 */
bool deserialize_operation(const uint8_t* buffer, size_t buffer_size, operation** op,
                           bool decompress);

/*
 * serialize_column_family_config
 * serialize a column family config
 * @param config the column family config to serialize
 * @param buffer the buffer to write the serialized data to
 * @param encoded_size the size of the encoded data
 * @return whether the operation was successful
 */
bool serialize_column_family_config(const column_family_config* config, uint8_t** buffer,
                                    size_t* encoded_size);

/*
 * deserialize_column_family_config
 * deserialize a column family config
 * @param buffer the buffer to read the serialized data from
 * @param buffer_size the size of the buffer
 * @param config the column family config to deserialize
 * @return whether the operation was successful
 */
bool deserialize_column_family_config(const uint8_t* buffer, size_t buffer_size,
                                      column_family_config** config);

/*
 * serialize_bloomfilter
 * serialize a bloomfilter
 * @param bf the bloomfilter to serialize
 * @param buffer the buffer to write the serialized data to
 * @param encoded_size the size of the encoded data
 * @param compress whether to compress the data
 * @return whether the operation was successful
 */
bool serialize_bloomfilter(const bloomfilter* bf, uint8_t** buffer, size_t* encoded_size,
                           bool compress);

/*
 * deserialize_bloomfilter
 * deserialize a bloomfilter
 * @param buffer the buffer to read the serialized data from
 * @param buffer_size the size of the buffer
 * @param bf the bloomfilter to deserialize
 * @param decompress whether to decompress the data
 * @return whether the operation was successful
 */
bool deserialize_bloomfilter(const uint8_t* buffer, size_t buffer_size, bloomfilter** bf,
                             bool decompress);

#endif /* SERIALIZE_H */