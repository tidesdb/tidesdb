/*
* Copyright 2024 TidesDB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

#include <jni.h>
#include "../../bindings/c/libtidesdb_c.h"

JNIEXPORT jlong JNICALL Java_tidesdb_LSMT_newLSMT(JNIEnv *, jobject, jstring, jint, jint, jint);
JNIEXPORT void JNICALL Java_tidesdb_LSMT_delete(JNIEnv *, jobject, jlong);
JNIEXPORT jint JNICALL Java_tidesdb_LSMT_put(JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);
JNIEXPORT jbyteArray JNICALL Java_tidesdb_LSMT_get(JNIEnv *, jobject, jlong, jbyteArray);
JNIEXPORT jint JNICALL Java_tidesdb_LSMT_deleteKey(JNIEnv *, jobject, jlong, jbyteArray);
JNIEXPORT void JNICALL Java_tidesdb_LSMT_close(JNIEnv *, jobject, jlong);
JNIEXPORT jlong JNICALL Java_tidesdb_LSMT_beginTransaction(JNIEnv *, jobject, jlong);
JNIEXPORT jint JNICALL Java_tidesdb_LSMT_commitTransaction(JNIEnv *, jobject, jlong, jlong);
JNIEXPORT void JNICALL Java_tidesdb_LSMT_rollbackTransaction(JNIEnv *, jobject, jlong, jlong);
JNIEXPORT void JNICALL Java_tidesdb_LSMT_addDelete(JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);
JNIEXPORT void JNICALL Java_tidesdb_LSMT_addPut(JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);
JNIEXPORT jlong JNICALL Java_tidesdb_Wal_newWalWithPath(JNIEnv *, jobject, jstring);
JNIEXPORT jint JNICALL Java_tidesdb_Wal_recover(JNIEnv *, jobject, jlong, jlong);
JNIEXPORT void JNICALL Java_tidesdb_Wal_close(JNIEnv *, jobject, jlong);
JNIEXPORT jobjectArray JNICALL Java_tidesdb_LSMT_lessThan(JNIEnv *, jobject, jlong, jbyteArray);
JNIEXPORT jobjectArray JNICALL Java_tidesdb_LSMT_greaterThan(JNIEnv *, jobject, jlong, jbyteArray);
JNIEXPORT jobjectArray JNICALL Java_tidesdb_LSMT_range(JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);
JNIEXPORT jobjectArray JNICALL Java_tidesdb_LSMT_nRange(JNIEnv *, jobject, jlong, jbyteArray, jbyteArray);
JNIEXPORT jobjectArray JNICALL Java_tidesdb_LSMT_lessThanEq(JNIEnv *, jobject, jlong, jbyteArray);
JNIEXPORT jobjectArray JNICALL Java_tidesdb_LSMT_greaterThanEq(JNIEnv *, jobject, jlong, jbyteArray);