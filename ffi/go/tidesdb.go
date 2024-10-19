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

package tidesdb

/*
#cgo CFLAGS: -I/..
#cgo LDFLAGS: -L/.. -ltidesdb
#include "libtidesdb_c.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

// LSMT is a wrapper around the C LSMT struct
type LSMT struct {
	ptr *C.LSMT
}

// Wal is a wrapper around the C Wal struct
type Wal struct {
	ptr *C.Wal
}

// Transaction is a wrapper around the C Transaction struct
type Transaction struct {
	ptr *C.Transaction
}

// NewLSMT creates a new LSMT instance
func NewLSMT(directory string, memtableFlushSize, compactionInterval, maxCompactionThreads int) *LSMT {
	cDirectory := C.CString(directory)
	defer C.free(unsafe.Pointer(cDirectory))
	return &LSMT{ptr: C.LSMT_New(cDirectory, C.int(memtableFlushSize), C.int(compactionInterval), C.int(maxCompactionThreads))}
}

// Delete deletes an LSMT instance
func (lsmt *LSMT) Delete() {
	C.LSMT_Delete(lsmt.ptr)
}

// Put puts a key-value pair into the LSMT
func (lsmt *LSMT) Put(key, value []byte) int {
	return int(C.LSMT_Put(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), (*C.uint8_t)(unsafe.Pointer(&value[0])), C.size_t(len(value))))
}

// Get gets a value for a given key from the LSMT
func (lsmt *LSMT) Get(key []byte) []byte {
	var valueLen C.size_t
	value := C.LSMT_Get(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), &valueLen)
	defer C.free(unsafe.Pointer(value))
	return C.GoBytes(unsafe.Pointer(value), C.int(valueLen))
}

// DeleteKey deletes a key from the LSMT
func (lsmt *LSMT) DeleteKey(key []byte) int {
	return int(C.LSMT_DeleteKey(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key))))
}

// Close closes the LSMT
func (lsmt *LSMT) Close() {
	C.LSMT_Close(lsmt.ptr)
}

// BeginTransaction begins a new transaction
func (lsmt *LSMT) BeginTransaction() *Transaction {
	return &Transaction{ptr: C.LSMT_BeginTransaction(lsmt.ptr)}
}

// CommitTransaction commits a transaction
func (lsmt *LSMT) CommitTransaction(tx *Transaction) int {
	return int(C.LSMT_CommitTransaction(lsmt.ptr, tx.ptr))
}

// RollbackTransaction rolls back a transaction
func (lsmt *LSMT) RollbackTransaction(tx *Transaction) {
	C.LSMT_RollbackTransaction(lsmt.ptr, tx.ptr)
}

// AddDelete adds a delete operation to a transaction
func (tx *Transaction) AddDelete(key, value []byte) {
	C.LSMT_AddDelete(tx.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), (*C.uint8_t)(unsafe.Pointer(&value[0])), C.size_t(len(value)))
}

// AddPut adds a put operation to a transaction
func (tx *Transaction) AddPut(key, value []byte) {
	C.LSMT_AddPut(tx.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), (*C.uint8_t)(unsafe.Pointer(&value[0])), C.size_t(len(value)))
}

// NewWalWithPath creates a new Wal instance with a path
func NewWalWithPath(path string) *Wal {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	return &Wal{ptr: C.Wal_NewWithPath(cPath)}
}

// Recover recovers operations from the Wal
func (wal *Wal) Recover(lsmt *LSMT) int {
	return int(C.Wal_Recover(wal.ptr, lsmt.ptr))
}

// Close closes the Wal
func (wal *Wal) Close() {
	C.Wal_Close(wal.ptr)
}

// Helper function to convert C array to Go slice
func convertToGoSlice(cArray **C.uint8_t, length C.size_t) [][]byte {
	var result [][]byte
	for i := C.size_t(0); i < length; i++ {
		elem := C.GoBytes(unsafe.Pointer(C.getElement(cArray, i)), C.int(C.getElementLength(cArray, i)))
		result = append(result, elem)
	}
	return result
}

// NGet gets multiple values for a given key from the LSMT
func (lsmt *LSMT) NGet(key []byte) [][]byte {
	var resultLen C.size_t
	cArray := C.LSMT_NGet(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), &resultLen)
	defer C.free(unsafe.Pointer(cArray))
	return convertToGoSlice(cArray, resultLen)
}

// LessThan gets values less than a given key from the LSMT
func (lsmt *LSMT) LessThan(key []byte) [][]byte {
	var resultLen C.size_t
	cArray := C.LSMT_LessThan(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), &resultLen)
	defer C.free(unsafe.Pointer(cArray))
	return convertToGoSlice(cArray, resultLen)
}

// GreaterThan gets values greater than a given key from the LSMT
func (lsmt *LSMT) GreaterThan(key []byte) [][]byte {
	var resultLen C.size_t
	cArray := C.LSMT_GreaterThan(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), &resultLen)
	defer C.free(unsafe.Pointer(cArray))
	return convertToGoSlice(cArray, resultLen)
}

// Range gets values in a range from the LSMT
func (lsmt *LSMT) Range(start, end []byte) [][]byte {
	var resultLen C.size_t
	cArray := C.LSMT_Range(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&start[0])), C.size_t(len(start)), (*C.uint8_t)(unsafe.Pointer(&end[0])), C.size_t(len(end)), &resultLen)
	defer C.free(unsafe.Pointer(cArray))
	return convertToGoSlice(cArray, resultLen)
}

// NRange gets multiple values in a range from the LSMT
func (lsmt *LSMT) NRange(start, end []byte) [][]byte {
	var resultLen C.size_t
	cArray := C.LSMT_NRange(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&start[0])), C.size_t(len(start)), (*C.uint8_t)(unsafe.Pointer(&end[0])), C.size_t(len(end)), &resultLen)
	defer C.free(unsafe.Pointer(cArray))
	return convertToGoSlice(cArray, resultLen)
}

// LessThanEq gets values less than or equal to a given key from the LSMT
func (lsmt *LSMT) LessThanEq(key []byte) [][]byte {
	var resultLen C.size_t
	cArray := C.LSMT_LessThanEq(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), &resultLen)
	defer C.free(unsafe.Pointer(cArray))
	return convertToGoSlice(cArray, resultLen)
}

// GreaterThanEq gets values greater than or equal to a given key from the LSMT
func (lsmt *LSMT) GreaterThanEq(key []byte) [][]byte {
	var resultLen C.size_t
	cArray := C.LSMT_GreaterThanEq(lsmt.ptr, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key)), &resultLen)
	defer C.free(unsafe.Pointer(cArray))
	return convertToGoSlice(cArray, resultLen)
}