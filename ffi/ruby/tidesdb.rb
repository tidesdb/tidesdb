=begin
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
=end

require 'ffi'

module TidesDB
  extend FFI::Library
  ffi_lib 'libtidesdb'

  attach_function :LSMT_New, [:string, :int, :int, :int], :pointer
  attach_function :LSMT_Delete, [:pointer], :void
  attach_function :LSMT_Put, [:pointer, :pointer, :size_t, :pointer, :size_t], :int
  attach_function :LSMT_Get, [:pointer, :pointer, :size_t, :pointer], :pointer
  attach_function :LSMT_DeleteKey, [:pointer, :pointer, :size_t], :int
  attach_function :LSMT_Close, [:pointer], :void
  attach_function :LSMT_BeginTransaction, [:pointer], :pointer
  attach_function :LSMT_CommitTransaction, [:pointer, :pointer], :int
  attach_function :LSMT_RollbackTransaction, [:pointer, :pointer], :void
  attach_function :LSMT_AddDelete, [:pointer, :pointer, :size_t, :pointer, :size_t], :void
  attach_function :LSMT_AddPut, [:pointer, :pointer, :size_t, :pointer, :size_t], :void
  attach_function :Wal_NewWithPath, [:string], :pointer
  attach_function :Wal_Recover, [:pointer, :pointer], :int
  attach_function :Wal_Close, [:pointer], :void
  attach_function :LSMT_NGet, [:pointer, :pointer, :size_t, :pointer], :pointer
  attach_function :LSMT_LessThan, [:pointer, :pointer, :size_t, :pointer], :pointer
  attach_function :LSMT_GreaterThan, [:pointer, :pointer, :size_t, :pointer], :pointer
  attach_function :LSMT_Range, [:pointer, :pointer, :size_t, :pointer, :size_t, :pointer], :pointer
  attach_function :LSMT_NRange, [:pointer, :pointer, :size_t, :pointer, :size_t, :pointer], :pointer
  attach_function :LSMT_LessThanEq, [:pointer, :pointer, :size_t, :pointer], :pointer
  attach_function :LSMT_GreaterThanEq, [:pointer, :pointer, :size_t, :pointer], :pointer

  class LSMT
    def initialize(directory, memtable_flush_size, compaction_interval, max_compaction_threads)
      @ptr = TidesDB.LSMT_New(directory, memtable_flush_size, compaction_interval, max_compaction_threads)
    end

    def delete
      TidesDB.LSMT_Delete(@ptr)
    end

    def put(key, value)
      TidesDB.LSMT_Put(@ptr, FFI::MemoryPointer.from_string(key), key.size, FFI::MemoryPointer.from_string(value), value.size)
    end

    def get(key)
      value_len = FFI::MemoryPointer.new(:size_t)
      value_ptr = TidesDB.LSMT_Get(@ptr, FFI::MemoryPointer.from_string(key), key.size, value_len)
      value_ptr.read_string(value_len.read(:size_t))
    ensure
      FFI::MemoryPointer.free(value_ptr)
    end

    def delete_key(key)
      TidesDB.LSMT_DeleteKey(@ptr, FFI::MemoryPointer.from_string(key), key.size)
    end

    def close
      TidesDB.LSMT_Close(@ptr)
    end

    def begin_transaction
      Transaction.new(TidesDB.LSMT_BeginTransaction(@ptr))
    end

    def commit_transaction(tx)
      TidesDB.LSMT_CommitTransaction(@ptr, tx.ptr)
    end

    def rollback_transaction(tx)
      TidesDB.LSMT_RollbackTransaction(@ptr, tx.ptr)
    end

    def nget(key)
      result_len = FFI::MemoryPointer.new(:size_t)
      c_array = TidesDB.LSMT_NGet(@ptr, FFI::MemoryPointer.from_string(key), key.size, result_len)
      convert_to_ruby_array(c_array, result_len.read(:size_t))
    end

    def less_than(key)
      result_len = FFI::MemoryPointer.new(:size_t)
      c_array = TidesDB.LSMT_LessThan(@ptr, FFI::MemoryPointer.from_string(key), key.size, result_len)
      convert_to_ruby_array(c_array, result_len.read(:size_t))
    end

    def greater_than(key)
      result_len = FFI::MemoryPointer.new(:size_t)
      c_array = TidesDB.LSMT_GreaterThan(@ptr, FFI::MemoryPointer.from_string(key), key.size, result_len)
      convert_to_ruby_array(c_array, result_len.read(:size_t))
    end

    def range(start, end_)
      result_len = FFI::MemoryPointer.new(:size_t)
      c_array = TidesDB.LSMT_Range(@ptr, FFI::MemoryPointer.from_string(start), start.size, FFI::MemoryPointer.from_string(end_), end_.size, result_len)
      convert_to_ruby_array(c_array, result_len.read(:size_t))
    end

    def nrange(start, end_)
      result_len = FFI::MemoryPointer.new(:size_t)
      c_array = TidesDB.LSMT_NRange(@ptr, FFI::MemoryPointer.from_string(start), start.size, FFI::MemoryPointer.from_string(end_), end_.size, result_len)
      convert_to_ruby_array(c_array, result_len.read(:size_t))
    end

    def less_than_eq(key)
      result_len = FFI::MemoryPointer.new(:size_t)
      c_array = TidesDB.LSMT_LessThanEq(@ptr, FFI::MemoryPointer.from_string(key), key.size, result_len)
      convert_to_ruby_array(c_array, result_len.read(:size_t))
    end

    def greater_than_eq(key)
      result_len = FFI::MemoryPointer.new(:size_t)
      c_array = TidesDB.LSMT_GreaterThanEq(@ptr, FFI::MemoryPointer.from_string(key), key.size, result_len)
      convert_to_ruby_array(c_array, result_len.read(:size_t))
    end

    private

    def convert_to_ruby_array(c_array, length)
      result = []
      length.times do |i|
        elem_ptr = c_array.get_pointer(i * FFI::Pointer.size)
        elem_len = elem_ptr.read_string_length
        result << elem_ptr.read_string(elem_len)
      end
      result
    ensure
      FFI::MemoryPointer.free(c_array)
    end
  end

  class Transaction
    attr_reader :ptr

    def initialize(ptr)
      @ptr = ptr
    end

    def add_delete(key, value)
      TidesDB.LSMT_AddDelete(@ptr, FFI::MemoryPointer.from_string(key), key.size, FFI::MemoryPointer.from_string(value), value.size)
    end

    def add_put(key, value)
      TidesDB.LSMT_AddPut(@ptr, FFI::MemoryPointer.from_string(key), key.size, FFI::MemoryPointer.from_string(value), value.size)
    end
  end

  class Wal
    def initialize(path)
      @ptr = TidesDB.Wal_NewWithPath(path)
    end

    def recover(lsmt)
      TidesDB.Wal_Recover(@ptr, lsmt.ptr)
    end

    def close
      TidesDB.Wal_Close(@ptr)
    end
  end
end