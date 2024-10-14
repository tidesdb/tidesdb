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
#ifndef TIDESDB_LIBRARY_H
#define TIDESDB_LIBRARY_H


#include "kv.pb.h"
#include "operation.pb.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <functional>



// The TidesDB namespace
namespace TidesDB {

	constexpr std::string SSTABLE_EXTENSION = ".sst"; // SSTable file extension
	constexpr std::string TOMBSTONE_VALUE = "$tombstone"; // Tombstone value
	constexpr std::string WAL_EXTENSION = ".wal"; // Write-ahead log file extension

	// // Operation types (for transactions)
	enum class OperationType {
		OpPut,
		OpDelete
	};
	//
	// // Operation struct
	// struct Operation {
	// 	OperationType type; // Operation type
	// 	std::vector<uint8_t> key; // Key as a vector of bytes
	// 	std::vector<uint8_t> value; // Only used for OpPut
	// };

	// Transaction struct
	struct Transaction {
		std::vector<Operation> operations; // Operations in the transaction
		bool aborted = false; // Whether the transaction was aborted
	};

	// Exception class
	class TidesDBException : public std::exception {
	  private:
	    std::string message;
	  public:
	    explicit TidesDBException(const std::string &msg) : message(msg) {}
	    virtual const char* what() const noexcept override {
	        return message.c_str();
	    }
	};


	// Key-value struct
	// struct KeyValue {
	// 	std::vector<uint8_t> key;    // Key as a vector of bytes
	// 	std::vector<uint8_t> value;  // Value as a vector of bytes
	// };

	// Serialize serializes the KeyValue struct to a byte vector
	std::vector<uint8_t> serialize(const KeyValue& kv);

	// Deserialize deserializes a byte vector to a KeyValue struct
	KeyValue deserialize(const std::vector<uint8_t>& buffer);

	// SerializeOperation serializes the Operation struct to a byte vector
	std::vector<uint8_t> serializeOperation(const Operation& op);

	// DeserializeOperation deserializes a byte vector to an Operation struct
	Operation deserializeOperation(const std::vector<uint8_t>& buffer);


	// Gets os specific path separator
	std::string getPathSeparator();

	// Constants
	constexpr int PAGE_SIZE = 1024; // Page size
	constexpr int PAGE_HEADER_SIZE = sizeof(int64_t); // 8 bytes for overflow page pointer
	constexpr int PAGE_BODY_SIZE = PAGE_SIZE - PAGE_HEADER_SIZE; // Page body size

	// AVL Node class
	class AVLNode {
	public:
		std::vector<uint8_t> key;
		std::vector<uint8_t> value;
		AVLNode* left;
		AVLNode* right;
		int height;

		AVLNode(const std::vector<uint8_t>& k, const std::vector<uint8_t>& v)
			: key(k), value(v), left(nullptr), right(nullptr), height(1) {}
	};

	// AVL Tree class
	class AVLTree {
	private:
		AVLNode* root;
		std::shared_mutex rwlock;

		AVLNode* rightRotate(AVLNode* y);
		AVLNode* leftRotate(AVLNode* x);
		int getBalance(AVLNode* node);
		AVLNode* insert(AVLNode* node, const std::vector<uint8_t>& key, const std::vector<uint8_t>& value);
		void printHex(const std::vector<uint8_t>& data);
		AVLNode* deleteNode(AVLNode* root, const std::vector<uint8_t>& key);
		void deleteKey(const std::vector<uint8_t>& key);
		void inOrder(AVLNode* node);
		AVLNode* minValueNode(AVLNode* node);
		int height(AVLNode* node);
		void inOrderTraversal(AVLNode* node, std::function<void(const std::vector<uint8_t>&, const std::vector<uint8_t>&)> func);
	public:
		void insert(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value);
		void deleteKV(const std::vector<uint8_t>& key);
		void inOrder();
		void inOrderTraversal(std::function<void(const std::vector<uint8_t>&, const std::vector<uint8_t>&)> func);

		void clear();
	};

    // Pager class
    // Manages reading and writing pages to a file
	class Pager {
	private:

		std::fstream file;
	public:
          // Constructor
          Pager(const std::string &filename, std::ios::openmode mode);

          // Destructor
          ~Pager();

          // Write page
          // Writes a new page to the file
          // takes a vector of characters as input
          // If the page is full, it writes to a new page and updates the overflow page number in the header
          // returns page number
		  int64_t Write(const std::vector<uint8_t> &data);

          // Write to page
          // Writes to an existing page in the file
          // takes a vector of characters as input
          // returns page number
		  int64_t WriteTo(int64_t page_number, const std::vector<uint8_t> &data);

          // Read page
		  // Reads a page from the file
          // takes a page number as input
          // returns a vector of characters
          // takes into account overflow pages
		  std::vector<uint8_t> Read(int64_t page_number);

		 // GetFile
		 // Returns the file stream
		 std::fstream& GetFile();


	}; // Pager class

	class Wal {
	public:
		Wal(Pager* pager) : pager(pager) {}
		Pager* pager;
		std::shared_mutex lock;

		bool WriteOperation(const Operation& operation);
		std::vector<Operation> ReadOperations();

		void Close();

	private:
	};

	class SSTable {
	public:
		SSTable(Pager* pager) : pager(pager) {}
		Pager* pager;
		std::vector<uint8_t> minKey;
		std::vector<uint8_t> maxKey;
		std::shared_mutex lock;
	};

	class LSMT {

	public:
		LSMT(const std::string & string, int memtable_flush_size, int compaction_interval, int minimum_ss_tables, const std::shared_ptr<Pager> & pager, const std::vector<std::shared_ptr<SSTable>> & vector) : directory(string), memtableFlushSize(memtable_flush_size), compactionInterval(compaction_interval), minimumSSTables(minimum_ss_tables) {
            wal = new Wal(new Pager(directory + getPathSeparator() + WAL_EXTENSION, std::ios::in | std::ios::out | std::ios::trunc));
			memtableSize.store(0);
			isFlushing.store(0);
			isCompacting.store(0);


			for (const auto &sstable : vector) {
                sstables.push_back(sstable.get());
            }

			// Create a new memtable
			memtable = new AVLTree();

        }

		~LSMT() {

		}

		bool Put(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value);

		void Close() {
			std::cout << "Close called\n";

			// Lock the memtable for writing
			std::unique_lock<std::shared_mutex> memtableLock(memtableMutex);

			// Flush the memtable to disk
			if (!flushMemtable()) {
				std::cerr << "Failed to flush memtable during close\n";
			}

			// Clear the memtable
			memtable->clear();

			// Clear the list of SSTables
			{
				std::unique_lock<std::shared_mutex> sstablesLockGuard(sstablesLock);
				sstables.clear();
			}

			// Close the write-ahead log
			wal->Close();

			std::cout << "Close completed\n";
		}

		// Function to create a new LSMT instance
		static std::unique_ptr<LSMT> New(const std::string &directory, std::filesystem::perms directoryPerm, int memtableFlushSize, int compactionInterval, int minimumSSTables) {
			if (directory.empty()) {
				throw std::invalid_argument("directory cannot be empty");
			}

			if (!std::filesystem::exists(directory)) {
				std::filesystem::create_directory(directory);
				std::filesystem::permissions(directory, directoryPerm);
			}

			std::shared_ptr<Pager> walPager = std::make_shared<Pager>(directory + getPathSeparator() + WAL_EXTENSION, std::ios::in | std::ios::out | std::ios::trunc);

			std::vector<std::shared_ptr<SSTable>> sstables;
			for (const auto &entry : std::filesystem::directory_iterator(directory)) {
				if (entry.is_regular_file() && entry.path().extension() == SSTABLE_EXTENSION) {
					std::shared_ptr<Pager> sstablePager = std::make_shared<Pager>(entry.path().string(), std::ios::in | std::ios::out);
					sstables.push_back(std::make_shared<SSTable>(sstablePager.get()));
				}
			}

			return std::unique_ptr<LSMT>(new LSMT(directory, memtableFlushSize, compactionInterval, minimumSSTables, walPager, sstables));
		}
	private:




		std::vector<SSTable*> sstables;
		std::shared_mutex sstablesLock;
		std::shared_mutex memtableLock;
		std::shared_mutex walLock;

		std::string directory;
		int compactionInterval;
		int minimumSSTables;
		std::condition_variable_any cond;
		AVLTree* memtable;
		Wal* wal;
		std::shared_mutex memtableMutex;
		std::mutex condMutex;
		std::atomic<int32_t> isFlushing;
		std::atomic<int32_t> isCompacting;
		std::atomic<int64_t> memtableSize;
		int memtableFlushSize;

		bool flushMemtable();

	};

}

#endif //TIDESDB_LIBRARY_H
