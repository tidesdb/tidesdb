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

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <string>
#include <vector>

#include "proto/kv.pb.h"
#include "proto/operation.pb.h"

// The TidesDB namespace
namespace TidesDB {

const std::string SSTABLE_EXTENSION = ".sst";          // SSTable file extension
constexpr const char *TOMBSTONE_VALUE = "$tombstone";  // Tombstone value
const std::string WAL_EXTENSION = ".wal";              // Write-ahead log file extension

// ConvertToUint8Vector converts a vector of characters to a vector of unsigned
// 8-bit integers
std::vector<uint8_t> ConvertToUint8Vector(const std::vector<char> &input);

// ConvertToCharVector converts a vector of unsigned 8-bit integers to a vector
// of characters
std::vector<char> ConvertToCharVector(const std::vector<uint8_t> &input);

// Operation types (for transactions)
enum class OperationType {
    OpPut,    // Put operation
    OpDelete  // Delete operation
};

// Transaction operation
struct TransactionOperation {
    Operation op;               // the operation
    struct Rollback *rollback;  // Rollback information
};

// Rollback information for a transaction operation
struct Rollback {
    OperationType type;          // Type of the operation (OpPut or OpDelete)
    std::vector<uint8_t> key;    // Key of the operation
    std::vector<uint8_t> value;  // Value of the operation (for OpPut)
};

// Transaction struct
struct Transaction {
    std::vector<TransactionOperation> operations;  // List of operations
    bool aborted = false;                          // Whether the transaction was aborted
    void AddPut(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value);
};

// Exception class
class TidesDBException : public std::exception {
   private:
    std::string message;  // Exception message
   public:
    explicit TidesDBException(const std::string &msg) : message(msg) {}
    virtual const char *what() const noexcept override { return message.c_str(); }
};

// Serialize serializes the KeyValue struct to a byte vector
std::vector<uint8_t> serialize(const KeyValue &kv);

// Deserialize deserializes a byte vector to a KeyValue struct
KeyValue deserialize(const std::vector<uint8_t> &buffer);

// SerializeOperation serializes the Operation struct to a byte vector
std::vector<uint8_t> serializeOperation(const Operation &op);

// DeserializeOperation deserializes a byte vector to an Operation struct
Operation deserializeOperation(const std::vector<uint8_t> &buffer);

// Gets os specific path separator
std::string getPathSeparator();

// Constants
constexpr int PAGE_SIZE =
    (1024 * 4);  // Page size, as discussed on Reddit 1024*4 is a better page size.
constexpr int PAGE_HEADER_SIZE = sizeof(int64_t);             // 8 bytes for overflow page pointer
constexpr int PAGE_BODY_SIZE = PAGE_SIZE - PAGE_HEADER_SIZE;  // Page body size


// SkipListNode is a node in a skip list
class SkipListNode {
public:
    std::vector<uint8_t> key;    // Key
    std::vector<uint8_t> value;  // Value
    std::vector<std::atomic<SkipListNode *>> forward;  // Forward pointers

    // Constructor
    SkipListNode(const std::vector<uint8_t> &k, const std::vector<uint8_t> &v, int level)
      : key(k), value(v), forward(level) {
        for (int i = 0; i < level; ++i) {
            forward[i].store(nullptr, std::memory_order_relaxed);
        }
    }
};

// SkipList is a lock-free skip list class
class SkipList {
private:
    int maxLevel;  // Maximum level of the skip list
    float probability;  // Probability of a node having a higher level
    std::shared_ptr<SkipListNode> head;
    std::atomic<int> level;  // Current level of the skip list
    std::atomic<int> cachedSize;  // should be atomic because it is accessed by multiple threads, this helps us avoid traversing the list to get the size
    // randomLevel generates a random level for a new node
    int randomLevel() const;
public:
    // Constructor
    SkipList(int maxLevel, float probability)
           : maxLevel(maxLevel), probability(probability), level(0) {
        head = std::make_shared<SkipListNode>(std::vector<uint8_t>(), std::vector<uint8_t>(), maxLevel);
    }

    // insert inserts a key-value pair into the skip list
    void insert(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value);

    // deleteKV deletes a key from the skip list
    void deleteKV(const std::vector<uint8_t> &key);

    // get gets the value for a given key
    std::vector<uint8_t> get(const std::vector<uint8_t> &key);

    // inOrderTraversal traverses the skip list in in-order traversal and calls a function on each node
    void inOrderTraversal(std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func) const;

    // getSize returns the number of nodes in the skip list
    int getSize() const;

    // clear clears the skip list
    void clear();



};


// AVL Node class
// @deprecated
class AVLNode {
   public:
    std::vector<uint8_t> key;    // Key
    std::vector<uint8_t> value;  // Value
    AVLNode *left;               // Left child
    AVLNode *right;              // Right child
    int height;                  // Height of the node

    // Constructor
    AVLNode(const std::vector<uint8_t> &k, const std::vector<uint8_t> &v)
        : key(k), value(v), left(nullptr), right(nullptr), height(1) {}
};

// AVL Tree class
// @deprecated
class AVLTree {
   private:
    AVLNode *root;             // Root node
    std::shared_mutex rwlock;  // Read-write lock

    // rightRotate rotates the AVL tree to the right
    AVLNode *rightRotate(AVLNode *y);

    // leftRotate rotates the AVL tree to the left
    AVLNode *leftRotate(AVLNode *x);

    // getBalance gets the balance factor of a node
    int getBalance(AVLNode *node);

    // insert inserts a key-value pair into the AVL tree
    AVLNode *insert(AVLNode *node, const std::vector<uint8_t> &key,
                    const std::vector<uint8_t> &value);

    // printHex prints a vector of unsigned 8-bit integers in hexadecimal format
    static void printHex(const std::vector<uint8_t> &data);

    // deleteNode deletes a node from the AVL tree
    AVLNode *deleteNode(AVLNode *root, const std::vector<uint8_t> &key);

    // deleteKey deletes a key from the AVL tree
    void deleteKey(const std::vector<uint8_t> &key);

    // inOrder prints the key-value pairs in the AVL tree in in-order traversal
    void inOrder(AVLNode *node);

    // minValueNode finds the node with the minimum value in the AVL tree
    AVLNode *minValueNode(AVLNode *node);

    // height gets the height of a node
    static int height(AVLNode *node);

    // inOrderTraversal traverses the AVL tree in in-order traversal and calls a
    // function on each node
    void inOrderTraversal(
        AVLNode *node,
        std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func);

   public:
    // insert inserts a key-value pair into the AVL tree
    void insert(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value);

    // deleteKV deletes a key from the AVL tree
    void deleteKV(const std::vector<uint8_t> &key);

    // inOrder prints the key-value pairs in the AVL tree in in-order traversal
    void inOrder();

    // inOrderTraversal traverses the AVL tree in in-order traversal and calls a
    // function on each node
    void inOrderTraversal(
        std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func);

    // clear clears the AVL tree
    void clear();

    // Get
    // Returns the value for a given key
    std::vector<uint8_t> Get(const std::vector<uint8_t> &key);

    // GetSize returns the number of nodes in the AVL tree
    int GetSize(AVLNode *root);

    // GetRoot returns the root node of the AVL tree
    int GetSize();
};

// Pager class
// Manages reading and writing pages to a file
class Pager {
   private:
    std::string fileName;  // File name
    std::fstream file;     // File stream
   public:
    // Constructor
    Pager(const std::string &filename, std::ios::openmode mode);

    // Destructor
    ~Pager();

    // Write
    // Writes a new page to the file
    // takes a vector of characters as input
    // If the page is full, it writes to a new page and updates the overflow page
    // number in the header returns page number
    int64_t Write(const std::vector<uint8_t> &data);

    // GetFileName
    std::string GetFileName() const;

    // WriteTp
    // Writes to an existing page in the file
    // takes a vector of characters as input
    // returns page number
    static int64_t WriteTo(int64_t page_number, const std::vector<uint8_t> &data);

    // Read
    // Reads a page from the file
    // takes a page number as input
    // returns a vector of characters
    // takes into account overflow pages
    std::vector<uint8_t> Read(int64_t page_number);

    // GetFile
    // Returns the file stream
    std::fstream &GetFile();

    // PagesCount
    // Returns the number of pages in the file
    int64_t PagesCount();

};  // Pager class

// Wal class
class Wal {
   public:
    Wal(Pager *pager) : pager(pager) {}
    std::shared_mutex lock;  // Mutex for write-ahead log

    // WriteOperation writes an operation to the write-ahead log
    bool WriteOperation(const Operation &op);

    // Recover recovers operations from the write-ahead log
    std::vector<Operation> Recover() const;

    // ReadOperations reads operations from the write-ahead log
    std::vector<Operation> ReadOperations();

    mutable std::mutex queueMutex; // Mutex for operation queue
    std::condition_variable queueCondVar; // Condition variable for operation queue
    std::queue<Operation> operationQueue; // Operation queue
    bool stopBackgroundThread = false; // Stop background thread
    std::thread backgroundThread; // Background thread

    // backgroundThreadFunc is the function that runs in the background thread
    // instead of appending on every write, we append to a queue and write in the background to not block the main thread
    void backgroundThreadFunc();

    // Close closes the write-ahead log
    void Close();

   private:
    Pager *pager;                       // Pager instance
    mutable std::shared_mutex walLock;  // Mutex for write-ahead log
};                                      // Wal class

// SSTable class
class SSTable {
   public:
    // Constructor
    SSTable(Pager *pager) : pager(pager) {}

    Pager *pager;                     // Pager instance
    std::vector<uint8_t> minKey;      // Minimum key
    std::vector<uint8_t> maxKey;      // Maximum key
    std::shared_mutex lock;           // Mutex for SSTable
    std::string GetFilePath() const;  // Get file path of SSTable
};                                    // SSTable class

// SSTableIterator class
// Used to iterate over the key-value pairs in an SSTable
class SSTableIterator {
   public:
    // Constructor
    SSTableIterator(Pager *pager) : pager(pager), maxPages(pager->PagesCount()), currentPage(0) {}

    // Ok checks if the iterator is valid
    bool Ok() const { return currentPage < maxPages; }

    // Next returns the next key-value pair in the SSTable
    std::optional<KeyValue> Next() {
        if (!Ok()) {
            return std::nullopt;
        }

        auto data = pager->Read(currentPage++);
        return deserialize(data);
    }

   private:
    Pager *pager;         // Pager instance
    int64_t maxPages;     // Maximum number of pages
    int64_t currentPage;  // Current page
};

// LSMT class
// Log-structured merge-tree
class LSMT {
   public:
    // Constructor
    LSMT(const std::string &string, int memtable_flush_size, int compaction_interval,
         const std::shared_ptr<Pager> &pager, const std::vector<std::shared_ptr<SSTable>> &vector)
        : directory(string),
          memtableFlushSize(memtable_flush_size),
          compactionInterval(compaction_interval) {
        wal = new Wal(new Pager(directory + getPathSeparator() + WAL_EXTENSION,
                                std::ios::in | std::ios::out | std::ios::trunc));
        isFlushing.store(0);
        isCompacting.store(0);

        for (const auto &sstable : vector) {
            sstables.push_back(sstable);
        }

        // Create a new memtable
        memtable = new SkipList(12, 0.25); // 12 is the max level, 0.25 is the probability
    }

    // Destructor
    ~LSMT() {}

    // Put inserts a key-value pair into the LSMT
    bool Put(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value);

    // Delete deletes a key from the LSMT
    bool Delete(const std::vector<uint8_t> &key);

    // Compact compacts the SSTables
    bool Compact();

    void processSSTable(SSTable *sstable, std::unique_ptr<AVLTree> &memtable);

    // NGet returns all key-value pairs not equal to a given key
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> NGet(
        const std::vector<uint8_t> &key) const;

    // LessThan returns all key-value pairs less than a given key
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LessThan(
        const std::vector<uint8_t> &key) const;

    // GreaterThan returns all key-value pairs greater than a given key
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> GreaterThan(
        const std::vector<uint8_t> &key) const;

    // Range returns all key-value pairs between a start and end key
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> Range(
        const std::vector<uint8_t> &start, const std::vector<uint8_t> &end) const;

    // NRange returns all key-value pairs not between a start and end key
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> NRange(
        const std::vector<uint8_t> &start, const std::vector<uint8_t> &end) const;

    // LessThanEq returns all key-value pairs less than or equal to a given key
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LessThanEq(
        const std::vector<uint8_t> &key);

    // GreaterThanEq returns all key-value pairs greater than or equal to a given
    // key
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> GreaterThanEq(
        const std::vector<uint8_t> &key) const;

    // BeginTransaction begins a new transaction
    Transaction *BeginTransaction();

    // CommitTransaction commits a transaction
    bool CommitTransaction(Transaction *tx);

    // RollbackTransaction rolls back a transaction
    void RollbackTransaction(Transaction *tx);

    // RunRecoveredOperations runs recovered operations from the write-ahead log
    bool RunRecoveredOperations(const std::vector<Operation> &operations);

    // Get returns the value for a given key
    std::vector<uint8_t> Get(const std::vector<uint8_t> &key);

    // SplitSSTable splits an SSTable into n SSTables
    std::vector<std::shared_ptr<SSTable>> SplitSSTable(SSTable *sstable, int n) const;

    // Close closes the LSMT
    void Close() {
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
    }

    // New creates a new LSMT instance
    static std::unique_ptr<LSMT> New(const std::string &directory,
                                     std::filesystem::perms directoryPerm, int memtableFlushSize,
                                     int compactionInterval) {
        if (directory.empty()) {
            throw std::invalid_argument("directory cannot be empty");
        }

        if (!std::filesystem::exists(directory)) {
            std::filesystem::create_directory(directory);
            std::filesystem::permissions(directory, directoryPerm);
        }

        std::shared_ptr<Pager> walPager =
            std::make_shared<Pager>(directory + getPathSeparator() + WAL_EXTENSION,
                                    std::ios::in | std::ios::out | std::ios::trunc);

        for (const auto &entry : std::filesystem::directory_iterator(directory)) {
            if (entry.is_regular_file() && entry.path().extension() == SSTABLE_EXTENSION) {
                std::shared_ptr<Pager> sstablePager =
                    std::make_shared<Pager>(entry.path().string(), std::ios::in | std::ios::out);
                std::shared_ptr<SSTable> sstable = std::make_shared<SSTable>(sstablePager.get());
            }
        }

        return std::make_unique<LSMT>(directory, memtableFlushSize, compactionInterval, walPager,
                                      std::vector<std::shared_ptr<SSTable>>());
    }

   private:
    // Active transactions
    // Transactions that are actively being written to and awaiting commit
    std::vector<Transaction *> activeTransactions;   // List of active transactions
    std::shared_mutex activeTransactionsLock;        // Mutex for active transactions
    std::vector<std::shared_ptr<SSTable>> sstables;  // List of SSTables
    std::shared_mutex sstablesLock;                  // Mutex for SSTables
    // We lock wal when writing to it
    std::shared_mutex walLock;  // Mutex for write-ahead log
    Wal *wal;                   // Write-ahead log
    std::string directory;      // Directory for storing data
    int compactionInterval;  // Compaction interval (amount of SSTables to wait before compacting)
                             // we should have at least this many SSTables, if there
                             // are less after compaction, we will not further compact
    std::condition_variable_any cond;        // Condition variable for flushing and compacting
    SkipList *memtable;                       // Skip list memtable
    std::atomic<int32_t> isFlushing;         // Whether the memtable is being flushed
    std::atomic<int32_t> isCompacting;       // Whether the SSTables are being compacted
    int memtableFlushSize;                   // Memtable flush size
    std::vector<std::future<void>> futures;  // List of futures, used for flushing and compacting

    // Create a thread pool, could be configurable in the future
    const size_t compactionThreads = std::thread::hardware_concurrency();  // Number of threads used
                                                                           // for compaction
    // We try to get through the SSTables as fast as possible, so we use a thread
    // pool for compaction Each thread batch processes SSTables, so we can have
    // multiple threads processing SSTables at the same time to speed up
    // compaction

    // flushMemtable flushes the memtable to disk
    bool flushMemtable();
};

}  // namespace TidesDB

#endif  // TIDESDB_LIBRARY_H
