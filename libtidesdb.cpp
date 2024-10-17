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
#include "libtidesdb.h"

#include <iostream>
#include <random>

// The TidesDB namespace
namespace TidesDB {

// ConvertToUint8Vector converts a vector of chars to a vector of uint8_t
std::vector<uint8_t> ConvertToUint8Vector(const std::vector<char> &input) {
    return std::vector<uint8_t>(input.begin(), input.end());
}

// ConvertToCharVector converts a vector of uint8_t to a vector of chars
std::vector<char> ConvertToCharVector(const std::vector<uint8_t> &input) {
    return std::vector<char>(input.begin(), input.end());
}

// serialize serializes the KeyValue struct to a byte vector
std::vector<uint8_t> serialize(const KeyValue &kv) {
    std::vector<uint8_t> buffer(kv.ByteSizeLong());
    kv.SerializeToArray(buffer.data(), buffer.size());
    return buffer;
}

// deserialize deserializes a byte vector to a KeyValue
KeyValue deserialize(const std::vector<uint8_t> &buffer) {
    KeyValue kv;
    kv.ParseFromArray(buffer.data(), buffer.size());
    return kv;
}

// deserializeOperation deserializes a byte vector to an Operation
Operation deserializeOperation(const std::vector<uint8_t> &buffer) {
    Operation op;
    op.ParseFromArray(buffer.data(), buffer.size());
    return op;
}

// serializeOperation serializes the Operation struct to a byte vector
std::vector<uint8_t> serializeOperation(const Operation &op) {
    std::vector<uint8_t> buffer(op.ByteSizeLong());
    op.SerializeToArray(buffer.data(), buffer.size());
    return buffer;
}

// getPathSeparator
// Gets os specific path separator
std::string getPathSeparator() {
    return std::string(1, std::filesystem::path::preferred_separator);
}

// SSTable::GetFilePath
// gets the file path of the SSTable
std::string SSTable::GetFilePath() const { return pager->GetFileName(); }

// Pager::Pager
// Pager Constructor
Pager::Pager(const std::string &filename, std::ios::openmode mode) : fileName(filename) {
    // Check if the file exists
    if (!std::filesystem::exists(filename)) {
        // Create the file
        std::ofstream createFile(filename);
        if (!createFile) {
            throw TidesDBException("Failed to create file: " + filename);
        }

        createFile.close();
    }

    // Open the file with the given filename and mode
    file.open(filename, mode);
    if (!file.is_open()) {
        throw TidesDBException("Failed to open file: " + filename);
    }

    // Initialize pageLocks based on the number of pages
    int64_t pageCount = PagesCount();
    pageLocks.resize(pageCount);
    for (auto &lock : pageLocks) {
        lock = std::make_shared<std::shared_mutex>();
    }
}

// Pager::GetFileName
// returns the filename of the pager
std::string Pager::GetFileName() const { return fileName; }

// Pager::~Pager
// Pager Destructor
Pager::~Pager() {}

// Pager::Write writes data to the paged file, creating overflow pages if necessary
int64_t Pager::Write(const std::vector<uint8_t> &data) {
    std::unique_lock<std::shared_mutex> fileLock(fileMutex);


    if (!file.is_open()) {
        throw TidesDBException("File is not open");
    }

    if (data.empty()) {
        throw TidesDBException("Data is empty");
    }



    file.seekg(0, std::ios::end);
    int64_t page_number = file.tellg() / PAGE_SIZE;

    int64_t data_written = 0;
    int64_t current_page = page_number;

    // Create new page lock
    pageLocks.push_back(std::make_shared<std::shared_mutex>());

    while (data_written < data.size()) {
        file.seekp(current_page * PAGE_SIZE);
        if (file.fail()) {
            throw TidesDBException("Failed to seek to page: " + std::to_string(current_page));
        }

        // Write the header for overflow management
        int64_t overflow_page =
            (data.size() - data_written > PAGE_BODY_SIZE) ? current_page + 1 : -1;
        file.write(reinterpret_cast<const char *>(&overflow_page), sizeof(overflow_page));

        // Pad the header
        std::vector<uint8_t> header_padding(PAGE_HEADER_SIZE - sizeof(int64_t), '\0');
        file.write(reinterpret_cast<const char *>(header_padding.data()), header_padding.size());

        // Write the page body
        int64_t chunk_size = std::min(static_cast<int64_t>(data.size() - data_written),
                                      static_cast<int64_t>(PAGE_BODY_SIZE));
        file.write(reinterpret_cast<const char *>(data.data() + data_written), chunk_size);
        data_written += chunk_size;

        // Pad the body if necessary
        if (chunk_size < PAGE_BODY_SIZE) {
            std::vector<uint8_t> body_padding(PAGE_BODY_SIZE - chunk_size, '\0');
            file.write(reinterpret_cast<const char *>(body_padding.data()), body_padding.size());
        }

        current_page++;

        // Create a new page lock
        pageLocks.push_back(std::make_shared<std::shared_mutex>());
    }

    return page_number;
}

// Pager::WriteTo
// @TODO: Implement the method, probably wont be used
int64_t Pager::WriteTo(int64_t page_number, const std::vector<uint8_t> &data) {
    // Implement the method similarly to Write, but start at the specified
    // page_number
    return 0;
}

// Pager::Read
// reads data from a file starting at a specified page number and handles overflow pages if the data
// spans multiple pages
std::vector<uint8_t> Pager::Read(int64_t page_number) {
    if (!file.is_open()) {
        throw TidesDBException("File is not open");
    }

    if (page_number < 0) {
        throw TidesDBException("Invalid page number");
    }

    file.seekg(page_number * PAGE_SIZE);
    if (file.fail()) {
        throw TidesDBException("Failed to seek to page: " + std::to_string(page_number));
    }

    int64_t overflow_page;
    file.read(reinterpret_cast<char *>(&overflow_page), sizeof(overflow_page));
    if (file.fail()) {
        throw TidesDBException("Failed to read page header for page: " +
                               std::to_string(page_number));
    }

    std::vector<uint8_t> header_padding(PAGE_HEADER_SIZE - sizeof(int64_t), '\0');
    file.read(reinterpret_cast<char *>(header_padding.data()), header_padding.size());

    std::vector<uint8_t> data(PAGE_BODY_SIZE, '\0');
    file.read(reinterpret_cast<char *>(data.data()), PAGE_BODY_SIZE);
    if (file.fail()) {
        throw TidesDBException("Failed to read page body for page: " + std::to_string(page_number));
    }

    int64_t current_page = overflow_page;



    while (current_page != -1) {
        std::shared_lock overflow_lock(*pageLocks[current_page]);

        file.seekg(current_page * PAGE_SIZE);
        if (file.fail()) {
            throw TidesDBException("Failed to seek to overflow page: " +
                                   std::to_string(current_page));
        }

        file.read(reinterpret_cast<char *>(&overflow_page), sizeof(overflow_page));
        if (file.fail()) {
            throw TidesDBException("Failed to read overflow header for page: " +
                                   std::to_string(current_page));
        }

        file.read(reinterpret_cast<char *>(header_padding.data()), header_padding.size());

        std::vector<uint8_t> overflow_data(PAGE_BODY_SIZE, '\0');
        file.read(reinterpret_cast<char *>(overflow_data.data()), PAGE_BODY_SIZE);
        if (file.fail()) {
            throw TidesDBException("Failed to read overflow body for page: " +
                                   std::to_string(current_page));
        }

        data.insert(data.end(), overflow_data.begin(), overflow_data.end());
        current_page = overflow_page;
    }

    // Remove null bytes from the data
    data.erase(std::remove_if(data.begin(), data.end(), [](uint8_t c) { return c == '\0'; }),
               data.end());

    return data;
}


// SkipList::randomLevel
// generates a random level for a new node in the skip list. This level determines the height of the
// node in the skip list, which affects the efficiency of search, insertion, and deletion operations
int SkipList::randomLevel() {
    int lvl = 0;
    while (lvl < maxLevel && dis(gen) < probability * RAND_MAX) {
        lvl++;
    }
    return lvl;
}

// SkipList::insert
// inserts a key-value pair into the SkipList
bool SkipList::insert(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
    std::vector<SkipListNode *> update(maxLevel + 1);
    SkipListNode *x = head.get();

    for (int i = level; i >= 0; i--) {
        SkipListNode *next;
        while ((next = x->forward[i].load(std::memory_order_acquire)) && next->key < key) {
            x = next;
        }
        update[i] = x;
    }

    x = x->forward[0].load(std::memory_order_acquire);

    if (x && x->key == key) {
        x->value = value;  // Overwrite the current value
        return true;
    }

    int newLevel = randomLevel();
    if (newLevel > level) {
        for (int i = level + 1; i <= newLevel; i++) {
            update[i] = head.get();
        }
        level.store(newLevel, std::memory_order_release);
    }

    x = new SkipListNode(key, value, newLevel);
    for (int i = 0; i <= newLevel; i++) {
        SkipListNode *next;
        do {
            next = update[i]->forward[i].load(std::memory_order_relaxed);
            x->forward[i].store(next, std::memory_order_relaxed);
        } while (!update[i]->forward[i].compare_exchange_weak(next, x, std::memory_order_release, std::memory_order_relaxed));
    }

    cachedSize.fetch_add(1, std::memory_order_relaxed);  // Increment size
    return true;
}

// SkipList::deleteKV
// deletes a key-value pair from the SkipList
void SkipList::deleteKV(const std::vector<uint8_t> &key) {
    std::vector<SkipListNode *> update(maxLevel, nullptr);
    SkipListNode *x = head.get();

    // Find the node to delete
    for (int i = level.load(std::memory_order_relaxed); i >= 0; i--) {
        while (x->forward[i].load(std::memory_order_acquire) != nullptr &&
               x->forward[i].load(std::memory_order_acquire)->key < key) {
            x = x->forward[i].load(std::memory_order_acquire);
        }
        update[i] = x;
    }

    x = x->forward[0].load(std::memory_order_acquire);

    // If the key exists, proceed to delete
    if (x != nullptr && x->key == key) {
        for (int i = 0; i <= level.load(std::memory_order_relaxed); i++) {
            if (update[i]->forward[i].load(std::memory_order_acquire) != x) {
                break;
            }
            update[i]->forward[i].store(x->forward[i].load(std::memory_order_relaxed),
                                        std::memory_order_release);
        }

        // Decrease the level of the skip list if needed
        while (level.load(std::memory_order_relaxed) > 0 &&
               head->forward[level.load(std::memory_order_relaxed)].load(
                   std::memory_order_acquire) == nullptr) {
            level.fetch_sub(1, std::memory_order_relaxed);
        }

        cachedSize.fetch_sub(1, std::memory_order_relaxed);
        delete x;  // Free the memory
    }
}

// SkipList::inOrderTraversal
// traverses the skip list in order and applies the provided function func to each key-value pair
void SkipList::inOrderTraversal(
    std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func) const {
    SkipListNode *x = head->forward[0].load(std::memory_order_acquire);
    while (x != nullptr) {
        func(x->key, x->value);
        x = x->forward[0].load(std::memory_order_acquire);
    }
}

// SkipList::get
// get returns the value for a given key in the SkipList
std::vector<uint8_t> SkipList::get(const std::vector<uint8_t> &key) const {
    SkipListNode *x = head.get();
    for (int i = level.load(std::memory_order_relaxed); i >= 0; i--) {
        while (x->forward[i].load(std::memory_order_acquire) != nullptr &&
               x->forward[i].load(std::memory_order_acquire)->key < key) {
            x = x->forward[i].load(std::memory_order_acquire);
        }
    }

    x = x->forward[0].load(std::memory_order_acquire);
    if (x != nullptr && x->key == key) {
        return x->value;
    }
    return {};  // Key not found
}

// SkipList::getSize
// GetSize returns the size of the SkipList
int SkipList::getSize() const { return cachedSize.load(std::memory_order_relaxed); }

// SkipList::clear
// clear clears the SkipList
void SkipList::clear() {
    SkipListNode *x = head->forward[0].load(std::memory_order_acquire);
    while (x != nullptr) {
        SkipListNode *next = x->forward[0].load(std::memory_order_acquire);
        delete x;
        x = next;
    }
    for (int i = 0; i < maxLevel; ++i) {
        head->forward[i].store(nullptr, std::memory_order_release);
    }
    level.store(0, std::memory_order_release);
    cachedSize.store(0, std::memory_order_release);
}

// AVLTree::height
// returns the height of the AVL tree node
// @deprecated
int AVLTree::height(AVLNode *node) {
    if (node == nullptr) return 0;
    return node->height;
}

// AVLTree::GetSize
// returns the size of the AVL tree
// @deprecated
int AVLTree::GetSize(AVLNode *node) {
    if (node == nullptr) {
        return 0;
    }
    return 1 + GetSize(node->left) + GetSize(node->right);
}

// AVLTree::GetSize
// returns the size of the AVL tree
// @deprecated
int AVLTree::GetSize() {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    return GetSize(root);
}

// AVLTree::rightRotate
// performs a right rotation on the AVL tree node
// @deprecated
AVLNode *AVLTree::rightRotate(AVLNode *y) {
    AVLNode *x = y->left;
    AVLNode *T2 = x->right;

    x->right = y;
    y->left = T2;

    y->height = std::max(height(y->left), height(y->right)) + 1;
    x->height = std::max(height(x->left), height(x->right)) + 1;

    return x;
}

// AVLTree::leftRotate
// performs a left rotation on the AVL tree node
// @deprecated
AVLNode *AVLTree::leftRotate(AVLNode *x) {
    AVLNode *y = x->right;
    AVLNode *T2 = y->left;

    y->left = x;
    x->right = T2;

    x->height = std::max(height(x->left), height(x->right)) + 1;
    y->height = std::max(height(y->left), height(y->right)) + 1;

    return y;
}

// AVLTree::getBalance
// returns the balance factor of the AVL tree node
// @deprecated
int AVLTree::getBalance(AVLNode *node) {
    if (node == nullptr) return 0;
    return height(node->left) - height(node->right);
}

// AVLTree::insert
// inserts a key-value pair into the AVL tree
// @deprecated
AVLNode *AVLTree::insert(AVLNode *node, const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) {
    if (node == nullptr) return new AVLNode(key, value);

    if (key < node->key)
        node->left = insert(node->left, key, value);
    else if (key > node->key)
        node->right = insert(node->right, key, value);
    else {
        // Key already exists, update the value
        node->value = value;
        return node;
    }

    node->height = 1 + std::max(height(node->left), height(node->right));

    int balance = getBalance(node);

    if (balance > 1 && key < node->left->key) return rightRotate(node);

    if (balance < -1 && key > node->right->key) return leftRotate(node);

    if (balance > 1 && key > node->left->key) {
        node->left = leftRotate(node->left);
        return rightRotate(node);
    }

    if (balance < -1 && key < node->right->key) {
        node->right = rightRotate(node->right);
        return leftRotate(node);
    }

    return node;
}

// AVLTree::printHex
// prints the hex representation of the data
// @deprecated
void AVLTree::printHex(const std::vector<uint8_t> &data) {
    for (auto byte : data) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

// AVLTree::deleteNode
// deletes a key-value pair from the AVL tree
// @deprecated
AVLNode *AVLTree::deleteNode(AVLNode *root, const std::vector<uint8_t> &key) {
    if (root == nullptr) return root;

    if (key < root->key)
        root->left = deleteNode(root->left, key);
    else if (key > root->key)
        root->right = deleteNode(root->right, key);
    else {
        if ((root->left == nullptr) || (root->right == nullptr)) {
            AVLNode *temp = root->left ? root->left : root->right;

            if (temp == nullptr) {
                temp = root;
                root = nullptr;
            } else
                *root = *temp;

            delete temp;
        } else {
            AVLNode *temp = minValueNode(root->right);

            root->key = temp->key;
            root->value = temp->value;

            root->right = deleteNode(root->right, temp->key);
        }
    }

    if (root == nullptr) return root;

    root->height = 1 + std::max(height(root->left), height(root->right));

    int balance = getBalance(root);

    if (balance > 1 && getBalance(root->left) >= 0) return rightRotate(root);

    if (balance > 1 && getBalance(root->left) < 0) {
        root->left = leftRotate(root->left);
        return rightRotate(root);
    }

    if (balance < -1 && getBalance(root->right) <= 0) return leftRotate(root);

    if (balance < -1 && getBalance(root->right) > 0) {
        root->right = rightRotate(root->right);
        return leftRotate(root);
    }

    return root;
}

// AVLTree::minValueNode
// returns the node with the minimum value in the AVL tree
// @deprecated
AVLNode *AVLTree::minValueNode(AVLNode *node) {
    AVLNode *current = node;
    while (current->left != nullptr) current = current->left;
    return current;
}

// AVLTree::insert
// inserts a key-value pair into the AVL tree
// will update the value if the key already exists
// @deprecated
void AVLTree::insert(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    root = insert(root, key, value);
}

// AVLTree::deleteKV
// deletes a key-value pair from the AVL tree
// @deprecated
void AVLTree::deleteKV(const std::vector<uint8_t> &key) { deleteKey(key); }

// AVLTree::inOrder
// prints the key-value pairs in the AVL tree in order
// @deprecated
void AVLTree::inOrder(AVLNode *node) {
    if (node != nullptr) {
        inOrder(node->left);
        printHex(node->key);
        inOrder(node->right);
    }
}

// AVLTree::inOrder
// prints the key-value pairs in the AVL tree in order
// @deprecated
void AVLTree::inOrder() {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    inOrder(root);
}

// AVLTree::inOrderTraversal
// traverses the AVL tree in order and calls the function on
// each node
// @deprecated
void AVLTree::inOrderTraversal(
    AVLNode *node,
    std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func) {
    if (node != nullptr) {
        inOrderTraversal(node->left, func);
        func(node->key, node->value);
        inOrderTraversal(node->right, func);
    }
}

// AVLTree::inOrderTraversal
// traverses the AVL tree in order and calls the function on
// each node
// @deprecated
void AVLTree::inOrderTraversal(
    std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func) {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    inOrderTraversal(root, func);
}

// AVLTree::deleteKey
// deletes a key from the AVL tree
// @deprecated
void AVLTree::deleteKey(const std::vector<uint8_t> &key) {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    root = deleteNode(root, key);
}

// AVLTree::Get
// returns the value for a given key
// @deprecated
std::vector<uint8_t> AVLTree::Get(const std::vector<uint8_t> &key) {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    AVLNode *current = root;

    while (current != nullptr) {
        if (key < current->key) {
            current = current->left;
        } else if (key > current->key) {
            current = current->right;
        } else {
            // check if tombstone
            if (current->value ==
                std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE))) {
                // Handle tombstone
            }

            return current->value;  // Key found, return the value
        }
    }

    return {};  // Key not found, return an empty vector
}

// Wal::Close
// responsible for safely stopping the background thread that processes the write-ahead log (WAL).
// It sets a flag to stop the thread, notifies the condition variable to wake up the thread
// if it is waiting, and then joins the thread to ensure it has finished executing.
void Wal::Close() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        stopBackgroundThread = true;
    }
    queueCondVar.notify_one();
    if (backgroundThread.joinable()) {
        backgroundThread.join();
    }

    // Close the pager
    pager->Close();
}

// Wal::WriteOperation
// tesponsible for writing an operation to the write-ahead log (WAL).
// It ensures thread safety by using a mutex to lock the operation queue,
// pushes the operation onto the queue, and then notifies a condition variable to
// signal that a new operation is available
bool Wal::WriteOperation(const Operation &op) {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        operationQueue.push(op);
    }
    queueCondVar.notify_one();
    return true;
}

// Wal::Recover
// reads and processes operations from the Write-Ahead Log (WAL) pages one by one. It locks the WAL
// for reading, iterates through each page, deserializes the data into an Operation object, and
// immediately processes the operation by inserting or deleting key-value pairs in the LSMT's
// memtable. This approach avoids storing all operations in memory at once, optimizing memory usage.
bool TidesDB::Wal::Recover(LSMT &lsmt) const {
    // Lock the WAL for reading
    std::unique_lock<std::shared_mutex> lock(walLock);

    // Get the number of pages in the WAL
    int64_t pageCount = pager->PagesCount();

    // Iterate through each page in the WAL
    for (int64_t i = 0; i < pageCount; ++i) {
        // Read the data from the current page
        std::vector<uint8_t> data = pager->Read(i);

        // Deserialize the data into an Operation object
        Operation op = deserializeOperation(data);

        // Process the operation immediately
        switch (static_cast<int>(op.type())) {
            case static_cast<int>(TidesDB::OperationType::OpPut): {
                std::vector<uint8_t> key(op.key().begin(), op.key().end());
                std::vector<uint8_t> value(op.value().begin(), op.value().end());
                lsmt.InsertIntoMemtable(key, value);
                break;
            }
            case static_cast<int>(TidesDB::OperationType::OpDelete): {
                std::vector<uint8_t> key(op.key().begin(), op.key().end());
                lsmt.DeleteFromMemtable(key);
                break;
            }
            default:
                std::cerr << "Unknown operation type: " << static_cast<int>(op.type()) << std::endl;
                return false;
        }
    }

    return true;
}

// LSMT::flushMemtable
// responsible for flushing the current memtable to disk. It creates a new memtable,
// transfers the data from the current memtable to the new one, and then adds the new memtable
// to the flush queue. Finally, it notifies the flush thread to process the queue
bool LSMT::flushMemtable() {
    try {
        // Create a new memtable
        auto newMemtable = std::make_unique<SkipList>(12, 0.25);

        // Iterate over the current memtable and insert its elements into the new memtable
        memtable->inOrderTraversal(
            [&newMemtable](const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
                newMemtable->insert(key, value);
            });

        // Clear the current memtable
        memtable->clear();

        // Add the new memtable to the flush queue
        {
            std::lock_guard<std::mutex> lock(flushQueueMutex);
            flushQueue.push(std::move(newMemtable));
            flushQueueCondVar.notify_one();  // Notify the flush thread
        }

        return true;
    } catch (const std::exception &e) {
        std::cerr << "Error in flushMemtable: " << e.what() << std::endl;
        return false;
    }
}

// LSMT::flushThreadFunc
// responsible for flushing the memtable to disk. It continuously waits for new memtables
// to be added to the flush queue, processes them, and writes their key-value pairs to SSTables.
// If the number of SSTables exceeds the compaction interval, it triggers a background compaction
void LSMT::flushThreadFunc() {
    while (stopBackgroundThreads.load() == 0) {
        std::unique_ptr<SkipList> newMemtable;

        // Wait for a new memtable to be added to the queue
        {
            std::unique_lock<std::mutex> lock(flushQueueMutex);
            flushQueueCondVar.wait(lock, [this] { return !flushQueue.empty(); });

            newMemtable = std::move(flushQueue.front());
            flushQueue.pop();

            // Check for the sentinel value
            if (newMemtable == nullptr) {
                break;  // Exit the loop if the sentinel value is encountered
            }
        }

        std::vector<KeyValue> kvPairs;  // Key-value pairs to be written to the SSTable

        // Populate kvPairs with key-value pairs from the new memtable
        newMemtable->inOrderTraversal(
            [&kvPairs](const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
                KeyValue kv;
                kv.set_key(key.data(), key.size());
                kv.set_value(value.data(), value.size());
                kvPairs.push_back(kv);
            });

        // Increment the counter before using it
        int sstableCounter;
        {
            std::shared_lock<std::shared_mutex> lock(sstablesLock);
            sstableCounter = sstables.size() + 1;
        }

        // Write the key-value pairs to the SSTable
        std::string sstablePath = directory + getPathSeparator() + "sstable_" +
                                  std::to_string(sstableCounter) + SSTABLE_EXTENSION;

        // Create a new SSTable with a new Pager
        auto sstable = std::make_shared<SSTable>(
            new Pager(sstablePath, std::ios::in | std::ios::out | std::ios::trunc));

        // We must set minKey and maxKey
        if (!kvPairs.empty()) {
            sstable->minKey =
                std::vector<uint8_t>(kvPairs.front().key().begin(), kvPairs.front().key().end());
            sstable->maxKey =
                std::vector<uint8_t>(kvPairs.back().key().begin(), kvPairs.back().key().end());
        }

        // Serialize the key-value pairs
        for (const auto &kv : kvPairs) {
            sstable->pager->Write(serialize(kv));
        }

        // Add the new SSTable to the list of SSTables
        {
            std::unique_lock<std::shared_mutex> lock(sstablesLock);
            sstables.push_back(sstable);
        }

        // Check if we need to compact
        if (sstableCounter >= compactionInterval) {
            Compact();
        }
    }
}

// LSMT::Delete
// responsible for deleting a key from the LSMT structure.
// It ensures thread safety by using locks and condition variables, writes the delete operation to
// the Write-Ahead Log (WAL), and inserts a tombstone value into the memtable. If the memtable
// exceeds a certain size, it triggers a background flush to disk
bool LSMT::Delete(const std::vector<uint8_t> &key) {
    // Check if we are flushing or compacting
    {
        std::unique_lock lock(sstablesLock);
        cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    }  // Automatically unlocks when leaving the scope

    // Lock and write to the write-ahead log
    {
        std::unique_lock lock(walLock);
        Operation op;
        op.set_type(static_cast<::OperationType>(OperationType::OpDelete));
        op.set_key(key.data(), key.size());

        if (!wal->WriteOperation(op)) {
            return false;  // Return false if writing to the WAL fails
        }
    }  // Automatically unlocks when leaving the scope

    {
        memtable->insert(
            key, std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE)));
    }  // Automatically unlocks when leaving the scope

    // If the memtable size exceeds the flush size, flush the memtable to disk
    if (memtable->getSize() > memtableFlushSize) {
        flushMemtable();
    }

    return true;
}

// LSMT::Put
//  inserts a key-value pair into the LSMT structure.
//  function ensures thread safety by using locks and condition variables, writes the operation to
//  the Write-Ahead Log (WAL), and inserts the key-value pair into the memtable. If the memtable
//  exceeds a certain size, it triggers a background flush to disk.
bool LSMT::Put(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
    // Check if we are flushing or compacting
    {
        std::unique_lock lock(sstablesLock);
        cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    }  // Automatically unlocks when leaving the scope

    // Check for null pointers
    if (!wal || !memtable) {
        throw std::runtime_error("WAL or memtable is not initialized");
    }

    // Lock and write to the write-ahead log
    {
        std::unique_lock lock(walLock);
        Operation op;
        op.set_key(key.data(), key.size());
        op.set_value(value.data(), value.size());
        op.set_type(static_cast<::OperationType>(OperationType::OpPut));

        if (!wal->WriteOperation(op)) {
            return false;  // Return false if writing to the WAL fails
        }
    }  // Automatically unlocks when leaving the scope

    // Check if value is tombstone
    if (value == std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE))) {
        throw std::invalid_argument("value cannot be a tombstone");
    }

    // Insert the key-value pair into the memtable
    memtable->insert(key, value);

    // If the memtable size exceeds the flush size, flush the memtable to disk
    if (memtable->getSize() > memtableFlushSize) {
        if (!flushMemtable()) {
            return false;
        }
    }

    // Notify the compaction thread
    cond.notify_one();

    return true;
}

// LSMT::Get
// retrieve a value for a given key from the LSMT.
// It first checks the memtable and then searches the SSTables if the key is not found in the
// memtable.
std::vector<uint8_t> LSMT::Get(const std::vector<uint8_t> &key) {
    // Check if we are flushing or compacting
    {
        std::unique_lock lock(sstablesLock);
        cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    }  // Automatically unlocks when leaving the scope

    // Check the memtable for the key
    std::vector<uint8_t> value;
    { value = memtable->get(key); }  // Automatically unlocks when leaving the scope

    // If value is found and it's not a tombstone, return it
    if (!value.empty() &&
        value != std::vector<uint8_t>(std::vector<uint8_t>(
                     TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE)))) {
        return value;
                     }

    // Search the SSTables for the key, starting from the latest
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        auto sstable = *it;
        std::shared_lock<std::shared_mutex> sstableLock(sstable->lock);

        // If the key is not within the range of this SSTable, skip it
        if (key < sstable->minKey || key > sstable->maxKey) {
            continue;
        }

        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                break;
            }

            // Check for tombstones
            if (std::string(kv->value().begin(), kv->value().end()) == TOMBSTONE_VALUE) {
                return {};
            }

            // Check for the key
            if (key ==
                ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()))) {
                return ConvertToUint8Vector(
                    std::vector<char>(kv->value().begin(), kv->value().end()));
                }
        }
    }

    return {};  // Key not found, return an empty vector
}

// Pager::GetFile
// gets pager file
std::fstream &Pager::GetFile() { return file; }

// TidesDB::Wal::backgroundThreadFunc
// is a background thread function for the Write-Ahead Log (WAL).
// It continuously processes operations from a queue and writes them to the WAL file
void TidesDB::Wal::backgroundThreadFunc() {
    while (true) {
        std::unique_lock<std::mutex> lock(queueMutex);
        queueCondVar.wait(lock, [this] { return !operationQueue.empty() || stopBackgroundThread; });

        if (stopBackgroundThread && operationQueue.empty()) {
            break;
        }

        Operation op = operationQueue.front();
        operationQueue.pop();
        lock.unlock();

        // Serialize and write the operation to the WAL
        std::vector<uint8_t> serializedOp = serializeOperation(op);
        pager->Write(serializedOp);
    }
}

// Pager::PagesCount
// returns the number of pages in the SSTable
int64_t Pager::PagesCount() {
    if (!file.is_open()) {
        return 0;
    }

    file.seekg(0, std::ios::end);
    int64_t fileSize = file.tellg();
    return fileSize / PAGE_SIZE;
}

// AVLTree::clear
// clears the AVL tree
void AVLTree::clear() {
    std::unique_lock<std::shared_mutex> lock(rwlock);

    // initialze new AVL tree
    root = nullptr;
}

// LSMT::Compact
// starts a background thread to perform compaction of SSTables in a non-blocking manner. It pairs
// SSTables, merges them, and writes the merged data to new SSTables. The old SSTables are then
// deleted.
bool LSMT::Compact() {
    try {
        std::vector<std::future<void>> futures;
        std::vector<std::pair<std::shared_ptr<SSTable>, std::shared_ptr<SSTable>>> sstablePairs;

        {
            std::shared_lock<std::shared_mutex> lock(sstablesLock);
            for (size_t i = 0; i < sstables.size(); i += 2) {
                if (i + 1 < sstables.size()) {
                    sstablePairs.emplace_back(sstables[i], sstables[i + 1]);
                }
            }
        }

        for (const auto &pair : sstablePairs) {
            futures.push_back(std::async(std::launch::async, [this, pair] {
                try {
                    auto sstable1 = pair.first;
                    auto sstable2 = pair.second;

                    auto it1 = std::make_unique<SSTableIterator>(sstable1->pager);
                    auto it2 = std::make_unique<SSTableIterator>(sstable2->pager);
                    auto newMemtable = std::make_unique<AVLTree>();

                    std::optional<std::vector<uint8_t>> currentKey1, currentValue1;
                    std::optional<std::vector<uint8_t>> currentKey2, currentValue2;

                    std::unique_lock<std::shared_mutex> sstableLock1(sstable1->lock);
                    std::unique_lock<std::shared_mutex> sstableLock2(sstable2->lock);


                    if (!it1 || !it2) {
                        return;
                    }

                    if (it1->Ok()) {
                        auto kv = it1->Next();
                        if (!kv) {
                            return;
                        }

                        currentKey1 = std::vector<uint8_t>(kv->key().begin(), kv->key().end());
                        currentValue1 = std::vector<uint8_t>(kv->value().begin(), kv->value().end());
                    }
                    if (it2->Ok()) {
                        auto kv = it2->Next();
                        if (!kv) {
                                                return;
                                            }


                        currentKey2 = std::vector<uint8_t>(kv->key().begin(), kv->key().end());
                        currentValue2 = std::vector<uint8_t>(kv->value().begin(), kv->value().end());
                    }

                    while (currentKey1.has_value() || currentKey2.has_value()) {
                        if (!currentKey2.has_value() || (currentKey1.has_value() && currentKey1 < currentKey2)) {
                            newMemtable->insert(currentKey1.value(), currentValue1.value());
                            if (it1->Ok()) {
                                auto kv = it1->Next();
                                currentKey1 = std::vector<uint8_t>(kv->key().begin(), kv->key().end());
                                currentValue1 = std::vector<uint8_t>(kv->value().begin(), kv->value().end());
                            } else {
                                currentKey1.reset();
                                currentValue1.reset();
                            }
                        } else {
                            newMemtable->insert(currentKey2.value(), currentValue2.value());
                            if (it2->Ok()) {
                                auto kv = it2->Next();
                                currentKey2 = std::vector<uint8_t>(kv->key().begin(), kv->key().end());
                                currentValue2 = std::vector<uint8_t>(kv->value().begin(), kv->value().end());
                            } else {
                                currentKey2.reset();
                                currentValue2.reset();
                            }
                        }
                    }

                    if (newMemtable->GetSize() > 0) {
                        std::string newSSTablePath = directory + getPathSeparator() + "sstable_compacted_" +
                                                     std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) +
                                                     SSTABLE_EXTENSION;
                        auto newSSTable = std::make_shared<SSTable>(
                            new Pager(newSSTablePath, std::ios::in | std::ios::out | std::ios::trunc));

                        newMemtable->inOrderTraversal([&newSSTable](const std::vector<uint8_t> &key,
                                                                    const std::vector<uint8_t> &value) {
                            KeyValue kv;
                            kv.set_key(key.data(), key.size());
                            kv.set_value(value.data(), value.size());
                            std::vector<uint8_t> serialized = serialize(kv);
                            newSSTable->pager->Write(serialized);
                        });

                        {
                            std::unique_lock<std::shared_mutex> sstablesLockGuard(sstablesLock);
                            sstables.push_back(newSSTable);
                        }
                    }

                    std::filesystem::remove(sstable1->pager->GetFileName());
                    std::filesystem::remove(sstable2->pager->GetFileName());

                    {
                        std::unique_lock<std::shared_mutex> sstablesLockGuard(sstablesLock);
                        sstables.erase(std::remove(sstables.begin(), sstables.end(), sstable1), sstables.end());
                        sstables.erase(std::remove(sstables.begin(), sstables.end(), sstable2), sstables.end());
                    }
                } catch (const std::exception &e) {
                    std::cerr << "Error during compaction: " << e.what() << std::endl;
                }
            }));
        }

        for (auto &future : futures) {
            future.get();
        }
    } catch (const std::exception &e) {
        std::cerr << "Error in Compact function: " << e.what() << std::endl;
        return false;
    }

    return true;
}

// LSMT::BeginTransaction
// begins a new transaction
Transaction *LSMT::BeginTransaction() {
    auto tx = new Transaction();
    {
        std::lock_guard<std::shared_mutex> lock(activeTransactionsLock);
        activeTransactions.push_back(tx);
    }
    return tx;
}

// LSMT::AddPut
// adds a put operation to the transaction.
void LSMT::AddPut(Transaction *tx, const std::vector<uint8_t> &key,
                  const std::vector<uint8_t> &value) {
    auto rollback =
        std::make_unique<Rollback>(OperationType::OpDelete, key, std::vector<uint8_t>{});

    Operation op;
    op.set_type(static_cast<::OperationType>(OperationType::OpPut));
    op.set_key(key.data(), key.size());
    op.set_value(value.data(), value.size());

    {
        std::lock_guard<std::mutex> lock(tx->operationsMutex);
        tx->operations.push_back(TransactionOperation{op, rollback.release()});
    }
}

// LSMT::AddDelete
// adds a delete operation to the transaction.
void LSMT::AddDelete(Transaction *tx, const std::vector<uint8_t> &key,
                     const std::vector<uint8_t> &value) {
    auto rollback = std::make_unique<Rollback>(OperationType::OpPut, key, value);

    Operation op;
    op.set_type(static_cast<::OperationType>(OperationType::OpDelete));
    op.set_key(key.data(), key.size());

    {
        std::lock_guard<std::mutex> lock(tx->operationsMutex);
        tx->operations.push_back(TransactionOperation{op, rollback.release()});
    }
}

// LSMT::CommitTransaction
// commits a transaction.
// On error we rollback the transaction
bool LSMT::CommitTransaction(Transaction *tx) {
    // Check if the transaction has already been aborted
    if (tx->aborted) {
        throw std::runtime_error("transaction has been aborted");
    }

    // Check if the transaction is already committed
    {
        std::shared_lock<std::shared_mutex> lock(activeTransactionsLock);
        if (std::find(activeTransactions.begin(), activeTransactions.end(), tx) ==
            activeTransactions.end()) {
            throw std::runtime_error("transaction has already been committed or does not exist");
        }
    }

    // Process each operation in the transaction
    for (const auto &txOp : tx->operations) {
        const auto &op = txOp.op;
        switch (op.type()) {
            case static_cast<int>(OperationType::OpPut):
                if (!Put(ConvertToUint8Vector(std::vector<char>(op.key().begin(), op.key().end())),
                         ConvertToUint8Vector(
                             std::vector<char>(op.value().begin(), op.value().end())))) {
                    RollbackTransaction(tx);
                    return false;
                }
                break;
            case static_cast<int>(OperationType::OpDelete):
                if (!Delete(ConvertToUint8Vector(
                        std::vector<char>(op.key().begin(), op.key().end())))) {
                    RollbackTransaction(tx);
                    return false;
                }
                break;
        }
    }

    // Remove the transaction from the active list
    {
        std::lock_guard<std::shared_mutex> lock(activeTransactionsLock);
        auto it = std::find(activeTransactions.begin(), activeTransactions.end(), tx);
        if (it != activeTransactions.end()) {
            activeTransactions.erase(it);
        }
    }

    return true;
}

// LSMT::RollbackTransaction
// rolls back a transaction, checks if the transaction has already been committed
void LSMT::RollbackTransaction(Transaction *tx) {
    // Check if the transaction has already been committed
    if (std::find(activeTransactions.begin(), activeTransactions.end(), tx) ==
        activeTransactions.end()) {
        std::cerr << "Transaction has already been committed or does not exist" << std::endl;
        return;
    }

    tx->aborted = true;
    for (auto it = tx->operations.rbegin(); it != tx->operations.rend(); ++it) {
        const auto &rollback = it->rollback;
        switch (rollback->type) {
            case OperationType::OpPut:
                Put(rollback->key, rollback->value);
                break;
            case OperationType::OpDelete:
                Delete(rollback->key);
                break;
        }
    }

    // Remove the transaction from the active list.
    auto it = std::find(activeTransactions.begin(), activeTransactions.end(), tx);
    if (it != activeTransactions.end()) {
        activeTransactions.erase(it);
    }
}

// LSMT::NGet
// gets all key-value pairs except the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::NGet(
    const std::vector<uint8_t> &key) const {
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> kvMap;

    // Traverse the memtable and collect key-value pairs not equal to the key
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k != key) {
            kvMap.insert({k, v});  // Use insert to avoid overwriting
        }
    });

    // Traverse the SSTables and collect key-value pairs not equal to the key
    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv) {
                auto kvKey =
                    ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()));
                if (kvKey != key) {
                    kvMap.insert(
                        {kvKey, ConvertToUint8Vector(std::vector<char>(
                                    kv->value().begin(), kv->value().end()))});  // Use insert
                }
            }
        }
    }

    // Convert the map to a vector of pairs
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    for (const auto &kv : kvMap) {
        result.emplace_back(kv);
    }

    return result;
}

// LSMT::LessThanEq
// gets all key-value pairs less than or equal to the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::LessThanEq(
    const std::vector<uint8_t> &key) const {
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> kvMap;

    // Traverse the memtable and collect key-value pairs less than or equal to the key
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k <= key && kvMap.find(k) == kvMap.end()) {
            kvMap[k] = v;
        }
    });

    // Traverse the SSTables and collect key-value pairs less than or equal to the key
    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && std::string(key.begin(), key.end()) >= kv->key() &&
                kvMap.find(ConvertToUint8Vector(
                    std::vector<char>(kv->key().begin(), kv->key().end()))) == kvMap.end()) {
                kvMap[ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()))] =
                    ConvertToUint8Vector(std::vector<char>(kv->value().begin(), kv->value().end()));
            }
        }
    }

    // Convert the map to a vector of pairs
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    for (const auto &kv : kvMap) {
        result.emplace_back(kv);
    }

    return result;
}

// LSMT::GreaterThanEq
// gets all key-value pairs greater than or equal to the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::GreaterThanEq(
    const std::vector<uint8_t> &key) const {
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> kvMap;

    // Traverse the memtable and collect key-value pairs greater than or equal to the key
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k >= key) {
            kvMap[k] = v;
        }
    });

    // Traverse the SSTables and collect key-value pairs greater than or equal to the key
    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && std::string(key.begin(), key.end()) <= kv->key()) {
                kvMap[ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()))] =
                    ConvertToUint8Vector(std::vector<char>(kv->value().begin(), kv->value().end()));
            }
        }
    }

    // Convert the map to a vector of pairs
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    for (const auto &kv : kvMap) {
        result.emplace_back(kv);
    }

    return result;
}

// LSMT::LessThan
// gets all key-value pairs less than the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::LessThan(
    const std::vector<uint8_t> &key) const {
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> kvMap;

    // Traverse the memtable and collect key-value pairs less than the key
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k < key) {
            kvMap[k] = v;
        }
    });

    // Traverse the SSTables and collect key-value pairs less than the key
    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && std::string(key.begin(), key.end()) < kv->key()) {
                kvMap[ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()))] =
                    ConvertToUint8Vector(std::vector<char>(kv->value().begin(), kv->value().end()));
            }
        }
    }

    // Convert the map to a vector of pairs
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    for (const auto &kv : kvMap) {
        result.emplace_back(kv);
    }

    return result;
}

// LSMT::GreaterThan
// gets all key-value pairs greater than the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::GreaterThan(
    const std::vector<uint8_t> &key) const {
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> kvMap;

    // Traverse the memtable and collect key-value pairs greater than the key
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k > key) {
            kvMap.insert({k, v});  // Use insert to avoid overwriting
        }
    });

    // Traverse the SSTables and collect key-value pairs greater than the key
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        SSTableIterator sstableIt((*it)->pager);
        while (sstableIt.Ok()) {
            auto kv = sstableIt.Next();
            if (kv) {
                std::vector<uint8_t> kv_key(kv->key().begin(), kv->key().end());
                std::vector<uint8_t> kv_value(kv->value().begin(), kv->value().end());
                if (kv_key > key) {
                    kvMap.insert({kv_key, kv_value});  // Use insert to avoid overwriting
                }
            }
        }
    }

    // Convert the map to a vector of pairs
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    for (const auto &kv : kvMap) {
        result.emplace_back(kv);
    }

    return result;
}

// LSMT::Range
// gets all key-value pairs in the range of start and end
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::Range(
    const std::vector<uint8_t> &start, const std::vector<uint8_t> &end) const {
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> kvMap;

    // Traverse the memtable and collect key-value pairs in the range
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k >= start && k <= end) {
            kvMap.insert({k, v});  // Use insert to avoid overwriting
        }
    });

    // Traverse the SSTables and collect key-value pairs in the range
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        SSTableIterator sstableIt((*it)->pager);
        while (sstableIt.Ok()) {
            auto kv = sstableIt.Next();
            if (kv) {
                std::string kv_key_str = kv->key();
                std::vector<char> kv_key_chars(kv_key_str.begin(), kv_key_str.end());
                std::vector<uint8_t> kv_key = ConvertToUint8Vector(
                    std::vector<char>(kv_key_chars.begin(), kv_key_chars.end()));

                if (kv_key >= start && kv_key <= end) {
                    kvMap.insert(
                        {kv_key, ConvertToUint8Vector(std::vector<char>(
                                     kv->value().begin(), kv->value().end()))});  // Use insert
                }
            }
        }
    }

    // Convert the map to a vector of pairs
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    for (const auto &kv : kvMap) {
        result.emplace_back(kv);
    }

    return result;
}

// LSMT::NRange
// gets all key-value pairs not in the range of start and end
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::NRange(
    const std::vector<uint8_t> &start, const std::vector<uint8_t> &end) const {
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> kvMap;

    // Traverse the memtable and collect key-value pairs not in the range
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k < start || k > end) {
            kvMap.insert({k, v});  // Use insert to avoid overwriting
        }
    });

    // Traverse the SSTables and collect key-value pairs not in the range
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        SSTableIterator sstableIt((*it)->pager);
        while (sstableIt.Ok()) {
            auto kv = sstableIt.Next();
            if (kv) {
                std::string kv_key_str = kv->key();
                std::vector<char> kv_key_chars(kv_key_str.begin(), kv_key_str.end());
                std::vector<uint8_t> kv_key = ConvertToUint8Vector(
                    std::vector<char>(kv_key_chars.begin(), kv_key_chars.end()));

                if (kv_key < start || kv_key > end) {
                    kvMap.insert(
                        {kv_key, ConvertToUint8Vector(std::vector<char>(
                                     kv->value().begin(), kv->value().end()))});  // Use insert
                }
            }
        }
    }

    // Convert the map to a vector of pairs
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    for (const auto &kv : kvMap) {
        result.emplace_back(kv);
    }

    return result;
}

}  // namespace TidesDB