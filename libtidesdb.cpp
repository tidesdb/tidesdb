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

// deserialize deserializes a byte vector to a KeyValue struct
KeyValue deserialize(const std::vector<uint8_t> &buffer) {
    KeyValue kv;
    kv.ParseFromArray(buffer.data(), buffer.size());
    return kv;
}

// deserializeOperation deserializes a byte vector to an Operation struct
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

// Gets os specific path separator
std::string getPathSeparator() {
    return std::string(1, std::filesystem::path::preferred_separator);
}

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
}

// GetFileName returns the filename of the pager
std::string Pager::GetFileName() const { return fileName; }

// Pager Destructor
Pager::~Pager() {
    if (file.is_open()) {
        file.close();
    }
}

// Write writes the data to the pager
int64_t Pager::Write(const std::vector<uint8_t> &data) {
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
    }

    return page_number;
}

// @TODO: Implement the method, probably wont be used
int64_t Pager::WriteTo(int64_t page_number, const std::vector<uint8_t> &data) {
    // Implement the method similarly to Write, but start at the specified
    // page_number
    return 0;
}

// Read reads the data from the pager
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

// randomLevel returns a random level for the SkipList
int SkipList::randomLevel() const {
    int lvl = 1;
    while ((static_cast<float>(rand()) / RAND_MAX) < probability && lvl < maxLevel) {
        lvl++;
    }
    return lvl;
}

// insert inserts a key-value pair into the SkipList
void SkipList::insert(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
    std::vector<SkipListNode*> update(maxLevel, nullptr);
    auto x = head.get();

    for (int i = level.load(std::memory_order_relaxed); i >= 0; i--) {
        while (x->forward[i].load(std::memory_order_acquire) != nullptr &&
               x->forward[i].load(std::memory_order_acquire)->key < key) {
            x = x->forward[i].load(std::memory_order_acquire);
               }
        update[i] = x;
    }

    x = x->forward[0].load(std::memory_order_acquire);

    if (x != nullptr && x->key == key) {
        // Key exists, update the value
        x->value = value;
    } else {
        // Key does not exist, insert a new node
        int newLevel = randomLevel();
        if (newLevel > level.load(std::memory_order_relaxed)) {
            for (int i = level.load(std::memory_order_relaxed) + 1; i < newLevel; i++) {
                update[i] = head.get();
            }
            level.store(newLevel, std::memory_order_release);
        }

        x = new SkipListNode(key, value, newLevel);
        for (int i = 0; i < newLevel; i++) {
            x->forward[i].store(update[i]->forward[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
            update[i]->forward[i].store(x, std::memory_order_release);
        }
        cachedSize.fetch_add(1, std::memory_order_relaxed);  // Increment cachedSize
    }
}


// deleteKV deletes a key-value pair from the SkipList
void SkipList::deleteKV(const std::vector<uint8_t> &key) {
    std::vector<SkipListNode*> update(maxLevel, nullptr);
    auto x = head.get();

    for (int i = level.load(std::memory_order_relaxed); i >= 0; i--) {
        while (x->forward[i].load(std::memory_order_acquire) != nullptr &&
               x->forward[i].load(std::memory_order_acquire)->key < key) {
            x = x->forward[i].load(std::memory_order_acquire);
               }
        update[i] = x;
    }

    x = x->forward[0].load(std::memory_order_acquire);

    if (x != nullptr && x->key == key) {
        for (int i = 0; i <= level.load(std::memory_order_relaxed); i++) {
            if (update[i]->forward[i].load(std::memory_order_acquire) != x) {
                break;
            }
            update[i]->forward[i].store(x->forward[i].load(std::memory_order_relaxed), std::memory_order_release);
        }

        while (level.load(std::memory_order_relaxed) > 0 &&
               head->forward[level.load(std::memory_order_relaxed)].load(std::memory_order_acquire) == nullptr) {
            level.fetch_sub(1, std::memory_order_relaxed);
               }

        cachedSize.fetch_sub(1, std::memory_order_relaxed);  // Decrement cachedSize
        delete x;  // Free the memory of the deleted node
    }
}

// inOrderTraversal traverses the SkipList in order and calls the function on each node
void SkipList::inOrderTraversal(std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func) const {
    auto x = head.get();
    while (x->forward[0].load(std::memory_order_acquire) != nullptr) {
        x = x->forward[0].load(std::memory_order_acquire);
        func(x->key, x->value);
    }
}

// get returns the value for a given key in the SkipList
std::vector<uint8_t> SkipList::get(const std::vector<uint8_t> &key) {
    auto x = head.get();
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

    return {};
}

// GetSize returns the size of the SkipList
int SkipList::getSize() const { return cachedSize.load(std::memory_order_relaxed); }

// clear clears the SkipList
void SkipList::clear() {
    auto x = head.get();
    while (x->forward[0].load(std::memory_order_acquire) != nullptr) {
        auto next = x->forward[0].load(std::memory_order_acquire);
        delete x;
        x = next;
    }
    delete x;
    level.store(0, std::memory_order_relaxed);
    cachedSize.store(0, std::memory_order_relaxed);
}

// height returns the height of the AVL tree node
// @deprecated
int AVLTree::height(AVLNode *node) {
    if (node == nullptr) return 0;
    return node->height;
}

// GetSize returns the size of the AVL tree
// @deprecated
int AVLTree::GetSize(AVLNode *node) {
    if (node == nullptr) {
        return 0;
    }
    return 1 + GetSize(node->left) + GetSize(node->right);
}

// GetSize returns the size of the AVL tree
int AVLTree::GetSize() {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    return GetSize(root);
}

// rightRotate performs a right rotation on the AVL tree node
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

// leftRotate performs a left rotation on the AVL tree node
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

// getBalance returns the balance factor of the AVL tree node
// @deprecated
int AVLTree::getBalance(AVLNode *node) {
    if (node == nullptr) return 0;
    return height(node->left) - height(node->right);
}

// insert inserts a key-value pair into the AVL tree
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

// printHex prints the hex representation of the data
// @deprecated
void AVLTree::printHex(const std::vector<uint8_t> &data) {
    for (auto byte : data) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

// deleteNode deletes a key-value pair from the AVL tree
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

// minValueNode returns the node with the minimum value in the AVL tree
// @deprecated
AVLNode *AVLTree::minValueNode(AVLNode *node) {
    AVLNode *current = node;
    while (current->left != nullptr) current = current->left;
    return current;
}

// insert inserts a key-value pair into the AVL tree
// will update the value if the key already exists
// @deprecated
void AVLTree::insert(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    root = insert(root, key, value);
}

// deleteKV deletes a key-value pair from the AVL tree
// @deprecated
void AVLTree::deleteKV(const std::vector<uint8_t> &key) { deleteKey(key); }

// inOrder prints the key-value pairs in the AVL tree in order
// @deprecated
void AVLTree::inOrder(AVLNode *node) {
    if (node != nullptr) {
        inOrder(node->left);
        printHex(node->key);
        inOrder(node->right);
    }
}

// inOrder prints the key-value pairs in the AVL tree in order
// @deprecated
void AVLTree::inOrder() {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    inOrder(root);
}

// inOrderTraversal traverses the AVL tree in order and calls the function on
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

// inOrderTraversal traverses the AVL tree in order and calls the function on
// each node
// @deprecated
void AVLTree::inOrderTraversal(
    std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func) {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    inOrderTraversal(root, func);
}

// deleteKey deletes a key from the AVL tree
// @deprecated
void AVLTree::deleteKey(const std::vector<uint8_t> &key) {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    root = deleteNode(root, key);
}

// Get returns the value for a given key
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

// Close closes the Write-Ahead Log
void Wal::Close() {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        stopBackgroundThread = true;
    }
    queueCondVar.notify_one();
    if (backgroundThread.joinable()) {
        backgroundThread.join();
    }
}

// WriteOperation writes an operation to the write-ahead log
bool Wal::WriteOperation(const Operation &op) {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        operationQueue.push(op);
    }
    queueCondVar.notify_one();
    return true;
}

// Recover recovers the write-ahead log
std::vector<Operation> Wal::Recover() const {
    std::vector<Operation> operations;

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

        // Add the operation to the list of operations
        operations.push_back(op);
    }

    return operations;
}

// RunRecoveredOperations runs the recovered operations
bool LSMT::RunRecoveredOperations(const std::vector<Operation> &operations) {
    for (const auto &op : operations) {
        switch (static_cast<int>(op.type())) {
            case static_cast<int>(OperationType::OpPut): {
                std::vector<uint8_t> key(op.key().begin(), op.key().end());
                std::vector<uint8_t> value(op.value().begin(), op.value().end());
                if (!Put(key, value)) {
                    return false;
                }
                break;
            }
            case static_cast<int>(OperationType::OpDelete): {
                std::vector<uint8_t> key(op.key().begin(), op.key().end());
                if (!Delete(key)) {
                    return false;
                }
                break;
            }
            default:
                std::cerr << "Unknown operation type\n";
                return false;
        }
    }
    return true;
}

// flushMemtable flushes the memtable to disk
bool LSMT::flushMemtable() {
    // Create a new memtable
    auto newMemtable = std::make_unique<AVLTree>();

    // Iterate over the current memtable and insert its elements into the new memtable
    memtable->inOrderTraversal(
        [&newMemtable](const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
            newMemtable->insert(key, value);
        });

    // Start a background thread for flushing
    flushThread = std::thread([this, newMemtable = std::move(newMemtable)]() mutable {
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
            // Set minKey and maxKey here
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
    });

    flushThread.detach();  // Detach the thread to run in the background
    return true;
}



// Delete deletes a key from the LSMT
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

// Put puts a key-value pair in the LSMT
bool LSMT::Put(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
    // Check if we are flushing or compacting
    std::unique_lock lock(sstablesLock);
    cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    lock.unlock();  // Unlock the mutex

    walLock.lock();
    // Append the operation to the write-ahead log
    Operation op;
    op.set_key(key.data(), key.size());
    op.set_value(value.data(), value.size());
    op.set_type(static_cast<::OperationType>(OperationType::OpPut));

    if (!wal->WriteOperation(op)) {
        walLock.unlock();
        return false;
    }
    walLock.unlock();

    // Check if value is tombstone
    if (value == std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE))) {
        throw std::invalid_argument("value cannot be a tombstone");
    }


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

// Get gets a value for a given key
std::vector<uint8_t> LSMT::Get(const std::vector<uint8_t> &key) {
    // Check if we are flushing or compacting
    {
        std::unique_lock lock(sstablesLock);
        cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    }  // Automatically unlocks when leaving the scope

    // Check the memtable for the key
    std::vector<uint8_t> value;
    {
        value = memtable->get(key);
    }  // Automatically unlocks when leaving the scope

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

// GetFile gets pager file
std::fstream &Pager::GetFile() { return file; }

// backgroundThreadFunc is the background thread function for the WAL
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



// PagesCount returns the number of pages in the SSTable
int64_t Pager::PagesCount() {
    if (!file.is_open()) {
        return 0;
    }

    file.seekg(0, std::ios::end);
    int64_t fileSize = file.tellg();
    return fileSize / PAGE_SIZE;
}

// clear memtable
void AVLTree::clear() {
    std::unique_lock<std::shared_mutex> lock(rwlock);

    // initialze new AVL tree
    root = nullptr;
}

// GetFilePath gets the file path of the SSTable
std::string SSTable::GetFilePath() const { return pager->GetFileName(); }

// Compact
// Compact merges pairs of SSTables in a trivial non-blocking multithreaded manner
bool LSMT::Compact() {
    // Start a background thread for compaction
    std::thread compactionThread([this]() {
        std::vector<std::future<void>> futures;
        std::vector<std::pair<std::shared_ptr<SSTable>, std::shared_ptr<SSTable>>> sstablePairs;

        {
            std::shared_lock<std::shared_mutex> lock(sstablesLock);
            for (size_t i = 0; i < sstables.size(); i += 2) {
                if (i + 1 < sstables.size()) {
                    // Lock the SSTables temporarily
                    sstablePairs.emplace_back(sstables[i], sstables[i + 1]);
                }
            }
        }

        for (const auto &pair : sstablePairs) {
            futures.push_back(std::async(std::launch::async, [this, pair] {
                auto sstable1 = pair.first;
                auto sstable2 = pair.second;

                auto it1 = std::make_unique<SSTableIterator>(sstable1->pager);
                auto it2 = std::make_unique<SSTableIterator>(sstable2->pager);
                auto newMemtable = std::make_unique<AVLTree>();

                std::optional<std::vector<uint8_t>> currentKey1, currentValue1;
                std::optional<std::vector<uint8_t>> currentKey2, currentValue2;

                // Lock sstable1 and sstable2
                std::unique_lock<std::shared_mutex> sstableLock1(sstable1->lock);
                std::unique_lock<std::shared_mutex> sstableLock2(sstable2->lock);

                // Initialize keys and values
                try {
                    if (it1->Ok()) {
                        auto kv = it1->Next();
                        currentKey1 = std::vector<uint8_t>(kv->key().begin(), kv->key().end());
                        currentValue1 = std::vector<uint8_t>(kv->value().begin(), kv->value().end());
                    }
                    if (it2->Ok()) {
                        auto kv = it2->Next();
                        currentKey2 = std::vector<uint8_t>(kv->key().begin(), kv->key().end());
                        currentValue2 = std::vector<uint8_t>(kv->value().begin(), kv->value().end());
                    }
                } catch (const std::exception &e) {
                    std::cerr << "Error initializing keys and values: " << e.what() << std::endl;
                    return;
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

                // Check if the new memtable has entries before writing
                if (newMemtable->GetSize() > 0) {
                    // Write the new memtable to a new SSTable
                    std::string newSSTablePath = directory + getPathSeparator() + "sstable_compacted_" +
                        std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) + SSTABLE_EXTENSION;
                    auto newSSTable = std::make_shared<SSTable>(
                        new Pager(newSSTablePath, std::ios::in | std::ios::out | std::ios::trunc));

                    newMemtable->inOrderTraversal([&newSSTable](const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
                        KeyValue kv;
                        kv.set_key(key.data(), key.size());
                        kv.set_value(value.data(), value.size());
                        std::vector<uint8_t> serialized = serialize(kv);
                        newSSTable->pager->Write(serialized);
                    });

                    // Add the new SSTable to the list of SSTables
                    {
                        std::unique_lock<std::shared_mutex> sstablesLockGuard(sstablesLock);
                        sstables.push_back(newSSTable);
                    }
                }

                // Delete the old SSTables
                std::filesystem::remove(sstable1->pager->GetFileName());
                std::filesystem::remove(sstable2->pager->GetFileName());

                // Remove the old SSTables from the list of SSTables
                {
                    std::unique_lock<std::shared_mutex> sstablesLockGuard(sstablesLock);
                    sstables.erase(std::remove(sstables.begin(), sstables.end(), sstable1), sstables.end());
                    sstables.erase(std::remove(sstables.begin(), sstables.end(), sstable2), sstables.end());
                }
            }));
        }

        for (auto &future : futures) {
            future.get();
        }
    });

    compactionThread.detach();  // Detach the thread to run in the background

    return true;
}

// BeginTransaction starts a new transaction.
Transaction *LSMT::BeginTransaction() {
    auto tx = new Transaction();
    activeTransactions.push_back(tx);
    return tx;
}

// AddPut adds a put operation to the transaction.
void AddPut(Transaction *tx, const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
    Rollback *rollback = new Rollback{OperationType::OpDelete, key, {}};

    // op
    Operation op;
    op.set_type(static_cast<::OperationType>(OperationType::OpPut));
    op.set_key(key.data(), key.size());
    op.set_value(value.data(), value.size());

    tx->operations.push_back(TransactionOperation{op, rollback});
}

// AddDelete adds a delete operation to the transaction.
void AddDelete(Transaction *tx, const std::vector<uint8_t> &key) {
    // Would be good to get the value of the key before deleting it so we can
    // rollback

    Rollback *rollback = new Rollback{OperationType::OpPut, key, {}};

    // op
    Operation op;
    op.set_type(static_cast<::OperationType>(OperationType::OpDelete));
    op.set_key(key.data(), key.size());

    tx->operations.push_back(TransactionOperation{op, rollback});
}

// CommitTransaction commits a transaction.
// On error we rollback the transaction
bool LSMT::CommitTransaction(Transaction *tx) {
    if (tx->aborted) {
        throw std::runtime_error("transaction has been aborted");
    }

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

    // Remove the transaction from the active list.
    auto it = std::find(activeTransactions.begin(), activeTransactions.end(), tx);
    if (it != activeTransactions.end()) {
        activeTransactions.erase(it);
    }

    return true;
}

// RollbackTransaction rolls back a transaction.
void LSMT::RollbackTransaction(Transaction *tx) {
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

// NGet gets all key-value pairs except the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::NGet(
    const std::vector<uint8_t> &key) const {
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k != key) {
            result.emplace_back(k, v);
        }
    });

    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end())) !=
                          key) {
                result.emplace_back(
                    ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end())),
                    ConvertToUint8Vector(
                        std::vector<char>(kv->value().begin(), kv->value().end())));
            }
        }
    }
    return result;
}

// LessThanEq gets all key-value pairs less than or equal to the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::LessThanEq(
    const std::vector<uint8_t> &key) {
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k <= key) {
            result.emplace_back(k, v);
        }
    });

    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && std::string(key.begin(), key.end()) <= kv->key()) {
                result.emplace_back(key, ConvertToUint8Vector(std::vector<char>(
                                             kv->value().begin(), kv->value().end())));
            }
        }
    }
    return result;
}

// GreaterThanEq gets all key-value pairs greater than or equal to the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::GreaterThanEq(
    const std::vector<uint8_t> &key) const {
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k >= key) {
            result.emplace_back(k, v);
        }
    });

    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && std::string(key.begin(), key.end()) >= kv->key()) {
                result.emplace_back(key, ConvertToUint8Vector(std::vector<char>(
                                             kv->value().begin(), kv->value().end())));
            }
        }
    }
    return result;
}

// LessThan gets all key-value pairs less than the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::LessThan(
    const std::vector<uint8_t> &key) const {
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k < key) {
            result.emplace_back(k, v);
        }
    });

    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && std::string(key.begin(), key.end()) < kv->key()) {
                result.emplace_back(key, ConvertToUint8Vector(std::vector<char>(
                                             kv->value().begin(), kv->value().end())));
            }
        }
    }
    return result;
}

// GreaterThan gets all key-value pairs greater than the key
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::GreaterThan(
    const std::vector<uint8_t> &key) const {
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k > key) {
            result.emplace_back(k, v);
        }
    });

    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && std::string(key.begin(), key.end()) > kv->key()) {
                result.emplace_back(key, ConvertToUint8Vector(std::vector<char>(
                                             kv->value().begin(), kv->value().end())));
            }
        }
    }
    return result;
}

// Range gets all key-value pairs in the range of start and end
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::Range(
    const std::vector<uint8_t> &start, const std::vector<uint8_t> &end) const {
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k >= start && k <= end) {
            result.emplace_back(k, v);
        }
    });

    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && (std::string(start.begin(), start.end()) <= kv->key() &&
                       std::string(end.begin(), end.end()) >= kv->key())) {
                result.emplace_back(
                    ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end())),
                    ConvertToUint8Vector(
                        std::vector<char>(kv->value().begin(), kv->value().end())));
            }
        }
    }
    return result;
}

// NRange gets all key-value pairs not in the range of start and end
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::NRange(
    const std::vector<uint8_t> &start, const std::vector<uint8_t> &end) const {
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> result;
    memtable->inOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k < start || k > end) {
            result.emplace_back(k, v);
        }
    });

    for (const auto &sstable : sstables) {
        SSTableIterator it(sstable->pager);
        while (it.Ok()) {
            auto kv = it.Next();
            if (kv && (std::string(start.begin(), start.end()) > kv->key() ||
                       std::string(end.begin(), end.end()) < kv->key())) {
                result.emplace_back(
                    ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end())),
                    ConvertToUint8Vector(
                        std::vector<char>(kv->value().begin(), kv->value().end())));
            }
        }
    }
    return result;
}

}  // namespace TidesDB