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
#include "libtidesdb.hpp"

// The TidesDB namespace
namespace TidesDB {

// ConvertToUint8Vector
// converts a vector of chars to a vector of uint8_t
std::vector<uint8_t> ConvertToUint8Vector(const std::vector<char> &input) {
    return std::vector<uint8_t>(input.begin(), input.end());
}

// ConvertToCharVector
// converts a vector of uint8_t to a vector of chars
std::vector<char> ConvertToCharVector(const std::vector<uint8_t> &input) {
    return std::vector<char>(input.begin(), input.end());
}

// compressZstd
// compresses a byte vector using Zstandard
std::vector<uint8_t> compressZstd(const std::vector<uint8_t> &input) {
    // Check if the input is empty
    if (input.empty()) {
        return {};
    }

    size_t maxCompressedSize = ZSTD_compressBound(input.size());
    std::vector<uint8_t> compressed(maxCompressedSize);

    size_t compressedSize =
        ZSTD_compress(compressed.data(), maxCompressedSize, input.data(), input.size(),
                      1  // Compression level
        );

    if (ZSTD_isError(compressedSize)) {
        throw TidesDBException("Compression failed: " +
                               std::string(ZSTD_getErrorName(compressedSize)));
    }

    compressed.resize(compressedSize);
    return compressed;
}

// decompressZstd
// decompresses a byte vector using Zstandard
std::vector<uint8_t> decompressZstd(const std::vector<uint8_t> &compressed) {
    // Check if the input is empty
    if (compressed.empty()) {
        return {};
    }

    unsigned long long decompressedSize =
        ZSTD_getFrameContentSize(compressed.data(), compressed.size());
    if (decompressedSize == ZSTD_CONTENTSIZE_ERROR) {
        throw TidesDBException("Error getting decompressed size");
    }
    if (decompressedSize == ZSTD_CONTENTSIZE_UNKNOWN) {
        throw TidesDBException("Unknown decompressed size");
    }

    std::vector<uint8_t> decompressed(decompressedSize);

    size_t result = ZSTD_decompress(decompressed.data(), decompressedSize, compressed.data(),
                                    compressed.size());

    if (ZSTD_isError(result)) {
        throw TidesDBException("Decompression failed: " + std::string(ZSTD_getErrorName(result)));
    }

    decompressed.resize(result);
    return decompressed;
}

// serialize
// serializes the KeyValue struct to a byte vector
std::vector<uint8_t> serialize(const KeyValue &kv) {
    // Check if the key or value is empty
    if (kv.key().empty() || kv.value().empty()) {
        throw TidesDBException("Key or value is empty");
    }

    std::vector<uint8_t> buffer(kv.ByteSizeLong());
    kv.SerializeToArray(buffer.data(), buffer.size());
    return buffer;
}

// deserialize
// deserializes a byte vector to a KeyValue
KeyValue deserialize(const std::vector<uint8_t> &buffer) {
    if (buffer.empty()) {
        throw TidesDBException("Buffer is empty");
    }

    KeyValue kv;
    kv.ParseFromArray(buffer.data(), buffer.size());
    return kv;
}

// deserializeOperation
// deserializes a byte vector to an Operation
Operation deserializeOperation(const std::vector<uint8_t> &buffer) {
    if (buffer.empty()) {
        throw TidesDBException("Buffer is empty");
    }

    Operation op;
    op.ParseFromArray(buffer.data(), buffer.size());
    return op;
}

// serializeOperation
// serializes the Operation struct to a byte vector
std::vector<uint8_t> serializeOperation(const Operation &op) {
    if (op.key().empty() && op.value().empty()) {
        throw TidesDBException("Key or value is empty");
    }

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

    // set filename and mode
    this->fileName = filename;

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
int64_t Pager::Write(const std::vector<uint8_t> &data, bool compress) {
    if (!file.is_open()) {
        throw TidesDBException("File is not open");
    }

    if (data.empty()) {
        throw TidesDBException("Data is empty");
    }

    const std::vector<uint8_t> *dataToWrite = &data;

    if (compress) {
        std::vector<uint8_t> compressedData;
        // Compress the data
        compressedData = compressZstd(data);
        dataToWrite = &compressedData;
    } else {
        dataToWrite = &data;
    }

    // Lock the file mutex
    std::unique_lock<std::shared_mutex> lock(fileMutex);

    file.seekg(0, std::ios::end);
    int64_t page_number = file.tellg() / PAGE_SIZE;

    int64_t data_written = 0;
    int64_t current_page = page_number;

    while (data_written < dataToWrite->size()) {
        // A little check if we need to add a new lock for the current page, just in case
        if (current_page >= pageLocks.size()) {
            pageLocks.push_back(std::make_shared<std::shared_mutex>());
        }

        file.seekp(current_page * PAGE_SIZE);
        if (file.fail()) {
            throw TidesDBException("Failed to seek to page: " + std::to_string(current_page));
        }

        // Write the header for overflow management
        int64_t overflow_page =
            (dataToWrite->size() - data_written > PAGE_BODY_SIZE) ? current_page + 1 : -1;
        file.write(reinterpret_cast<const char *>(&overflow_page), sizeof(overflow_page));

        // Pad the header
        std::vector<uint8_t> header_padding(PAGE_HEADER_SIZE - sizeof(int64_t), '\0');
        file.write(reinterpret_cast<const char *>(header_padding.data()), header_padding.size());

        // Write the page body
        int64_t chunk_size = std::min(static_cast<int64_t>(dataToWrite->size() - data_written),
                                      static_cast<int64_t>(PAGE_BODY_SIZE));
        file.write(reinterpret_cast<const char *>(dataToWrite->data() + data_written), chunk_size);
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

// Pager::Read
// reads data from a file starting at a specified page number and handles overflow pages if the data
// spans multiple pages
std::vector<uint8_t> Pager::Read(int64_t page_number, bool decompress) {
    if (!file.is_open()) {
        throw TidesDBException("File is not open");
    }

    if (page_number < 0) {
        throw TidesDBException("Invalid page number");
    }

    // We will calculate the page index and acquire the page lock
    int64_t pageIndex = page_number % pageLocks.size();
    std::shared_lock<std::shared_mutex> pageLock(*pageLocks[pageIndex]);

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
        // We will calculate the page index and acquire the overflow page lock
        pageIndex = current_page % pageLocks.size();
        std::shared_lock<std::shared_mutex> overflowPageLock(
            *pageLocks[pageIndex]);  // Will unlock when out of scope

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

    // Decompress the data if necessary
    if (decompress) {
        return decompressZstd(data);
    }

    return data;
}

// AVLTree::Clear
// clears the AVL tree
void AVLTree::Clear() {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    root = nullptr;
    cachedSize = 0;
}

// AVLTree::height
// returns the height of the AVL tree node
int AVLTree::height(AVLNode *node) {
    if (node == nullptr) return 0;
    return node->height;
}

// AVLTree::GetSize
// returns the size of the AVL tree
int AVLTree::GetSize() {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    return cachedSize;
}

// AVLTree::rightRotate
// performs a right rotation on the AVL tree node
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
int AVLTree::getBalance(AVLNode *node) {
    if (node == nullptr) return 0;
    return height(node->left) - height(node->right);
}

// AVLTree::insert
// inserts a key-value pair into the AVL tree
AVLNode *AVLTree::insert(AVLNode *node, const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value,
                         std::optional<std::chrono::steady_clock::time_point> expirationTime) {
    if (node == nullptr) {
        return new AVLNode(key, value, expirationTime);
    }

    // Check if the current node is expired
    if (node->expirationTime.has_value() &&
        node->expirationTime.value() <= std::chrono::steady_clock::now()) {
        // Mark as tombstone
        node->value =
            std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE));
    }

    if (key < node->key) {
        node->left = insert(node->left, key, value, expirationTime);
    } else if (key > node->key) {
        node->right = insert(node->right, key, value, expirationTime);
    } else {
        node->value = value;  // Update value

        if (expirationTime.has_value()) {
            node->expirationTime = expirationTime.value();
        } else {
            node->expirationTime.reset();
        }

        return node;
    }

    // Height and balancing logic
    node->height = 1 + std::max(height(node->left), height(node->right));
    int balance = getBalance(node);

    // Rotation logic
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
void AVLTree::printHex(const std::vector<uint8_t> &data) {
    for (auto byte : data) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

// AVLTree::deleteNode
// deletes a key-value pair from the AVL tree
AVLNode *AVLTree::deleteNode(AVLNode *root, const std::vector<uint8_t> &key) {
    if (root == nullptr) return root;

    if (key < root->key)
        root->left = deleteNode(root->left, key);
    else if (key > root->key)
        root->right = deleteNode(root->right, key);
    else {
        cachedSize -= root->key.size() + root->value.size();
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
AVLNode *AVLTree::minValueNode(AVLNode *node) {
    AVLNode *current = node;
    while (current->left != nullptr) current = current->left;
    return current;
}

// AVLTree::Insert
// inserts a key-value pair into the AVL tree
// will update the value if the key already exists
void AVLTree::Insert(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value,
                     std::optional<std::chrono::steady_clock::time_point> expirationTime) {
    std::unique_lock<std::shared_mutex> lock(rwlock);

    root = insert(root, key, value, expirationTime);
    cachedSize += key.size() + value.size();
}

// AVLTree::InsertBatch
// inserts a batch of key-value pairs into the AVL tree
void AVLTree::InsertBatch(const std::vector<KeyValue> &kvPairs) {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    for (const auto &kv : kvPairs) {
        root =
            insert(root, ConvertToUint8Vector(std::vector<char>(kv.key().begin(), kv.key().end())),
                   ConvertToUint8Vector(std::vector<char>(kv.value().begin(), kv.value().end())),
                   std::nullopt);
        cachedSize += kv.key().size() + kv.value().size();
    }
}

// AVLTree::inOrder
// prints the key-value pairs in the AVL tree in order
void AVLTree::inOrder(AVLNode *node) {
    if (node != nullptr) {
        inOrder(node->left);
        printHex(node->key);
        inOrder(node->right);
    }
}

// AVLTree::inOrder
// prints the key-value pairs in the AVL tree in order
void AVLTree::inOrder() { inOrder(root); }

// AVLTree::inOrderTraversal
// traverses the AVL tree in order and calls the function on
// each node
void AVLTree::inOrderTraversal(
    AVLNode *node,
    std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func) {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    if (node != nullptr) {
        inOrderTraversal(node->left, func);
        func(node->key, node->value);
        inOrderTraversal(node->right, func);
    }
}

// AVLTree::InOrderTraversal
// traverses the AVL tree in order and calls the function on
// each node
void AVLTree::InOrderTraversal(
    std::function<void(const std::vector<uint8_t> &, const std::vector<uint8_t> &)> func) {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    inOrderTraversal(root, func);
}

// AVLTree::Delete
// deletes a key from the AVL tree
void AVLTree::Delete(const std::vector<uint8_t> &key) {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    root = deleteNode(root, key);
}

// AVLTree::Get
// returns the value for a given key
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
                // We return an empty vector if it is a tombstone
                return {};
            }

            // Check if expired
            if (current->expirationTime.has_value() &&
                current->expirationTime.value() <= std::chrono::steady_clock::now()) {
                // Mark as tombstone
                current->value = std::vector<uint8_t>(TOMBSTONE_VALUE,
                                                      TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE));
                return {};
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
        std::lock_guard<std::mutex> lock(queueMutex);  // Lock the queue mutex
        stopBackgroundThread = true;                   // Set the flag to stop the background thread
    }
    queueCondVar.notify_one();          // Notify the condition variable to wake up the thread
    if (backgroundThread.joinable()) {  // Join the thread to ensure it has finished executing
        backgroundThread.join();
    }

    // Close the pager
    pager->Close();
}

// Wal::AppendOperation
// responsible for appending an operation to the write-ahead log (WAL).
// It ensures thread safety by using a mutex to lock the operation queue,
// pushes the operation onto the queue, and then notifies a condition variable to
// signal that a new operation is available
void Wal::AppendOperation(const Operation &op) {
    {
        std::lock_guard<std::mutex> lock(queueMutex);  // Lock the queue mutex
        operationQueue.push(op);                       // Push the operation onto the queue
    }
    queueCondVar
        .notify_one();  // Notify the condition variable to signal that a new operation is available
}

// Wal::Recover
// reads and processes operations from the Write-Ahead Log (WAL) pages one by one. It locks the WAL
// for reading, iterates through each page, deserializes the data into an Operation object, and
// immediately processes the operation by inserting or deleting key-value pairs in the LSMT's
// memtable. This approach avoids storing all operations in memory at once, optimizing memory usage.
bool Wal::Recover(LSMT &lsmt) const {
    // Lock the WAL for reading
    std::unique_lock<std::shared_mutex> lock(walLock);

    // Get the number of pages in the WAL
    int64_t pageCount = pager->PagesCount();

    // Iterate through each page in the WAL
    for (int64_t i = 0; i < pageCount; ++i) {
        // Read the data from the current page
        std::vector<uint8_t> data;
        try {
            data = pager->Read(i, compress);
        } catch (const std::exception &e) {
            std::cerr << "Error reading page " << i << ": " << e.what() << std::endl;
            return false;
        }

        if (data.empty()) {
            std::cerr << "Page " << i << " is empty" << std::endl;
            continue;
        }

        // Deserialize the data into an Operation object
        Operation op;
        try {
            op = deserializeOperation(data);
        } catch (const std::exception &e) {
            std::cerr << "Error deserializing operation from page " << i << ": " << e.what()
                      << std::endl;
            return false;
        }

        // Process the operation immediately
        switch (static_cast<int>(op.type())) {
            case static_cast<int>(TidesDB::OperationType::OpPut): {
                std::vector<uint8_t> key(op.key().begin(), op.key().end());
                std::vector<uint8_t> value(op.value().begin(), op.value().end());
                lsmt.Put(key, value);
                break;
            }
            case static_cast<int>(TidesDB::OperationType::OpDelete): {
                std::vector<uint8_t> key(op.key().begin(), op.key().end());
                lsmt.Delete(key);
                break;
            }
            default:
                std::cerr << "Unknown operation type: " << static_cast<int>(op.type())
                          << " on page " << i << std::endl;
                return false;
        }
    }

    return true;
}

// LSMT::writeLineToLog
// writes a line to the log file in format [YYYY-MM-DD HH:MM:SS] line
void LSMT::writeLineToLog(const std::string &line) {
    // Lock the log file mutex
    std::lock_guard<std::mutex> lock(logFileLock);

    // Get the current time
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    // Format the time as [YYYY-MM-DD HH:MM:SS]
    std::stringstream ss;
    ss << "[" << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X") << "] ";

    // Write the formatted time and the line to the log file
    logFile << ss.str() << line << std::endl;
}

// LSMT::flushMemtable
// responsible for flushing the current memtable to disk. It creates a new memtable,
// transfers the data from the current memtable to the new one, and then adds the new memtable
// to the flush queue. Finally, it notifies the flush thread to process the queue
bool LSMT::flushMemtable() {
    try {
        // Wait until we are done flushing or compacting
        {
            std::unique_lock lock(sstablesLock);
            cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
        }  // Automatically unlocks when leaving the scope

        isFlushing.store(1);  // Set the flag to indicate that we are flushing

        // If debug logging is enabled, write the operation to the log file
        if (logging) {
            writeLineToLog("Flushing memtable to disk at size: " +
                           std::to_string(memtable->GetSize()));
        }

        // Check if memtable is empty (in case on close)
        if (memtable->GetSize() == 0) {
            isFlushing.store(0);  // Reset the flag
            cond.notify_all();    // Notify all waiting threads
            return true;
        }

        // Create a new memtable
        auto newMemtable = std::make_unique<AVLTree>();

        // Iterate over the current memtable and insert its elements into the new memtable
        memtable->InOrderTraversal([&newMemtable](const std::vector<uint8_t> &key,
                                                  const std::vector<uint8_t> &value) {
            // Skip tombstones
            if (value ==
                std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE))) {
                return;
            }
            newMemtable->Insert(key, value);
        });

        // Clear the current memtable
        memtable->Clear();

        isFlushing.store(0);  // Reset the flag
        cond.notify_all();    // Notify all waiting threads

        // Add the new memtable to the flush queue
        {
            std::unique_lock<std::mutex> lock(flushQueueMutex);
            flushQueue.push(std::move(newMemtable));
        }
        flushQueueCondVar.notify_one();

        return true;
    } catch (const std::exception &e) {
        isFlushing.store(0);  // Reset the flag
        cond.notify_all();    // Notify all waiting threads
        std::cerr << "Error in flushMemtable: " << e.what() << std::endl;
        return false;
    }
}

// flushThreadFunc
// the background thread function that processes the flush queue. It waits for a new memtable to be
// added to the queue then pops and flushes the memtable to disk
void LSMT::flushThreadFunc() {
    while (stopBackgroundThreads.load() == 0) {
        std::unique_ptr<AVLTree> newMemtable;

        // Wait for a new memtable to be added to the queue
        {
            std::unique_lock<std::mutex> lock(flushQueueMutex);
            flushQueueCondVar.wait(
                lock, [this] { return stopBackgroundThreads.load() || !flushQueue.empty(); });
            if (stopBackgroundThreads.load() && flushQueue.empty()) {
                break;
            }

            if (!flushQueue.empty()) {
                newMemtable = std::move(flushQueue.front());
                flushQueue.pop();
            }
        }

        if (newMemtable) {
            std::vector<KeyValue> kvPairs;  // Key-value pairs to be written to the SSTable

            // Populate kvPairs with key-value pairs from the new memtable
            newMemtable->InOrderTraversal(
                [&kvPairs](const std::vector<uint8_t> &key, const std::vector<uint8_t> &value) {
                    KeyValue kv;

                    // Check if the value is a tombstone
                    // We should not write tombstones to disk
                    // We skip them
                    if (value == std::vector<uint8_t>(TOMBSTONE_VALUE,
                                                      TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE))) {
                        return;
                    }

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
            auto sstable = std::make_shared<SSTable>(std::make_shared<Pager>(
                sstablePath, std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc));

            // We must set minKey and maxKey
            if (!kvPairs.empty()) {
                sstable->minKey = std::vector<uint8_t>(kvPairs.front().key().begin(),
                                                       kvPairs.front().key().end());
                sstable->maxKey =
                    std::vector<uint8_t>(kvPairs.back().key().begin(), kvPairs.back().key().end());
            }

            if (kvPairs.empty()) {
                continue;  // Skip if there are no key-value pairs
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
                isCompacting.store(1);  // Set the flag to indicate that we are compacting
                Compact();              // Compact the SSTables
                isCompacting.store(0);  // Reset the flag
            }
        }

        // Reset the isFlushing flag
        isFlushing.store(0);
        flushQueueCondVar.notify_all();
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

    {
        Operation op;
        op.set_type(static_cast<::OperationType>(OperationType::OpDelete));
        op.set_key(key.data(), key.size());
        wal->AppendOperation(op);
    }

    // If debug logging is enabled, write the operation to the log file
    if (logging) {
        std::string line = "DELETE " + std::string(key.begin(), key.end());
        writeLineToLog(line);
    }

    memtable->Insert(
        key, std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE)));

    // If the memtable size exceeds the flush size, flush the memtable to disk
    if (memtable->GetSize() >= memtableFlushSize) {
        flushMemtable();
    }

    return true;
}

// LSMT::DeleteBatch
// responsible for deleting a batch of keys from the LSMT structure.
bool LSMT::DeleteBatch(const std::vector<std::vector<uint8_t>> &keys) {
    // Check if we are flushing or compacting
    {
        std::unique_lock lock(sstablesLock);
        cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    }  // Automatically unlocks when leaving the scope

    // Create a batch of operations
    std::vector<Operation> operations;
    for (const auto &key : keys) {
        Operation op;
        op.set_type(static_cast<::OperationType>(OperationType::OpDelete));
        op.set_key(key.data(), key.size());
        operations.push_back(op);
    }

    // Append the operations to the Write-Ahead Log (WAL)
    for (const auto &op : operations) {
        wal->AppendOperation(op);
    }

    // Create a batch of KeyValue pairs with tombstone values
    std::vector<KeyValue> kvPairs;
    for (const auto &key : keys) {
        KeyValue kv;
        kv.set_key(key.data(), key.size());
        kv.set_value(TOMBSTONE_VALUE, strlen(TOMBSTONE_VALUE));
        kvPairs.push_back(kv);
    }

    // Insert the batch of KeyValue pairs into the memtable
    memtable->InsertBatch(kvPairs);

    // If the memtable size exceeds the flush size, flush the memtable to disk
    if (memtable->GetSize() >= memtableFlushSize) {
        flushMemtable();
    }

    return true;
}

// LSMT::Put
//  inserts a key-value pair into the LSMT structure.
//  function ensures thread safety by using locks and condition variables, writes the operation to
//  the Write-Ahead Log (WAL), and inserts the key-value pair into the memtable. If the memtable
//  exceeds a certain size, it triggers a background flush to disk.
bool LSMT::Put(const std::vector<uint8_t> &key, const std::vector<uint8_t> &value,
               std::optional<std::chrono::steady_clock::time_point> expirationTime) {
    // Check if we are flushing or compacting
    {
        std::unique_lock lock(sstablesLock);
        cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    }  // Automatically unlocks when leaving the scope

    // Check for null pointers
    if (!wal || !memtable) {
        throw TidesDBException("WAL or memtable is null");
    }

    // If debug logging is enabled, write the operation to the log file
    if (logging) {
        std::string line = "PUT " + std::string(key.begin(), key.end()) + " " +
                           std::string(value.begin(), value.end());
        writeLineToLog(line);
    }

    {
        Operation op;
        op.set_key(key.data(), key.size());
        op.set_value(value.data(), value.size());
        op.set_type(static_cast<::OperationType>(OperationType::OpPut));
        wal->AppendOperation(op);
    }

    // Check if value is tombstone
    if (value == std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE))) {
        throw TidesDBException("Value cannot be a tombstone value");
    }

    // Insert the key-value pair into the memtable
    memtable->Insert(key, value, expirationTime);

    // If the memtable size exceeds the flush size, flush the memtable to disk
    if (memtable->GetSize() >= memtableFlushSize) {
        if (!flushMemtable()) {
            return false;
        }
    }

    return true;
}

// LSMT::PutBatch
// inserts a batch of key-value pairs into the LSMT structure.
// It ensures thread safety by using locks and condition variables, writes the operations to the
// Write-Ahead Log (WAL), and inserts the key-value pairs into the memtable. If the memtable exceeds
// a certain size, it triggers a background flush to disk.
bool LSMT::PutBatch(
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &batch) {
    // Check if we are flushing or compacting
    {
        std::unique_lock lock(sstablesLock);
        cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    }  // Automatically unlocks when leaving the scope

    // Check for null pointers
    if (!wal || !memtable) {
        throw TidesDBException("WAL or memtable is null");
    }

    // Create a batch of operations
    std::vector<Operation> operations;
    for (const auto &[key, value] : batch) {
        Operation op;
        op.set_key(key.data(), key.size());
        op.set_value(value.data(), value.size());
        op.set_type(static_cast<::OperationType>(OperationType::OpPut));
        operations.push_back(op);
    }

    // Append the operations to the Write-Ahead Log (WAL)
    for (const auto &op : operations) {
        wal->AppendOperation(op);
    }

    // Convert batch to KeyValue pairs
    std::vector<KeyValue> kvPairs;
    for (const auto &[key, value] : batch) {
        // Check if value is tombstone
        if (value ==
            std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE))) {
            throw TidesDBException("Value cannot be a tombstone value");
        }
        KeyValue kv;
        kv.set_key(key.data(), key.size());
        kv.set_value(value.data(), value.size());
        kvPairs.push_back(kv);
    }

    // Insert the batch of key-value pairs into the memtable
    memtable->InsertBatch(kvPairs);

    // If the memtable size exceeds the flush size, flush the memtable to disk
    if (memtable->GetSize() >= memtableFlushSize) {
        if (!flushMemtable()) {
            return false;
        }
    }

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

    std::vector<uint8_t> value;

    if (memtable->GetSize() > 0) {
        // Check the memtable for the key
        value = memtable->Get(key);

        // If value is found and it's not a tombstone, return it
        if (!value.empty() &&
            value !=
                std::vector<uint8_t>(TOMBSTONE_VALUE, TOMBSTONE_VALUE + strlen(TOMBSTONE_VALUE))) {
            return value;
        }
    }

    if (sstables.empty()) {
        return {};  // Early exit if there are no SSTables
    }

    // Iterate over the SSTables from latest to oldest
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        const auto &sstable = *it;
        if (!sstable) {
            continue;  // Skip null SSTables
        }

        {
            // we must lock for the min and max key check
            std::shared_lock lock(sstable->lock);

            // If the key is not within the range of this SSTable, skip it
            if (key < sstable->minKey || key > sstable->maxKey) {
                continue;
            }
        }

        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);
        if (!sstableIt) {
            continue;  // Skip if iterator creation failed
        }

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                break;  // Break if no more key-value pairs
            }

            // Check for tombstones
            if (std::string(kv->value().begin(), kv->value().end()) == TOMBSTONE_VALUE) {
                return {};  // Return empty vector if tombstone is found
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
void Wal::backgroundThreadFunc() {
    try {
        while (true) {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCondVar.wait(lock,
                              [this] { return stopBackgroundThread || !operationQueue.empty(); });

            if (stopBackgroundThread && operationQueue.empty()) {
                break;
            }

            if (!operationQueue.empty()) {
                Operation op = operationQueue.front();
                operationQueue.pop();
                lock.unlock();

                // if empty skip
                if (op.key().empty() && op.value().empty()) {
                    continue;
                }

                // Serialize and write the operation to the WAL
                std::vector<uint8_t> serializedOp = serializeOperation(op);
                int64_t pageNumber = pager->Write(serializedOp, compress);
                if (pageNumber < 0) {
                    std::cerr << "Failed to write operation to WAL" << std::endl;
                }
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "Exception in backgroundThreadFunc: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception in backgroundThreadFunc." << std::endl;
    }
}

// Pager::PagesCount
// returns the number of pages in the SSTable
int64_t Pager::PagesCount() {
    if (!file.is_open()) {
        throw TidesDBException("File is not open");
    }

    file.seekg(0, std::ios::end);
    int64_t fileSize = file.tellg();
    return fileSize / PAGE_SIZE;
}

// LSMT::Compact
// starts a background thread to perform compaction of SSTables in a non-blocking manner. It pairs
// SSTables, merges them, and writes the merged data to new SSTables. The old SSTables are then
// deleted.
bool LSMT::Compact() {
    // Start a background thread to perform compaction
    compactionThread = std::thread([this] {
        try {
            // If debug logging is enabled, write the operation to the log file
            if (logging) {
                writeLineToLog("Compacting SSTables");
            }

            const int maxConcurrentThreads =
                std::max(1, maxCompactionThreads);  // Max concurrent threads
            std::vector<std::unique_ptr<std::counting_semaphore<1>>>
                semaphores;                                   // Semaphores for concurrency
            for (int i = 0; i < maxConcurrentThreads; ++i) {  // Create semaphores
                semaphores.emplace_back(std::make_unique<std::counting_semaphore<1>>(1));
            }

            std::vector<std::future<void>> futures;
            std::vector<std::pair<std::shared_ptr<SSTable>, std::shared_ptr<SSTable>>> sstablePairs;

            // Pair SSTables
            {
                std::shared_lock<std::shared_mutex> lock(sstablesLock);
                for (size_t i = 0; i < sstables.size(); i += 2) {
                    if (i + 1 < sstables.size()) {
                        sstablePairs.emplace_back(sstables[i], sstables[i + 1]);
                    }
                }
            }

            // Compact SSTables
            for (const auto &pair : sstablePairs) {
                for (auto &semaphore : semaphores) {
                    semaphore->acquire();
                }
                futures.push_back(std::async(std::launch::async, [this, pair, &semaphores] {
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
                            std::cerr << "Error: Failed to create SSTableIterator.\n";
                            for (auto &semaphore : semaphores) {
                                semaphore->release();
                            }
                            return;
                        }

                        if (it1->Ok()) {
                            auto kv = it1->Next();
                            if (kv) {
                                currentKey1 =
                                    std::vector<uint8_t>(kv->key().begin(), kv->key().end());
                                currentValue1 =
                                    std::vector<uint8_t>(kv->value().begin(), kv->value().end());
                            }
                        }
                        if (it2->Ok()) {
                            auto kv = it2->Next();
                            if (kv) {
                                currentKey2 =
                                    std::vector<uint8_t>(kv->key().begin(), kv->key().end());
                                currentValue2 =
                                    std::vector<uint8_t>(kv->value().begin(), kv->value().end());
                            }
                        }

                        std::optional<std::vector<uint8_t>> minKey, maxKey;

                        while (currentKey1.has_value() || currentKey2.has_value()) {
                            if (!currentKey2.has_value() ||
                                (currentKey1.has_value() && *currentKey1 < *currentKey2)) {
                                newMemtable->Insert(*currentKey1, *currentValue1);
                                if (!minKey.has_value() || *currentKey1 < *minKey) {
                                    minKey = currentKey1;
                                }
                                if (!maxKey.has_value() || *currentKey1 > *maxKey) {
                                    maxKey = currentKey1;
                                }
                                if (it1->Ok()) {
                                    auto kv = it1->Next();
                                    if (kv) {
                                        currentKey1 = std::vector<uint8_t>(kv->key().begin(),
                                                                           kv->key().end());
                                        currentValue1 = std::vector<uint8_t>(kv->value().begin(),
                                                                             kv->value().end());
                                    } else {
                                        currentKey1.reset();
                                        currentValue1.reset();
                                    }
                                } else {
                                    currentKey1.reset();
                                    currentValue1.reset();
                                }
                            } else {
                                newMemtable->Insert(*currentKey2, *currentValue2);
                                if (!minKey.has_value() || *currentKey2 < *minKey) {
                                    minKey = currentKey2;
                                }
                                if (!maxKey.has_value() || *currentKey2 > *maxKey) {
                                    maxKey = currentKey2;
                                }
                                if (it2->Ok()) {
                                    auto kv = it2->Next();
                                    if (kv) {
                                        currentKey2 = std::vector<uint8_t>(kv->key().begin(),
                                                                           kv->key().end());
                                        currentValue2 = std::vector<uint8_t>(kv->value().begin(),
                                                                             kv->value().end());
                                    } else {
                                        currentKey2.reset();
                                        currentValue2.reset();
                                    }
                                } else {
                                    currentKey2.reset();
                                    currentValue2.reset();
                                }
                            }
                        }

                        if (newMemtable->GetSize() > 0) {
                            std::string newSSTablePath =
                                directory + getPathSeparator() + "sstable_compacted_" +
                                std::to_string(
                                    std::chrono::system_clock::now().time_since_epoch().count()) +
                                SSTABLE_EXTENSION;
                            auto newSSTable = std::make_shared<SSTable>(std::make_shared<Pager>(
                                newSSTablePath,
                                std::ios::in | std::ios::out | std::ios::binary | std::ios::trunc));
                            newMemtable->InOrderTraversal(
                                [&newSSTable, this](const std::vector<uint8_t> &key,
                                                    const std::vector<uint8_t> &value) {
                                    KeyValue kv;
                                    kv.set_key(key.data(), key.size());
                                    kv.set_value(value.data(), value.size());
                                    std::vector<uint8_t> serialized = serialize(kv);

                                    if (!serialized.empty()) {
                                        newSSTable->pager->Write(serialized);
                                    }
                                });

                            if (minKey.has_value()) {
                                newSSTable->minKey = *minKey;
                            }
                            if (maxKey.has_value()) {
                                newSSTable->maxKey = *maxKey;
                            }

                            {
                                std::unique_lock<std::shared_mutex> sstablesLockGuard(sstablesLock);
                                sstables.erase(
                                    std::remove(sstables.begin(), sstables.end(), sstable1),
                                    sstables.end());
                                sstables.erase(
                                    std::remove(sstables.begin(), sstables.end(), sstable2),
                                    sstables.end());
                                sstables.push_back(newSSTable);
                            }
                        }

                        sstable1->pager->Close();
                        sstable2->pager->Close();
                        std::filesystem::remove(sstable1->pager->GetFileName());
                        std::filesystem::remove(sstable2->pager->GetFileName());

                    } catch (const std::exception &e) {
                        std::cerr << "Error during compaction: " << e.what() << std::endl;
                    }
                    for (auto &semaphore : semaphores) {
                        semaphore->release();
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
    });

    if (compactionThread.joinable()) {
        compactionThread.join();
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
    memtable->InOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k != key) {
            kvMap.insert({k, v});  // Use insert to avoid overwriting
        }
    });

    // Traverse the SSTables from latest to oldest and collect key-value pairs not equal to the key
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        const auto &sstable = *it;
        if (!sstable) {
            continue;  // Skip null SSTables
        }

        // If the key is not within the range of this SSTable, skip it
        {
            // we must lock for the min and max key check
            std::shared_lock lock(sstable->lock);

            // If the key is not within the range of this SSTable, skip it
            if (key < sstable->minKey || key > sstable->maxKey) {
                continue;
            }
        }

        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);
        if (!sstableIt) {
            continue;  // Skip if iterator creation failed
        }

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                break;  // Break if no more key-value pairs
            }

            auto kvKey =
                ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()));
            if (kvKey != key) {
                kvMap.insert({kvKey, ConvertToUint8Vector(std::vector<char>(
                                         kv->value().begin(), kv->value().end()))});  // Use insert
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
    memtable->InOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k <= key && kvMap.find(k) == kvMap.end()) {
            kvMap[k] = v;
        }
    });

    // Traverse the SSTables from latest to oldest and collect key-value pairs less than or equal to
    // the key
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        const auto &sstable = *it;
        if (!sstable) {
            continue;  // Skip null SSTables
        }

        // If the key is not within the range of this SSTable, skip it
        {
            // we must lock for the min and max key check
            std::shared_lock lock(sstable->lock);

            // If the key is not within the range of this SSTable, skip it
            if (key < sstable->minKey || key > sstable->maxKey) {
                continue;
            }
        }

        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);
        if (!sstableIt) {
            continue;  // Skip if iterator creation failed
        }

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                continue;  // Skip if kv is null
            }

            auto kvKey =
                ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()));
            if (kvKey <= key && kvMap.find(kvKey) == kvMap.end()) {
                kvMap[kvKey] =
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
    memtable->InOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k >= key) {
            kvMap[k] = v;
        }
    });

    // Traverse the SSTables from latest to oldest and collect key-value pairs greater than or equal
    // to the key
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        const auto &sstable = *it;
        if (!sstable) {
            continue;  // Skip null SSTables
        }

        // If the key is not within the range of this SSTable, skip it
        {
            // we must lock for the min and max key check
            std::shared_lock lock(sstable->lock);

            // If the key is not within the range of this SSTable, skip it
            if (key < sstable->minKey || key > sstable->maxKey) {
                continue;
            }
        }
        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);
        if (!sstableIt) {
            continue;  // Skip if iterator creation failed
        }

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                break;  // Break if no more key-value pairs
            }

            auto kvKey =
                ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()));
            if (kvKey >= key && kvMap.find(kvKey) == kvMap.end()) {
                kvMap[kvKey] =
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
    memtable->InOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k < key) {
            kvMap[k] = v;
        }
    });

    // Traverse the SSTables from latest to oldest and collect key-value pairs less than the key
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        const auto &sstable = *it;
        if (!sstable) {
            continue;  // Skip null SSTables
        }

        // If the key is not within the range of this SSTable, skip it

        {
            // we must lock for the min and max key check
            std::shared_lock lock(sstable->lock);

            // If the key is not within the range of this SSTable, skip it
            if (key <= sstable->minKey) {
                continue;
            }
        }

        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);
        if (!sstableIt) {
            continue;  // Skip if iterator creation failed
        }

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                continue;
            }

            auto kvKey =
                ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()));
            if (kvKey < key && kvMap.find(kvKey) == kvMap.end()) {
                kvMap[kvKey] =
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
    memtable->InOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k > key) {
            kvMap.insert({k, v});  // Use insert to avoid overwriting
        }
    });

    // Traverse the SSTables from latest to oldest and collect key-value pairs greater than the key
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        const auto &sstable = *it;
        if (!sstable) {
            continue;  // Skip null SSTables
        }

        // If the key is not within the range of this SSTable, skip it
        {
            // we must lock for the min and max key check
            std::shared_lock lock(sstable->lock);

            // If the key is not within the range of this SSTable, skip it
            if (key >= sstable->maxKey) {
                continue;
            }
        }

        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);
        if (!sstableIt) {
            continue;  // Skip if iterator creation failed
        }

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                continue;
            }

            auto kvKey =
                ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()));
            if (kvKey > key && kvMap.find(kvKey) == kvMap.end()) {
                kvMap[kvKey] =
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

// LSMT::Range
// gets all key-value pairs in the range of start and end
std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> LSMT::Range(
    const std::vector<uint8_t> &start, const std::vector<uint8_t> &end) const {
    std::map<std::vector<uint8_t>, std::vector<uint8_t>> kvMap;

    // Traverse the memtable and collect key-value pairs in the range
    memtable->InOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k >= start && k <= end) {
            kvMap.insert({k, v});  // Use insert to avoid overwriting
        }
    });

    // Traverse the SSTables from latest to oldest and collect key-value pairs in the range
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        const auto &sstable = *it;
        if (!sstable) {
            continue;  // Skip null SSTables
        }

        {
            // we must lock for the min and max key check
            std::shared_lock lock(sstable->lock);

            // If the key is not within the range of this SSTable, skip it
            if (end < sstable->minKey || start > sstable->maxKey) {
                continue;
            }
        }

        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);
        if (!sstableIt) {
            continue;  // Skip if iterator creation failed
        }

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                continue;  // Skip if kv is null
            }

            auto kvKey =
                ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()));
            if (kvKey >= start && kvKey <= end && kvMap.find(kvKey) == kvMap.end()) {
                kvMap.insert({kvKey, ConvertToUint8Vector(std::vector<char>(kv->value().begin(),
                                                                            kv->value().end()))});
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
    memtable->InOrderTraversal([&](const std::vector<uint8_t> &k, const std::vector<uint8_t> &v) {
        if (k < start || k > end) {
            kvMap.insert({k, v});  // Use insert to avoid overwriting
        }
    });

    // Traverse the SSTables from latest to oldest and collect key-value pairs not in the range
    for (auto it = sstables.rbegin(); it != sstables.rend(); ++it) {
        const auto &sstable = *it;
        if (!sstable) {
            continue;  // Skip null SSTables
        }

        // If the key range does not overlap with this SSTable, skip it
        {
            // we must lock for the min and max key check
            std::shared_lock lock(sstable->lock);

            // If the key is not within the range of this SSTable, skip it
            if (end < sstable->minKey || start > sstable->maxKey) {
                continue;
            }
        }

        // Get an iterator for the SSTable file
        auto sstableIt = std::make_unique<SSTableIterator>(sstable->pager);
        if (!sstableIt) {
            continue;  // Skip if iterator creation failed
        }

        // Iterate over the SSTable
        while (sstableIt->Ok()) {
            auto kv = sstableIt->Next();
            if (!kv) {
                continue;  // Skip null key-value pairs
            }

            auto kvKey =
                ConvertToUint8Vector(std::vector<char>(kv->key().begin(), kv->key().end()));
            if ((kvKey < start || kvKey > end) && kvMap.find(kvKey) == kvMap.end()) {
                kvMap.insert({kvKey, ConvertToUint8Vector(std::vector<char>(kv->value().begin(),
                                                                            kv->value().end()))});
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

}  // end namespace TidesDB