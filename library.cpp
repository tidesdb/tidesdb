#include "library.h"

#include <iostream>


namespace TidesDB {

// Serialize serializes the KeyValue struct to a byte vector
std::vector<uint8_t> serialize(const KeyValue& kv) {
    std::vector<uint8_t> buffer(kv.ByteSizeLong());
    kv.SerializeToArray(buffer.data(), buffer.size());
    return buffer;
}


// Deserialize deserializes a byte vector to a KeyValue struct
KeyValue deserialize(const std::vector<uint8_t>& buffer) {
    KeyValue kv;
    kv.ParseFromArray(buffer.data(), buffer.size());
    return kv;
}

// DeserializeOperation deserializes a byte vector to an Operation struct
Operation deserializeOperation(const std::vector<uint8_t>& buffer) {
    Operation op;
    op.ParseFromArray(buffer.data(), buffer.size());
    return op;
}

// SerializeOperation serializes the Operation struct to a byte vector
std::vector<uint8_t> serializeOperation(const Operation& op) {
    std::vector<uint8_t> buffer(op.ByteSizeLong());
    op.SerializeToArray(buffer.data(), buffer.size());
    return buffer;
}


// Gets os specific path separator
std::string getPathSeparator() {
    #ifdef _WIN32
            return "\\";
    #else
            return "/";
    #endif
}

// Constructor
Pager::Pager(const std::string &filename, std::ios::openmode mode) {
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

// Destructor
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
        int64_t overflow_page = (data.size() - data_written > PAGE_BODY_SIZE) ? current_page + 1 : -1;
        file.write(reinterpret_cast<const char*>(&overflow_page), sizeof(overflow_page));

        // Pad the header
        std::vector<uint8_t> header_padding(PAGE_HEADER_SIZE - sizeof(int64_t), '\0');
        file.write(reinterpret_cast<const char*>(header_padding.data()), header_padding.size());

        // Write the page body
        int64_t chunk_size = std::min(static_cast<int64_t>(data.size() - data_written), static_cast<int64_t>(PAGE_BODY_SIZE));
        file.write(reinterpret_cast<const char*>(data.data() + data_written), chunk_size);
        data_written += chunk_size;

        // Pad the body if necessary
        if (chunk_size < PAGE_BODY_SIZE) {
            std::vector<uint8_t> body_padding(PAGE_BODY_SIZE - chunk_size, '\0');
            file.write(reinterpret_cast<const char*>(body_padding.data()), body_padding.size());
        }

        current_page++;
    }

    return page_number;
}

int64_t Pager::WriteTo(int64_t page_number, const std::vector<uint8_t> &data) {
    // Implement the method similarly to Write, but start at the specified page_number
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
    file.read(reinterpret_cast<char*>(&overflow_page), sizeof(overflow_page));
    if (file.fail()) {
        throw TidesDBException("Failed to read page header for page: " + std::to_string(page_number));
    }

    std::vector<uint8_t> header_padding(PAGE_HEADER_SIZE - sizeof(int64_t), '\0');
    file.read(reinterpret_cast<char*>(header_padding.data()), header_padding.size());

    std::vector<uint8_t> data(PAGE_BODY_SIZE, '\0');
    file.read(reinterpret_cast<char*>(data.data()), PAGE_BODY_SIZE);
    if (file.fail()) {
        throw TidesDBException("Failed to read page body for page: " + std::to_string(page_number));
    }

    int64_t current_page = overflow_page;
    while (current_page != -1) {
        file.seekg(current_page * PAGE_SIZE);
        if (file.fail()) {
            throw TidesDBException("Failed to seek to overflow page: " + std::to_string(current_page));
        }

        file.read(reinterpret_cast<char*>(&overflow_page), sizeof(overflow_page));
        if (file.fail()) {
            throw TidesDBException("Failed to read overflow header for page: " + std::to_string(current_page));
        }

        file.read(reinterpret_cast<char*>(header_padding.data()), header_padding.size());

        std::vector<uint8_t> overflow_data(PAGE_BODY_SIZE, '\0');
        file.read(reinterpret_cast<char*>(overflow_data.data()), PAGE_BODY_SIZE);
        if (file.fail()) {
            throw TidesDBException("Failed to read overflow body for page: " + std::to_string(current_page));
        }

        data.insert(data.end(), overflow_data.begin(), overflow_data.end());
        current_page = overflow_page;
    }

    // Remove null bytes from the data
    data.erase(std::remove_if(data.begin(), data.end(), [](uint8_t c) { return c == '\0'; }), data.end());

    return data;
}

int AVLTree::height(AVLNode* node) {
    if (node == nullptr)
        return 0;
    return node->height;
}

AVLNode* AVLTree::rightRotate(AVLNode* y) {
    AVLNode* x = y->left;
    AVLNode* T2 = x->right;

    x->right = y;
    y->left = T2;

    y->height = std::max(height(y->left), height(y->right)) + 1;
    x->height = std::max(height(x->left), height(x->right)) + 1;

    return x;
}

AVLNode* AVLTree::leftRotate(AVLNode* x) {
    AVLNode* y = x->right;
    AVLNode* T2 = y->left;

    y->left = x;
    x->right = T2;

    x->height = std::max(height(x->left), height(x->right)) + 1;
    y->height = std::max(height(y->left), height(y->right)) + 1;

    return y;
}

int AVLTree::getBalance(AVLNode* node) {
    if (node == nullptr)
        return 0;
    return height(node->left) - height(node->right);
}

AVLNode* AVLTree::insert(AVLNode* node, const std::vector<uint8_t>& key, const std::vector<uint8_t>& value) {
    if (node == nullptr)
        return new AVLNode(key, value);

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

    if (balance > 1 && key < node->left->key)
        return rightRotate(node);

    if (balance < -1 && key > node->right->key)
        return leftRotate(node);

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

void AVLTree::printHex(const std::vector<uint8_t>& data) {
    for (auto byte : data) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
}

AVLNode* AVLTree::deleteNode(AVLNode* root, const std::vector<uint8_t>& key) {
    if (root == nullptr)
        return root;

    if (key < root->key)
        root->left = deleteNode(root->left, key);
    else if (key > root->key)
        root->right = deleteNode(root->right, key);
    else {
        if ((root->left == nullptr) || (root->right == nullptr)) {
            AVLNode* temp = root->left ? root->left : root->right;

            if (temp == nullptr) {
                temp = root;
                root = nullptr;
            } else
                *root = *temp;

            delete temp;
        } else {
            AVLNode* temp = minValueNode(root->right);

            root->key = temp->key;
            root->value = temp->value;

            root->right = deleteNode(root->right, temp->key);
        }
    }

    if (root == nullptr)
        return root;

    root->height = 1 + std::max(height(root->left), height(root->right));

    int balance = getBalance(root);

    if (balance > 1 && getBalance(root->left) >= 0)
        return rightRotate(root);

    if (balance > 1 && getBalance(root->left) < 0) {
        root->left = leftRotate(root->left);
        return rightRotate(root);
    }

    if (balance < -1 && getBalance(root->right) <= 0)
        return leftRotate(root);

    if (balance < -1 && getBalance(root->right) > 0) {
        root->right = rightRotate(root->right);
        return leftRotate(root);
    }

    return root;
}

AVLNode* AVLTree::minValueNode(AVLNode* node) {
    AVLNode* current = node;
    while (current->left != nullptr)
        current = current->left;
    return current;
}

void AVLTree::insert(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value) {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    root = insert(root, key, value);
}

void AVLTree::deleteKV(const std::vector<uint8_t>& key) {
    deleteKey(key);
}

void AVLTree::inOrder(AVLNode* node) {
    if (node != nullptr) {
        inOrder(node->left);
        printHex(node->key);
        inOrder(node->right);
    }
}

void AVLTree::inOrder() {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    inOrder(root);
}

void AVLTree::inOrderTraversal(AVLNode* node, std::function<void(const std::vector<uint8_t>&, const std::vector<uint8_t>&)> func) {
    if (node != nullptr) {
        inOrderTraversal(node->left, func);
        func(node->key, node->value);
        inOrderTraversal(node->right, func);
    }
}

void AVLTree::inOrderTraversal(std::function<void(const std::vector<uint8_t>&, const std::vector<uint8_t>&)> func) {
    std::shared_lock<std::shared_mutex> lock(rwlock);
    inOrderTraversal(root, func);
}

void AVLTree::deleteKey(const std::vector<uint8_t>& key) {
    std::unique_lock<std::shared_mutex> lock(rwlock);
    root = deleteNode(root, key);
}

bool Wal::WriteOperation(const Operation& op) {
        // Implementation of writing operation to WAL
        return true; // Return true if successful, false otherwise
}

// flushMemtable flushes the memtable to disk
    bool LSMT::flushMemtable() {
    std::cout << "flushMemtable called\n";

    // Iterate through the memtable and write the key-value pairs to the SSTable
    std::vector<KeyValue> kvPairs;

    // Lock the memtable for reading
    std::shared_lock<std::shared_mutex> lock(memtableLock);

    // Populate kvPairs with key-value pairs from the memtable
    memtable->inOrderTraversal([&kvPairs](const std::vector<uint8_t>& key, const std::vector<uint8_t>& value) {
        KeyValue kv;
        kv.set_key(key.data(), key.size());
        kv.set_value(value.data(), value.size());
        kvPairs.push_back(kv);
    });

    lock.unlock();

    int sstableCounter = sstables.size();

    // Write the key-value pairs to the SSTable
    std::string sstablePath = directory + getPathSeparator() + "sstable_" + std::to_string(sstableCounter++) + SSTABLE_EXTENSION;

    // Create a new SSTable
    auto sstable = std::make_shared<SSTable>(new Pager(sstablePath, std::ios::in | std::ios::out | std::ios::trunc));

    // We must set minKey and maxKey
    if (!kvPairs.empty()) {
        if (!kvPairs.empty()) {
            sstable->minKey.assign(kvPairs.front().key().begin(), kvPairs.front().key().end());
            sstable->maxKey.assign(kvPairs.back().key().begin(), kvPairs.back().key().end());
        }
    }

    // Serialize the key-value pairs
    for (const auto& kv : kvPairs) {
        std::vector<uint8_t> serialized = serialize(kv);
        // Print serialized data
        for (auto byte : serialized) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl;

        sstable->pager->Write(serialized);
    }

    // Add the new SSTable to the list of SSTables
    {
        std::unique_lock<std::shared_mutex> sstablesLockGuard(sstablesLock);
        sstables.push_back(sstable.get());
    }

    return true;
}


bool LSMT::Delete(const std::vector<uint8_t>& key) {
    // Check if we are flushing or compacting
    std::unique_lock<std::mutex> lock(condMutex);
    cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });
    lock.unlock();

    // Append the operation to the write-ahead log
    Operation op;
    op.set_type(static_cast<::OperationType>(OperationType::OpDelete)); // Corrected the operation type to OpDelete
    op.set_key(key.data(), key.size());

    if (!wal->WriteOperation(op)) {
        return false;
    }

    // Lock memtable for writing
    std::unique_lock<std::shared_mutex> memtableLock(memtableMutex);

    // Write a tombstone value to the memtable for the key
    memtable->insert(key, std::vector<uint8_t>(TOMBSTONE_VALUE.begin(), TOMBSTONE_VALUE.end()));

    return true;
}


bool LSMT::Put(const std::vector<uint8_t>& key, const std::vector<uint8_t>& value) {
    std::cout << "Put called\n";

    // Check if we are flushing or compacting
    std::unique_lock<std::mutex> lock(condMutex);
    cond.wait(lock, [this] { return isFlushing.load() == 0 && isCompacting.load() == 0; });

    std::cout << "Put called after wait\n";

    std::cout << "lock memtable\n";


    std::unique_lock<std::shared_mutex> walLock(wal->lock);

    std::cout << "wal locked\n";

    // Lock memtable for writing
    std::unique_lock<std::shared_mutex> memtableLock(memtableMutex);

    std::cout << "memtable locked\n";

    std::cout << "lock wal\n";


    // Append the operation to the write-ahead log
    std::cout << "append operation\n";

    // Append the operation to the write-ahead log
    Operation op;
    op.set_key(key.data(), key.size());
    op.set_value(value.data(), value.size());
    op.set_type(static_cast<::OperationType>(OperationType::OpPut));

    if (!wal->WriteOperation(op)) {
        return false;
    }

    std::cout << "operation appended\n";

    // Check if value is tombstone
    if (value == std::vector<uint8_t>(TOMBSTONE_VALUE.begin(), TOMBSTONE_VALUE.end())) {
        throw std::invalid_argument("value cannot be a tombstone");
    }

    // Increase the memtable size
    memtableSize.fetch_add(key.size() + value.size());


    // Put the key-value pair in the memtable
    memtable->insert(key, value);
    // Increase the memtable size
    memtableSize.fetch_add(key.size() + value.size());

    std::cout << "memtable size: " << memtableSize.load() << std::endl;
    std::cout << "key value inserted\n";

    // If the memtable size exceeds the flush size, flush the memtable to disk
    if (memtableSize.load() > memtableFlushSize) {

        if (!flushMemtable()) {
            // Unlock the memtable
            memtableLock.unlock();

            // Unlock the write-ahead log
            walLock.unlock();

            // Notify the compaction thread
            cond.notify_one();

            return false;
        }
    }

    // Unlock the memtable
    memtableLock.unlock();

    // Unlock the write-ahead log
    walLock.unlock();

    // Notify the compaction thread
    cond.notify_one();


    return true;
}

// GetFile gets pager file
std::fstream& Pager::GetFile() {
    return file;
}

// wal close
void Wal::Close() const {
    if (pager->GetFile().is_open()) {
        pager->GetFile().close();
    }
}



// clear memtable
void AVLTree::clear() {
    std::unique_lock<std::shared_mutex> lock(rwlock);

    // initialze new AVL tree
    root = nullptr;
}

} // namespace TidesDB