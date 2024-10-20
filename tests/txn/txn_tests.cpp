#include <cassert>
#include <filesystem>
#include <iostream>
#include <vector>

#include "../../libtidesdb.hpp"

void printResult(const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &result) {
    for (const auto &kv : result) {
        std::cout << "Key: ";
        for (auto byte : kv.first) {
            std::cout << static_cast<int>(byte) << " ";
        }
        std::cout << "Value: ";
        for (auto byte : kv.second) {
            std::cout << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;
    }
}

bool expect(const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &result,
            const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> &expected) {
    if (result.size() != expected.size()) {
        std::cerr << "Size mismatch: expected " << expected.size() << " but got " << result.size()
                  << std::endl;
        return false;
    }
    for (size_t i = 0; i < result.size(); ++i) {
        if (result[i].first != expected[i].first) {
            std::cerr << "Key mismatch at index " << i << ": expected ";
            for (auto byte : expected[i].first) {
                std::cerr << static_cast<int>(byte) << " ";
            }
            std::cerr << "but got ";
            for (auto byte : result[i].first) {
                std::cerr << static_cast<int>(byte) << " ";
            }
            std::cerr << std::endl;
            return false;
        }
        if (result[i].second != expected[i].second) {
            std::cerr << "Value mismatch at index " << i << ": expected ";
            for (auto byte : expected[i].second) {
                std::cerr << static_cast<int>(byte) << " ";
            }
            std::cerr << "but got ";
            for (auto byte : result[i].second) {
                std::cerr << static_cast<int>(byte) << " ";
            }
            std::cerr << std::endl;
            return false;
        }
    }
    return true;
}

int main() {
    // Define parameters
    std::string directory = "./tidesdb_data";  // The directory for storing data
    std::filesystem::perms directoryPerm =
        std::filesystem::perms::owner_all | std::filesystem::perms::group_read;  // Permissions
    int memtableFlushSize = 10 * 1024;  // Example flush size (10 KB)
    int compactionInterval = 8;

    try {
        // Initialize the LSMT
        auto lsmTree =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        // Begin a transaction
        auto transaction1 = lsmTree->BeginTransaction();

        // Add a key-value pair within the transaction
        std::vector<uint8_t> key1 = {1, 1, 1, 1};
        std::vector<uint8_t> value1 = {1};
        lsmTree->AddPut(transaction1, key1, value1);

        // Commit the transaction
        if (!lsmTree->CommitTransaction(transaction1)) {
            std::cerr << "Transaction commit failed" << std::endl;
            return 1;
        }

        // Verify the key-value pair was added
        auto result1 = lsmTree->Get(key1);
        assert(result1 == value1 && "Transaction test failed for key1");

        // Begin another transaction
        auto transaction2 = lsmTree->BeginTransaction();

        // Delete the key within the transaction
        lsmTree->AddDelete(transaction2, key1, value1);

        // Commit the transaction
        if (!lsmTree->CommitTransaction(transaction2)) {
            std::cerr << "Transaction commit failed" << std::endl;
            return 1;
        }

        // Verify the key was deleted
        auto result2 = lsmTree->Get(key1);
        assert(result2.empty() && "Delete operation failed");

        // Begin another transaction to test rollback
        auto transaction3 = lsmTree->BeginTransaction();

        // Delete the key again within the transaction
        lsmTree->AddDelete(transaction3, key1, value1);

        // Rollback the transaction
        lsmTree->RollbackTransaction(transaction3);

        // Verify the key was restored
        auto result3 = lsmTree->Get(key1);
        assert(result3 == value1 && "Rollback operation failed");

        lsmTree->Close();

        // Remove the directory
        std::filesystem::remove_all(directory);

        std::cout << "All transaction tests passed!" << std::endl;

        return 0;

    } catch (const std::exception &e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
        return 1;
    }
}