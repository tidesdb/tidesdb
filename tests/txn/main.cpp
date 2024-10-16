#include <iostream>
#include <vector>
#include <cassert>
#include <filesystem>
#include "../../libtidesdb.h"

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
        std::cerr << "Size mismatch: expected " << expected.size() << " but got " << result.size() << std::endl;
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

        // Insert data within the transaction
        std::vector<uint8_t> key1 = {1, 1, 1, 1};
        std::vector<uint8_t> value1 = {1};
        lsmTree->Put(key1, value1);

        std::vector<uint8_t> key2 = {2, 2, 2, 2};
        std::vector<uint8_t> value2 = {2};
        lsmTree->Put(key2, value2);

        // Commit the transaction
        lsmTree->CommitTransaction(transaction1);

        // Verify the data was inserted
        auto result1 = lsmTree->Get(key1);
        assert(result1 == value1 && "Transaction test failed for key1");

        auto result2 = lsmTree->Get(key2);
        assert(result2 == value2 && "Transaction test failed for key2");

        // Begin another transaction
        auto transaction2 = lsmTree->BeginTransaction();

        // Insert more data within the transaction
        std::vector<uint8_t> key3 = {3, 3, 3, 3};
        std::vector<uint8_t> value3 = {3};
        lsmTree->Put(key3, value3);

        // Rollback the transaction
        lsmTree->RollbackTransaction(transaction2);

        // Verify the data was not inserted
        auto result3 = lsmTree->Get(key3);
        assert(result3.empty() && "Rollback test failed for key3");

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