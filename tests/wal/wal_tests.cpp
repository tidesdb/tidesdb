#include <cassert>
#include <filesystem>
#include <iostream>
#include <vector>

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

        // Begin another transaction
        auto transaction2 = lsmTree->BeginTransaction();

        // Delete the key within the transaction
        lsmTree->AddDelete(transaction2, key1, value1);

        // Commit the transaction
        if (!lsmTree->CommitTransaction(transaction2)) {
            std::cerr << "Transaction commit failed" << std::endl;
            return 1;
        }

        // Close the LSMT instance
        lsmTree->Close();

        // Remove all SSTables to simulate a crash
        for (const auto &entry : std::filesystem::directory_iterator(directory)) {
               // check if ending in .sst
                if (entry.path().extension() == ".sst") {
                        std::filesystem::remove(entry.path());
                }
        }

        // Recover from WAL
        auto wal = std::make_unique<TidesDB::Wal>(directory + "/wal.log");
        std::vector<Operation> recoveredOperations = wal->Recover();

        // Initialize a new LSMT instance
        auto recoveredLsmTree =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        // Run recovered operations
        if (!recoveredLsmTree->RunRecoveredOperations(recoveredOperations)) {
            std::cerr << "Failed to run recovered operations" << std::endl;
            return 1;
        }

        // Verify the key was deleted
        auto result = recoveredLsmTree->Get(key1);
        assert(result.empty() && "Recovery test failed");

        recoveredLsmTree->Close();

        // Clean up
        std::filesystem::remove_all(directory);

        std::cout << "WAL recovery test passed!" << std::endl;
        return 0;

    } catch (const std::exception &e) {
        std::cerr << "Error during WAL recovery test: " << e.what() << std::endl;
        return 1;
    }
}