#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "../../libtidesdb.hpp"

int main() {
    // Define parameters
    std::string directory = "./tidesdb_data";  // The directory for storing data
    std::filesystem::perms directoryPerm =
        std::filesystem::perms::owner_all | std::filesystem::perms::group_read;  // Permissions
    int memtableFlushSize = 10 * 1024;  // Example flush size (10 KB)
    int compactionInterval = 8;         // Compaction interval

    try {
        // Initialize the LSMT
        auto lsmTree =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        // Insert 20kb of data
        for (int i = 0; i < 20; i++) {
            std::string keyStr = "key" + std::to_string(i);
            std::string valueStr(1024, 'a' + i);
            std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
            std::vector<uint8_t> value(valueStr.begin(), valueStr.end());
            lsmTree->Put(key, value);
        }

        // Get key "key5"
        std::string keyStr = "key5";
        std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
        std::vector<uint8_t> dat = lsmTree->Get(key);

        if (dat.empty()) {
            std::cerr << "Key not found Get test failed" << std::endl;
        } else {
            std::cout << "Key found Get test passed" << std::endl;
        }

        // Delete key "key5"
        if (lsmTree->Delete(key)) {
            std::cout << "Key deleted Delete test passed" << std::endl;
        } else {
            std::cerr << "Key not found Delete test failed" << std::endl;
        }

        // Check if key "key5" is deleted
        dat = lsmTree->Get(key);

        if (dat.empty()) {
            std::cout << "Key not found delete then get test passed" << std::endl;
        } else {
            std::cerr << "Key found delete then get test failed" << std::endl;
        }

        lsmTree->Close();

        // Read the directory and delete all .sst files
        for (const auto &entry : std::filesystem::directory_iterator(directory)) {
            if (entry.path().extension() == ".sst") {
                std::filesystem::remove(entry.path());
            }
        }

        // Find the .wal file and rename to test.wal
        std::filesystem::path walFile;
        for (const auto &entry : std::filesystem::directory_iterator(directory)) {
            if (entry.path().filename() == ".wal") {
                walFile = entry.path();
                break;
            }
        }

        if (walFile.empty()) {
            std::cerr << "No .wal file found" << std::endl;
            return 1;
        }

        std::filesystem::rename(walFile, directory + "/test.wal");

        TidesDB::Wal wal(directory + "/test.wal");

        auto newLSMT =
            TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval);

        wal.Recover(*newLSMT);

        // Verify recovered data
        for (int i = 0; i < 20; i++) {
            std::string keyStr = "key" + std::to_string(i);
            std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
            std::string expectedValueStr(1024, 'a' + i);
            std::vector<uint8_t> expectedValue(expectedValueStr.begin(), expectedValueStr.end());
            std::vector<uint8_t> recoveredValue = newLSMT->Get(key);

            if (keyStr == "key5") {
                if (!recoveredValue.empty()) {
                    std::cerr << "Recovered data should be empty for deleted key " << keyStr
                              << std::endl;
                    return 1;
                }
            } else {
                if (recoveredValue != expectedValue) {
                    std::cerr << "Recovered data does not match for key " << keyStr << std::endl;
                    return 1;
                }
            }
        }

        std::cout << "Recovered data matches original data" << std::endl;

        newLSMT->Close();

        // remove the directory
        std::filesystem::remove_all(directory);

        return 0;

    } catch (const std::exception &e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
        return 1;
    }
}