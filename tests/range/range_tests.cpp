#include <cassert>
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

        // Insert 20kb of data
        for (int i = 0; i < 20; i++) {
            std::vector<uint8_t> key(4, i);
            std::vector<uint8_t> value(1, i);

            lsmTree->Put(key, value);
        }

        // Test the Range function
        std::cout << "Range [0,0,0,0] to [10,10,10,10]:" << std::endl;
        auto rangeResult = lsmTree->Range({0, 0, 0, 0}, {10, 10, 10, 10});
        printResult(rangeResult);
        std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expectedRange = {
            {{0, 0, 0, 0}, {0}}, {{1, 1, 1, 1}, {1}}, {{2, 2, 2, 2}, {2}},     {{3, 3, 3, 3}, {3}},
            {{4, 4, 4, 4}, {4}}, {{5, 5, 5, 5}, {5}}, {{6, 6, 6, 6}, {6}},     {{7, 7, 7, 7}, {7}},
            {{8, 8, 8, 8}, {8}}, {{9, 9, 9, 9}, {9}}, {{10, 10, 10, 10}, {10}}};
        assert(expect(rangeResult, expectedRange) && "Range test failed");

        // Test the LessThan function
        std::cout << "LessThan [10,10,10,10]:" << std::endl;
        auto lessThanResult = lsmTree->LessThan({10, 10, 10, 10});
        printResult(lessThanResult);
        std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expectedLessThan = {
            {{0, 0, 0, 0}, {0}}, {{1, 1, 1, 1}, {1}}, {{2, 2, 2, 2}, {2}}, {{3, 3, 3, 3}, {3}},
            {{4, 4, 4, 4}, {4}}, {{5, 5, 5, 5}, {5}}, {{6, 6, 6, 6}, {6}}, {{7, 7, 7, 7}, {7}},
            {{8, 8, 8, 8}, {8}}, {{9, 9, 9, 9}, {9}}};
        assert(expect(lessThanResult, expectedLessThan) && "LessThan test failed");

        // Test the GreaterThan function
        std::cout << "GreaterThan [10,10,10,10]:" << std::endl;
        auto greaterThanResult = lsmTree->GreaterThan({10, 10, 10, 10});
        printResult(greaterThanResult);
        std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expectedGreaterThan = {
            {{11, 11, 11, 11}, {11}}, {{12, 12, 12, 12}, {12}}, {{13, 13, 13, 13}, {13}},
            {{14, 14, 14, 14}, {14}}, {{15, 15, 15, 15}, {15}}, {{16, 16, 16, 16}, {16}},
            {{17, 17, 17, 17}, {17}}, {{18, 18, 18, 18}, {18}}, {{19, 19, 19, 19}, {19}}};
        assert(expect(greaterThanResult, expectedGreaterThan) && "GreaterThan test failed");

        // Test the NRange function
        std::cout << "NRange [0,0,0,0] to [10,10,10,10]:" << std::endl;
        auto nrangeResult = lsmTree->NRange({0, 0, 0, 0}, {10, 10, 10, 10});
        printResult(nrangeResult);
        std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expectedNRange = {
            {{11, 11, 11, 11}, {11}}, {{12, 12, 12, 12}, {12}}, {{13, 13, 13, 13}, {13}},
            {{14, 14, 14, 14}, {14}}, {{15, 15, 15, 15}, {15}}, {{16, 16, 16, 16}, {16}},
            {{17, 17, 17, 17}, {17}}, {{18, 18, 18, 18}, {18}}, {{19, 19, 19, 19}, {19}}};
        assert(expect(nrangeResult, expectedNRange) && "NRange test failed");

        // Test the GreaterThanEqual function
        std::cout << "GreaterThanEqual [10,10,10,10]:" << std::endl;
        auto greaterThanEqualResult = lsmTree->GreaterThanEq({10, 10, 10, 10});
        printResult(greaterThanEqualResult);
        std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
            expectedGreaterThanEqual = {{{10, 10, 10, 10}, {10}}, {{11, 11, 11, 11}, {11}},
                                        {{12, 12, 12, 12}, {12}}, {{13, 13, 13, 13}, {13}},
                                        {{14, 14, 14, 14}, {14}}, {{15, 15, 15, 15}, {15}},
                                        {{16, 16, 16, 16}, {16}}, {{17, 17, 17, 17}, {17}},
                                        {{18, 18, 18, 18}, {18}}, {{19, 19, 19, 19}, {19}}};
        assert(expect(greaterThanEqualResult, expectedGreaterThanEqual) &&
               "GreaterThanEqual test failed");

        // Test the LessThanEqual function
        std::cout << "LessThanEqual [10,10,10,10]:" << std::endl;
        auto lessThanEqualResult = lsmTree->LessThanEq({10, 10, 10, 10});
        printResult(lessThanEqualResult);
        std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expectedLessThanEqual = {
            {{0, 0, 0, 0}, {0}}, {{1, 1, 1, 1}, {1}}, {{2, 2, 2, 2}, {2}},     {{3, 3, 3, 3}, {3}},
            {{4, 4, 4, 4}, {4}}, {{5, 5, 5, 5}, {5}}, {{6, 6, 6, 6}, {6}},     {{7, 7, 7, 7}, {7}},
            {{8, 8, 8, 8}, {8}}, {{9, 9, 9, 9}, {9}}, {{10, 10, 10, 10}, {10}}};
        assert(expect(lessThanEqualResult, expectedLessThanEqual) && "LessThanEqual test failed");

        lsmTree->Close();

        // Remove the directory
        std::filesystem::remove_all(directory);

        std::cout << "All tests passed" << std::endl;

        return 0;

    } catch (const std::exception &e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
    }
}