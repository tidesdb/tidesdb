/*
 * This test program is designed to evaluate the thread-safety and correctness of the
 * TidesDB::SkipList implementation under concurrent operations. The test performs random insert,
 * get, and delete operations on the SkipList using multiple threads and verifies the results at the
 * end of the operations.
 *
 * The test consists of the following steps:
 *
 * 1. **Initialization
 *    - A TidesDB::SkipList object is created with a maximum level of 10 and a probability factor of
 * 0.5.
 *    - A shared map `expectedResults` is initialized to store the expected key-value pairs after
 * each operation.
 *    - A mutex `resultMutex` is initialized to protect access to the shared `expectedResults` map.
 *
 * 2. **Random Operation
 *    - A function `randomOperations` is defined to perform random insert, get, and delete
 * operations on the SkipList.
 *    - The function uses a random number generator to determine the key and the type of operation
 * (insert, get, or delete).
 *    - For each operation
 *      - **Insert** A key-value pair is inserted into the SkipList, and the expected result is
 * updated in the shared map.
 *      - **Get** The value for a given key is retrieved from the SkipList, and the result is
 * printed.
 *      - **Delete** A key-value pair is deleted from the SkipList, and the expected result is
 * removed from the shared map.
 *    - The function uses a lock guard to ensure thread-safe access to the shared `expectedResults`
 * map.
 *    - The function simulates work by sleeping for 100 milliseconds between operations.
 *
 * 3. **Thread Creation**
 *    - Four threads are created, each executing the `randomOperations` function with the SkipList
 * object, a unique thread ID, and a specified number of operations (10 operations per thread).
 *    - The threads are started and joined to ensure that all operations are completed before
 * proceeding to the next step.
 *
 * 4. **Result Verification**
 *    - After all threads have completed their operations, the main function compares the expected
 * results stored in the `expectedResults` map with the actual results retrieved from the SkipList.
 *    - For each key in the `expectedResults` map, the corresponding value is retrieved from the
 * SkipList and compared with the expected value.
 *    - If any mismatch is found, a message is printed indicating the key with the mismatch, and the
 * test is marked as failed.
 *    - If all expected results match the actual results, a message is printed indicating that all
 * tests passed.
 *
 * This test ensures that the TidesDB::SkipList implementation can handle concurrent operations
 * correctly and maintains data integrity under multi-threaded access.
 */
#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include "../../libtidesdb.h"

std::mutex resultMutex;
std::map<std::vector<uint8_t>, std::vector<uint8_t>> expectedResults;

void randomOperations(TidesDB::SkipList &skipList, int threadId, int operations) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(1, 100);
    std::uniform_int_distribution<> opDist(0, 2);

    for (int i = 0; i < operations; ++i) {
        int key = dist(gen);
        int op = opDist(gen);
        std::vector keyVec = {static_cast<uint8_t>(key)};
        std::vector valueVec = {static_cast<uint8_t>(key * 10)};

        if (op == 0) {  // Insert
            skipList.insert(keyVec, valueVec);
            std::lock_guard lock(resultMutex);
            expectedResults[keyVec] = valueVec;
            std::cout << "Thread " << threadId << " inserted key: " << key << std::endl;
        } else if (op == 1) {  // Get
            auto value = skipList.get(keyVec);
            std::lock_guard lock(resultMutex);
            if (!value.empty()) {
                std::cout << "Thread " << threadId << " got key: " << key
                          << " value: " << static_cast<int>(value[0]) << std::endl;
            } else {
                std::cout << "Thread " << threadId << " key: " << key << " not found" << std::endl;
            }
        } else {  // Delete
            skipList.deleteKV(keyVec);
            std::lock_guard lock(resultMutex);
            expectedResults.erase(keyVec);
            std::cout << "Thread " << threadId << " deleted key: " << key << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Sleep to simulate work
    }
}

int main() {
    TidesDB::SkipList skipList(10, 0.5);
    const int numThreads = 4;
    const int operationsPerThread = 10;

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back(randomOperations, std::ref(skipList), i, operationsPerThread);
    }

    for (auto &thread : threads) {
        thread.join();
    }

    // Compare expected and actual results
    bool testPassed = true;
    for (const auto &pair : expectedResults) {
        auto actualValue = skipList.get(pair.first);
        if (actualValue != pair.second) {
            std::cout << "Mismatch for key: " << static_cast<int>(pair.first[0]) << std::endl;
            testPassed = false;
        }
    }

    if (testPassed) {
        std::cout << "All tests passed" << std::endl;
    } else {
        std::cout << "Some tests failed" << std::endl;
    }

    return 0;
}