#include <chrono>
#include <iostream>
#include <random>
#include <vector>
#include "../libtidesdb.h"

// Function to generate random data
std::vector<uint8_t> generateRandomData(size_t size) {
    std::vector<uint8_t> data(size);
    std::generate(data.begin(), data.end(), []() { return rand() % 256; });
    return data;
}

// Benchmarking function
void benchmarkLSMT(TidesDB::LSMT &lsmt, size_t numOperations, size_t dataSize) {
    using namespace std::chrono;

    // Generate random keys and values
    std::vector<std::vector<uint8_t>> keys(numOperations);
    std::vector<std::vector<uint8_t>> values(numOperations);
    for (size_t i = 0; i < numOperations; ++i) {
        keys[i] = generateRandomData(dataSize);  // Generate random key
        values[i] = generateRandomData(dataSize);  // Generate random value
    }

    // Benchmark Put operations
    auto start = high_resolution_clock::now();  // Start timer
    for (size_t i = 0; i < numOperations; ++i) {
        lsmt.Put(keys[i], values[i]);  // Perform Put operation
    }
    auto end = high_resolution_clock::now();  // End timer
    auto putDuration = duration_cast<milliseconds>(end - start).count();  // Calculate duration
    std::cout << numOperations <<  " Put operations took " << putDuration << " ms\n";

    // Benchmark Get operations
    start = high_resolution_clock::now();  // Start timer
    for (size_t i = 0; i < numOperations; ++i) {
        lsmt.Get(keys[i]);  // Perform Get operation
    }
    end = high_resolution_clock::now();  // End timer
    auto getDuration = duration_cast<milliseconds>(end - start).count();  // Calculate duration
    std::cout << numOperations <<  " Get operations took " << getDuration << " ms\n";

    // Benchmark Delete operations
    start = high_resolution_clock::now();  // Start timer
    for (size_t i = 0; i < numOperations; ++i) {
        lsmt.Delete(keys[i]);  // Perform Delete operation
    }
    end = high_resolution_clock::now();  // End timer
    auto deleteDuration = duration_cast<milliseconds>(end - start).count();  // Calculate duration
    std::cout << numOperations << " Delete operations took " << deleteDuration << " ms\n";
}

int main() {
    // Initialize LSMT
    auto lsmt = TidesDB::LSMT::New("benchmark_directory", std::filesystem::perms::all, 250, 2);

    // Run benchmark
    // Note: The benchmark will run for 1000 operations with 5 bytes of data per operation
    benchmarkLSMT(*lsmt, 1000, 5);

    // Remove benchmark directory
        std::filesystem::remove_all("benchmark_directory");

    return 0;
}