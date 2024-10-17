#include <filesystem>
#include <iostream>
#include <vector>

#include "../../libtidesdb.h"

std::vector<uint8_t> convertToUint8Vector(const std::vector<char> &input) {
    return std::vector<uint8_t>(input.begin(), input.end());
}

std::vector<char> convertToCharVector(const std::vector<uint8_t> &input) {
    return std::vector<char>(input.begin(), input.end());
}

int main() {
    // Open the file in both read and write mode
    TidesDB::Pager pager("test.db", std::ios::in | std::ios::out | std::ios::binary);
    std::vector<char> data(1024 * 8, 'a');  // Write 8192 bytes of 'a' characters

    // Write "Hello, world!" to the end of the data vector
    data.insert(data.end(), "Hello, world!", "Hello, world!" + 13);

    // Write multiple pages
    std::vector<int64_t> page_numbers;
    for (int i = 0; i < 5; ++i) {
        int64_t page_number = pager.Write(convertToUint8Vector(data));
        page_numbers.push_back(page_number);
        std::cout << "Page number " << i << ": " << page_number << std::endl;
    }

    // Verify the data for each page
    bool all_tests_passed = true;
    for (int i = 0; i < 5; ++i) {
        std::vector<char> read_data = convertToCharVector(pager.Read(page_numbers[i]));
        if (std::string(read_data.begin(), read_data.end()) !=
            std::string(1024 * 8, 'a') + "Hello, world!") {
            std::cout << "Pager test failed for page " << i << std::endl;
            all_tests_passed = false;
        }
    }

    if (all_tests_passed) {
        std::cout << "All pager tests passed" << std::endl;
    } else {
        std::cout << "Some pager tests failed" << std::endl;
    }

    // Remove the test.db file
    std::filesystem::remove("test.db");
}