#include <iostream>
#include "library.h"

std::vector<uint8_t> convertToUint8Vector(const std::vector<char>& input) {
    return std::vector<uint8_t>(input.begin(), input.end());
}

std::vector<char> convertToCharVector(const std::vector<uint8_t>& input) {
    return std::vector<char>(input.begin(), input.end());
}

int main() {
    // Open the file in both read and write mode
    // TidesDB::Pager pager("test.db", std::ios::in | std::ios::out | std::ios::binary);
    // std::vector<char> data(1024, 'a');
    // // Write hello world to end of data vector
    // data.insert(data.end(), "Hello, world!", "Hello, world!" + 13);
    //
    // // Convert data to std::vector<uint8_t> before writing
    // int64_t page_number = pager.Write(convertToUint8Vector(data));
    // std::cout << "Page number: " << page_number << std::endl;
    //
    // // Convert read data from std::vector<uint8_t> to std::vector<char>
    // std::vector<char> read_data = convertToCharVector(pager.Read(page_number));
    // std::cout << "Read data size: " << read_data.size() << std::endl;
    // std::cout << "Read data: " << std::string(read_data.begin(), read_data.end()) << std::endl;


    // Test AVL tree
    // TidesDB::AVLTree tree;
    //
    // // Insert some key-value pairs
    // tree.insert({1, 2, 3}, {10, 20, 30});
    // tree.insert({4, 5, 6}, {40, 50, 60});
    // tree.insert({2, 3, 4}, {20, 30, 40});
    //
    // // Print in-order
    // tree.inOrder();
    //
    // // Delete a key
    // tree.deleteKV({1, 2, 3});
    //
    //
    // // Print in-order after deletion
    // std::cout << "After deletion:" << std::endl;
    // tree.inOrder();


    // Define parameters
    std::string directory = "./tidesdb_data"; // The directory for storing data
    std::filesystem::perms directoryPerm = std::filesystem::perms::owner_all | std::filesystem::perms::group_read; // Permissions
    int memtableFlushSize = 10 * 1024; // Example flush size (10 KB)
    int compactionInterval = 5; // Example compaction interval (in seconds)
    int minimumSSTables = 2; // Minimum SSTables required

    try {
        // Initialize the LSMT
        auto lsmTree = TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize, compactionInterval, minimumSSTables);


        // Insert 20kb of data
        for (int i = 0; i < 20; i++) {
            std::vector<uint8_t> key(4, i);
            std::vector<uint8_t> value(1024, i);


            lsmTree->Put(key, value);
        }


        lsmTree->Close();




        // You can now use lsmTree to perform operations
    } catch (const std::exception& e) {
        std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
    }

    return 0;

}
