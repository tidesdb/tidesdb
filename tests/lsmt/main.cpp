#include "../../library.h"
#include <iostream>

int main() {
  // Define parameters
  std::string directory = "./tidesdb_data"; // The directory for storing data
  std::filesystem::perms directoryPerm =
      std::filesystem::perms::owner_all |
      std::filesystem::perms::group_read; // Permissions
  int memtableFlushSize = 10 * 1024;      // Example flush size (10 KB)

    // compaction interval is
  int compactionInterval = 8;
  int minimumSSTables = 2; // Minimum SSTables required

  try {
    // Initialize the LSMT
    auto lsmTree =
        TidesDB::LSMT::New(directory, directoryPerm, memtableFlushSize,
                           compactionInterval, minimumSSTables);

    // Insert 20kb of data
    for (int i = 0; i < 20; i++) {
      std::vector<uint8_t> key(4, i);
      std::vector<uint8_t> value(1024, i);

      lsmTree->Put(key, value);
    }

    // Get key 5555
    std::vector<uint8_t> key(4, 5);

    std::vector<uint8_t> dat = lsmTree->Get(key);

    if (dat.size() == 0) {
      std::cerr << "Key not found Get test failed" << std::endl;
    } else {
      std::cout << "Key found Get test past" << std::endl;
    }

    // Delete key 5555
    if (lsmTree->Delete(key)) {
      std::cout << "Key deleted Delete test past" << std::endl;
    } else {
      std::cerr << "Key not found Delete test failed" << std::endl;
    }

    // Check if key 5555 is deleted
    dat = lsmTree->Get(key);

    if (dat.size() == 0) {
      std::cout << "Key not found delete then get test past" << std::endl;
    } else {
      std::cerr << "Key found delete get then test failed" << std::endl;
    }

    lsmTree->Close();

    // Remove the directory
    std::filesystem::remove_all(directory);

    return 0;

  } catch (const std::exception &e) {
    std::cerr << "Error initializing LSMT: " << e.what() << std::endl;
  }
}
