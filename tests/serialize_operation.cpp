#include <gtest/gtest.h>

#include "../libtidesdb.hpp"  // Include the header where serializeOperation is declared

// Test case for serializeOperation
TEST(SerializeOperationTest, HandlesValidOperation) {
    Operation op;
    op.set_type(OperationType::OpPut);
    op.set_key("test_key");
    op.set_value("test_value");

    std::vector<uint8_t> serialized = TidesDB::serializeOperation(op);
    Operation deserializedOp = TidesDB::deserializeOperation(serialized);

    EXPECT_EQ(deserializedOp.type(), op.type());
    EXPECT_EQ(deserializedOp.key(), op.key());
    EXPECT_EQ(deserializedOp.value(), op.value());
}

TEST(SerializeOperationTest, HandlesEmptyOperation) {
    Operation op;

    EXPECT_THROW({ std::vector<uint8_t> serialized = TidesDB::serializeOperation(op); },
                 TidesDB::TidesDBException);
}