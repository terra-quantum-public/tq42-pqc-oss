#include <gtest/gtest.h>
#include <pqc/delete.h>

#include <fstream>

TEST(FileDelete, input_size_less_than_AES_BLOCKLEN)
{
    const char * filename = "input_size_less_than_AES_BLOCKLEN.txt";
    std::ofstream MyFile(filename);
    MyFile << "-123456789012abc";
    MyFile.close();

    PQC_file_delete(filename);

    std::ifstream iff(filename);

    int result = 1;
    if (iff.fail())
        result = 0;

    EXPECT_NE(result, 1) << "file still exists";

    iff.close();
}

TEST(FileDelete, input_size_multiple_AES_BLOCKLEN)
{
    const char * filename = "input_size_multiple_AES_BLOCKLEN.txt";
    std::ofstream MyFile(filename);
    MyFile << "-123456789012345-123456789012345-123456789012abc-123456789012abc-123456789012abc-123456789012abc-"
              "123456789012abc-123456789012abc";
    MyFile.close();

    PQC_file_delete(filename);

    std::ifstream iff(filename);

    int result = 1;
    if (iff.fail())
        result = 0;

    EXPECT_NE(result, 1) << "file still exists";

    iff.close();
}


TEST(FileDelete, input_size_bigger_not_multiple_AES_BLOCKLEN)
{
    const char * filename = "input_size_bigger_not_multiple_AES_BLOCKLEN.txt";
    std::ofstream MyFile(filename);
    MyFile << "-123456789012345-123456789012345-123456789012abc-123456789012abc-123456789012abc-123456789012abc-"
              "123456789012abc-123456789012abcqwerty";
    MyFile.close();

    PQC_file_delete(filename);

    std::ifstream iff(filename);

    int result = 1;
    if (iff.fail())
        result = 0;

    EXPECT_NE(result, 1) << "file still exists";

    iff.close();
}

TEST(FileDelete, BadInput)
{
    const char * filename = "BadInput.txt";

    EXPECT_EQ(PQC_file_delete(filename), PQC_IO_ERROR);
}
