#include <gtest/gtest.h>
#include <pqc/delete.h>

#include <fstream>

TEST(FileDelete, input_size_less_than_AES_BLOCKLEN)
{
    const char * filename = "input_size_less_than_AES_BLOCKLEN.txt";
    std::ofstream MyFile(filename);
    MyFile << "-123456789012abc";
    MyFile.close();

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";

    EXPECT_EQ(PQC_file_delete(context, filename), PQC_OK) << "file remove should return OK";

    PQC_context_close(context);

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

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";

    EXPECT_EQ(PQC_file_delete(context, filename), PQC_OK) << "file remove should return OK";

    PQC_context_close(context);

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

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";

    EXPECT_EQ(PQC_file_delete(context, filename), PQC_OK) << "file remove should return OK";

    PQC_context_close(context);

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

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    EXPECT_NE(context, PQC_BAD_CONTEXT) << "Context intialization should pass";

    EXPECT_EQ(PQC_file_delete(context, filename), PQC_IO_ERROR);

    PQC_context_close(context);
}
