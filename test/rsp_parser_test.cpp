#include <gtest/gtest.h>
#include <sstream>

#include "rsp_parser.h"

void PrintTo(const RSPValue & value, std::ostream * os) { *os << "(" << value.key_ << " = " << value.value_ << ")"; }

template <typename T> std::ostream & operator<<(std::ostream & stream, const std::vector<T> & v)
{
    stream << "[";
    for (size_t i = 0; i < v.size(); ++i)
    {
        stream << v[i];
        if (i != v.size() - 1)
        {
            stream << ", ";
        }
    }
    stream << "]";
    return stream;
}

std::ostream & operator<<(std::ostream & stream, const std::vector<uint8_t> & v)
{
    for (uint8_t value : v)
    {
        stream << std::setfill('0') << std::setw(2) << std::hex << (int)value;
    }
    return stream;
}

std::ostream & operator<<(std::ostream & stream, const AESRSPRecord & value)
{
    stream << "{key: " << value.key_ << ", iv: " << value.iv_ << ", plaintext: " << value.plaintext_
           << ", ciphertext: " << value.ciphertext_ << "}";
    return stream;
}

void PrintTo(const AESRSPRecord & value, std::ostream * os) { *os << value; }

void PrintTo(const AESRSPDataset & value, std::ostream * os)
{
    *os << "{encrypt: " << value.encrypt_ << ", decrypt: " << value.decrypt_ << "}";
}


TEST(RSP_PARSER, TEST_INIT)
{
    std::istringstream stream("123");
    RSPParser reader(stream);
    EXPECT_EQ(reader.current(), '1');
}

TEST(RSP_PARSER, TEST_EMPTY)
{
    std::istringstream stream("");
    RSPParser reader(stream);
    EXPECT_EQ(reader.current(), '\0');
}

class ParserSkipSpacesTestData
{
public:
    ParserSkipSpacesTestData(const char * input, char expected) : input_(input), expected_(expected) {}

    const char * input_;
    char expected_;
};

class RSPParserSkipSpacesTestSuite : public testing::TestWithParam<ParserSkipSpacesTestData>
{
};

TEST_P(RSPParserSkipSpacesTestSuite, TEST_SKIP_SPACES)
{
    ParserSkipSpacesTestData data = GetParam();

    std::istringstream stream(data.input_);

    RSPParser reader(stream);

    reader.skip_spaces();
    EXPECT_EQ(reader.current(), data.expected_);
}

INSTANTIATE_TEST_SUITE_P(
    RSP_PARSER, RSPParserSkipSpacesTestSuite,
    testing::Values(
        ParserSkipSpacesTestData("123", '1'), ParserSkipSpacesTestData("   123", '1'),
        ParserSkipSpacesTestData(" \n \t \r  123", '1'), ParserSkipSpacesTestData("", '\0')
    )
);


class ParserParseWordTestData
{
public:
    ParserParseWordTestData(const char * input, char expected_next_char, std::string expected_word)
        : input_(input), expected_next_char_(expected_next_char), expected_word_(expected_word)
    {
    }

    const char * input_;
    char expected_next_char_;
    std::string expected_word_;
};

class RSPParserParseWordTestSuite : public testing::TestWithParam<ParserParseWordTestData>
{
};

TEST_P(RSPParserParseWordTestSuite, TEST_PARSE_WORD)
{
    ParserParseWordTestData data = GetParam();

    std::istringstream stream(data.input_);

    RSPParser reader(stream);

    std::string actual = reader.parse_word();
    EXPECT_EQ(actual, data.expected_word_);
    EXPECT_EQ(reader.current(), data.expected_next_char_);
}

INSTANTIATE_TEST_SUITE_P(
    RSP_PARSER, RSPParserParseWordTestSuite,
    testing::Values(
        ParserParseWordTestData("123", '\0', "123"), ParserParseWordTestData("   123", ' ', ""),
        ParserParseWordTestData("abc def", ' ', "abc"), ParserParseWordTestData("fgh]", ']', "fgh"),
        ParserParseWordTestData("=", '=', "")
    )
);


class RSPParserParseCommentTestSuite : public testing::TestWithParam<ParserParseWordTestData>
{
};

TEST_P(RSPParserParseCommentTestSuite, TEST_PARSE_COMMENT)
{
    ParserParseWordTestData data = GetParam();

    std::istringstream stream(data.input_);

    RSPParser reader(stream);

    std::string actual = reader.parse_comment();
    EXPECT_EQ(actual, data.expected_word_);
    EXPECT_EQ(reader.current(), data.expected_next_char_);
}

INSTANTIATE_TEST_SUITE_P(
    RSP_PARSER, RSPParserParseCommentTestSuite,
    testing::Values(
        ParserParseWordTestData("# 123", '\0', "# 123"), ParserParseWordTestData("# 1 2 3\r\nabc", '\r', "# 1 2 3")
    )
);

TEST(RSP_PARSER, TEST_PARSE_HEADER)
{
    std::istringstream stream("[section]\r\n");
    RSPParser reader(stream);
    EXPECT_EQ(reader.parse_header(), std::string("section"));
    EXPECT_EQ(reader.current(), '\r');
}

TEST(RSP_PARSER, TEST_PARSE_EMPTY_HEADER)
{
    std::istringstream stream("[]\r\n");
    RSPParser reader(stream);
    EXPECT_THROW(reader.parse_header(), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_PARSE_INCOMPLETE_FILE_HEADER)
{
    std::istringstream stream("[no_end");
    RSPParser reader(stream);
    EXPECT_THROW(reader.parse_header(), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_PARSE_INCOMPLETE_LINE_HEADER)
{
    std::istringstream stream("[no_end\r\n");
    RSPParser reader(stream);
    EXPECT_THROW(reader.parse_header(), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_PARSE_VALUE)
{
    std::istringstream stream("name = 123\r\n");
    RSPParser reader(stream);
    EXPECT_EQ(reader.parse_value(), RSPValue("name", "123"));
    EXPECT_EQ(reader.current(), '\r');
}

TEST(RSP_PARSER, TEST_PARSE_VALUE_NO_EQUAL_SIGN)
{
    std::istringstream stream("name\r\n");
    RSPParser reader(stream);
    EXPECT_THROW(reader.parse_value(), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_PARSE_VALUE_NO_VALUE)
{
    std::istringstream stream("name =\r\n");
    RSPParser reader(stream);
    EXPECT_THROW(reader.parse_value(), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_PARSE_VALUE_EMPTY)
{
    std::istringstream stream("");
    RSPParser reader(stream);
    EXPECT_THROW(reader.parse_value(), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_STRING_2_INT)
{
    std::string str("123");
    EXPECT_EQ(RSPParser::string2int(str), 123);
}

TEST(RSP_PARSER, TEST_STRING_2_INT_EXTRA_CHAR)
{
    std::string str("123abc");
    EXPECT_THROW(RSPParser::string2int(str), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_STRING_2_INT_ONLY_CHAR)
{
    std::string str("abc");
    EXPECT_THROW(RSPParser::string2int(str), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_STRING_2_BINARY)
{
    std::string str("0123456789ABCDEFabcdef");
    EXPECT_EQ(
        RSPParser::string2binary(str),
        std::vector<uint8_t>({0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF})
    );
}

TEST(RSP_PARSER, TEST_STRING_2_BINARY_WRONG_LEN)
{
    std::string str("0A12fFF");
    EXPECT_THROW(RSPParser::string2binary(str), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_STRING_2_BINARY_WRONG_CHAR)
{
    std::string str("0A1GfF");
    EXPECT_THROW(RSPParser::string2binary(str), std::invalid_argument);
}

TEST(RSP_PARSER, TEST_AES_PARSE_BLOCK_ENCRYPT_ORDER)
{
    std::istringstream stream(
        "COUNT = 0\r\nKEY = 0000000000000000000000000000000000000000000000000000000000000000\r\nIV = "
        "014730f80ac625fe84f026c60bfd547d\r\nPLAINTEXT = 00\r\nCIPHERTEXT = 5c"
    );

    AESRSPRecord expected;
    expected.key_ = std::vector<uint8_t>(32, 0);
    expected.iv_ = std::vector<uint8_t>(
        {0x01, 0x47, 0x30, 0xf8, 0x0a, 0xc6, 0x25, 0xfe, 0x84, 0xf0, 0x26, 0xc6, 0x0b, 0xfd, 0x54, 0x7d}
    );
    expected.plaintext_ = std::vector<uint8_t>({0x00});
    expected.ciphertext_ = std::vector<uint8_t>({0x5C});

    AESRSPParser parser(stream);

    EXPECT_EQ(parser.parse_block(), expected);
}

TEST(RSP_PARSER, TEST_AES_PARSE_BLOCK_DECRYPT_ORDER)
{
    std::istringstream stream(
        "COUNT = 0\r\nKEY = 0000000000000000000000000000000000000000000000000000000000000000\r\nIV = "
        "014730f80ac625fe84f026c60bfd547d\r\nCIPHERTEXT = 5c\r\nPLAINTEXT = 00\r\n"
    );

    AESRSPRecord expected;
    expected.key_ = std::vector<uint8_t>(32, 0);
    expected.iv_ = std::vector<uint8_t>(
        {0x01, 0x47, 0x30, 0xf8, 0x0a, 0xc6, 0x25, 0xfe, 0x84, 0xf0, 0x26, 0xc6, 0x0b, 0xfd, 0x54, 0x7d}
    );
    expected.plaintext_ = std::vector<uint8_t>({0x00});
    expected.ciphertext_ = std::vector<uint8_t>({0x5C});

    AESRSPParser parser(stream);

    EXPECT_EQ(parser.parse_block(), expected);
}

TEST(RSP_PARSER, TEST_AES_PARSE_BLOCK_NO_IV)
{
    std::istringstream stream(
        "COUNT = 0\r\nKEY = 0000000000000000000000000000000000000000000000000000000000000000\r\nPLAINTEXT = "
        "00\r\nCIPHERTEXT = 5c"
    );

    AESRSPRecord expected;
    expected.key_ = std::vector<uint8_t>(32, 0);
    expected.plaintext_ = std::vector<uint8_t>({0x00});
    expected.ciphertext_ = std::vector<uint8_t>({0x5C});

    AESRSPParser parser(stream);

    EXPECT_EQ(parser.parse_block(), expected);
}


TEST(RSP_PARSER, TEST_AES_PARSE_DATASET)
{
    std::istringstream stream(
        "# CAVS 11.1\r\n# Config info for aes_values\r\n# AESVS GFSbox test data for CFB8\r\n# State : Encrypt and "
        "Decrypt\r\n# Key Length : 256\r\n# Generated on Fri Apr 22 15:11 : 50 2011\r\n\r\n"
        "[ENCRYPT]\r\n\r\n"
        "COUNT = 0\r\nKEY = 0000000000000000000000000000000000000000000000000000000000000000\r\nIV = "
        "014730f80ac625fe84f026c60bfd547d\r\nPLAINTEXT = 00\r\nCIPHERTEXT = 5c\r\n\r\n"
        "COUNT = 1\r\nKEY = 0000000000000000000000000000000000000000000000000000000000000000\r\nIV = "
        "0b24af36193ce4665f2825d7b4749c98\r\nPLAINTEXT = 00\r\nCIPHERTEXT = a9\r\n\r\n"
        "[DECRYPT]\r\n\r\n"
        "COUNT = 0\r\nKEY = 0000000000000000000000000000000000000000000000000000000000000000\r\nIV = "
        "8a560769d605868ad80d819bdba03771\r\nCIPHERTEXT = 38\r\nPLAINTEXT = 00\r\n\r\n"
        "COUNT = 1\r\nKEY = 0000000000000000000000000000000000000000000000000000000000000000\r\nIV = "
        "91fbef2d15a97816060bee1feaa49afe\r\nCIPHERTEXT = 1b\r\nPLAINTEXT = 00\r\n\r\n"
    );

    AESRSPDataset expected;
    expected.encrypt_ = std::vector<AESRSPRecord>(
        {AESRSPRecord(
             std::vector<uint8_t>(32, 0),
             std::vector<uint8_t>(
                 {0x01, 0x47, 0x30, 0xf8, 0x0a, 0xc6, 0x25, 0xfe, 0x84, 0xf0, 0x26, 0xc6, 0x0b, 0xfd, 0x54, 0x7d}
             ),
             std::vector<uint8_t>({0x00}), std::vector<uint8_t>({0x5C})
         ),
         AESRSPRecord(
             std::vector<uint8_t>(32, 0),
             std::vector<uint8_t>(
                 {0x0b, 0x24, 0xaf, 0x36, 0x19, 0x3c, 0xe4, 0x66, 0x5f, 0x28, 0x25, 0xd7, 0xb4, 0x74, 0x9c, 0x98}
             ),
             std::vector<uint8_t>({0x00}), std::vector<uint8_t>({0xa9})
         )}
    );

    expected.decrypt_ = std::vector<AESRSPRecord>(
        {AESRSPRecord(
             std::vector<uint8_t>(32, 0),
             std::vector<uint8_t>(
                 {0x8a, 0x56, 0x07, 0x69, 0xd6, 0x05, 0x86, 0x8a, 0xd8, 0x0d, 0x81, 0x9b, 0xdb, 0xa0, 0x37, 0x71}
             ),
             std::vector<uint8_t>({0x00}), std::vector<uint8_t>({0x38})
         ),
         AESRSPRecord(
             std::vector<uint8_t>(32, 0),
             std::vector<uint8_t>(
                 {0x91, 0xfb, 0xef, 0x2d, 0x15, 0xa9, 0x78, 0x16, 0x06, 0x0b, 0xee, 0x1f, 0xea, 0xa4, 0x9a, 0xfe}
             ),
             std::vector<uint8_t>({0x00}), std::vector<uint8_t>({0x1b})
         )}
    );

    AESRSPParser parser(stream);

    EXPECT_EQ(parser.parse(), expected);
}