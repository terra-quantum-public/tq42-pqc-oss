#include "rsp_parser.h"

#include <string>

void RSPParser::skip_spaces()
{
    while (current() && std::isspace(current()))
    {
        next();
    }
}

void RSPParser::skip_inline_spaces()
{
    while (current() && std::isspace(current()) && current() != '\r' && current() != '\n')
    {
        next();
    }
}

std::string RSPParser::parse_word()
{
    std::string word;
    for (; std::isalnum(current()); next())
    {
        word += current();
    }
    return word;
}

std::string RSPParser::parse_comment()
{
    std::string result;
    for (; current() != '\0' && current() != '\r' && current() != '\n'; next())
    {
        result += current();
    }
    return result;
}

std::string RSPParser::parse_header()
{
    if (current() != '[')
    {
        throw std::invalid_argument("expected '[' not found");
    }
    next();
    std::string header = parse_word();
    if (header.length() == 0)
    {
        throw std::invalid_argument("Empty section header (empty '[]')");
    }
    if (current() != ']')
    {
        throw std::invalid_argument("expected ']' not found");
    }
    next();
    return header;
}

RSPValue RSPParser::parse_header_value()
{
    if (current() != '[')
    {
        throw std::invalid_argument("expected '[' not found");
    }
    next();
    RSPValue value = parse_value();
    if (current() != ']')
    {
        throw std::invalid_argument("expected ']' not found");
    }
    next();
    return value;
}

RSPValue RSPParser::parse_value()
{
    std::string key, value;

    key = parse_word();

    skip_inline_spaces();

    if (current_ != '=')
    {
        throw std::invalid_argument("expected '=' not found");
    }
    next();

    skip_inline_spaces();

    value = parse_word();

    if (key.length() == 0)
    {
        throw std::invalid_argument("malformed data string");
    }

    return RSPValue(key, value);
}

std::string RSPParser::expect_value(const std::string & key)
{
    RSPValue value = parse_value();

    if (value.key_ != key)
    {
        throw std::invalid_argument(std::string("expected ") + key + " not found.");
    }

    return value.value_;
}

int RSPParser::string2int(const std::string & str)
{
    std::size_t pos{};
    int val = std::stoi(str, &pos);
    if (pos != str.length())
    {
        throw std::invalid_argument("non-digit characters where digit is expected");
    }
    return val;
}

static inline uint8_t char2int(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    throw std::invalid_argument("invalid character in what is expected to be hex string");
}

std::vector<uint8_t> RSPParser::string2binary(const std::string & str)
{
    std::vector<uint8_t> result;

    if (str.length() % 2 != 0)
    {
        throw std::invalid_argument("hex string should be of even size");
    }

    result.reserve(str.length() / 2);

    for (auto i = str.cbegin(); i != str.cend(); ++i)
    {
        result.push_back(char2int(*i) * 0x10 + char2int(*(++i)));
    }

    return result;
}

void RSPParser::next()
{
    input_.get(current_);
    if (!input_.good())
    {
        current_ = '\0';
    }
}

bool RSPValue::operator==(const RSPValue & other) const { return key_ == other.key_ && value_ == other.value_; }

AESRSPRecord AESRSPParser::parse_block()
{
    AESRSPRecord result;

    expect_value("COUNT");
    skip_spaces();
    result.key_ = string2binary(expect_value("KEY"));
    skip_spaces();
    if (current() == 'I')
    {
        result.iv_ = string2binary(expect_value("IV"));
        skip_spaces();
    }
    if (current() == 'P')
    {
        result.plaintext_ = string2binary(expect_value("PLAINTEXT"));
        skip_spaces();
        result.ciphertext_ = string2binary(expect_value("CIPHERTEXT"));
    }
    else
    {
        result.ciphertext_ = string2binary(expect_value("CIPHERTEXT"));
        skip_spaces();
        result.plaintext_ = string2binary(expect_value("PLAINTEXT"));
    }

    return result;
}

AESRSPDataset AESRSPParser::parse()
{
    AESRSPDataset dataset;
    std::string section;

    skip_spaces();

    while (current() != '\0')
    {
        if (current() == '#')
        {
            parse_comment();
        }
        else if (current() == '[')
        {
            section = parse_header();
            if (section != "ENCRYPT" && section != "DECRYPT")
            {
                throw std::invalid_argument("Unexpected section " + section);
            }
        }
        else
        {
            AESRSPRecord record = parse_block();
            if (section == "ENCRYPT")
            {
                dataset.encrypt_.push_back(record);
            }
            else if (section == "DECRYPT")
            {
                dataset.decrypt_.push_back(record);
            }
            else
            {
                throw std::invalid_argument("Data outside of ENCRYPT/DECRYPT sections.");
            }
        }

        skip_spaces();
    }
    return dataset;
}

AESGCMRSPRecord AESGCMRSPParser::parse_block()
{
    AESGCMRSPRecord result;

    expect_value("Count");
    skip_spaces();
    result.key_ = string2binary(expect_value("Key"));
    skip_spaces();
    if (current() == 'I')
    {
        result.iv_ = string2binary(expect_value("IV"));
        skip_spaces();
    }
    if (current() == 'P')
    {
        result.plaintext_ = string2binary(expect_value("PT"));
        skip_spaces();
        result.aad_ = string2binary(expect_value("AAD"));
        skip_spaces();
        result.ciphertext_ = string2binary(expect_value("CT"));
        skip_spaces();
        result.tag_ = string2binary(expect_value("Tag"));
    }
    else
    {
        result.ciphertext_ = string2binary(expect_value("CT"));
        skip_spaces();
        result.aad_ = string2binary(expect_value("AAD"));
        skip_spaces();
        result.tag_ = string2binary(expect_value("Tag"));
        skip_spaces();
        if (current() == 'P')
        {
            result.plaintext_ = string2binary(expect_value("PT"));
        }
        else
        {
            if (parse_word() != "FAIL")
            {
                throw std::invalid_argument("expected 'PT' or 'FAIL'");
            }
            result.fail_ = true;
        }
    }

    return result;
}

AESGCMRSPDataset AESGCMRSPParser::parse()
{
    AESGCMRSPDataset dataset;

    skip_spaces();

    while (current() != '\0')
    {
        if (current() == '#')
        {
            parse_comment();
        }
        else if (current() == '[')
        {
            parse_header_value();
        }
        else
        {
            AESGCMRSPRecord record = parse_block();
            dataset.push_back(record);
        }

        skip_spaces();
    }
    return dataset;
}