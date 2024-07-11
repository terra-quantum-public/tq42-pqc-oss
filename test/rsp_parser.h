#include <cstdint>
#include <iostream>
#include <vector>

class RSPValue
{
public:
    RSPValue(const std::string & key, const std::string & value) : key_(key), value_(value) {}
    std::string key_;
    std::string value_;

    bool operator==(const RSPValue & other) const;
};

class RSPParser
{
public:
    RSPParser(std::istream & input) : input_(input) { next(); }

    void skip_spaces();
    char current() { return current_; }
    std::string parse_word();
    std::string parse_comment();
    std::string parse_header();
    RSPValue parse_value();
    std::string expect_value(const std::string & key);

    static int string2int(const std::string & str);
    static std::vector<uint8_t> string2binary(const std::string & str);

private:
    void next();

    char current_ = '\0';
    std::istream & input_;
};

class AESRSPRecord
{
public:
    AESRSPRecord() {}
    AESRSPRecord(
        const std::vector<uint8_t> & key, const std::vector<uint8_t> & iv, const std::vector<uint8_t> & plaintext,
        const std::vector<uint8_t> & ciphertext
    )
        : key_(key), iv_(iv), plaintext_(plaintext), ciphertext_(ciphertext)
    {
    }

    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;
    std::vector<uint8_t> plaintext_;
    std::vector<uint8_t> ciphertext_;

    bool operator==(const AESRSPRecord & other) const
    {
        return key_ == other.key_ && iv_ == other.iv_ && plaintext_ == other.plaintext_ &&
               ciphertext_ == other.ciphertext_;
    }
};

class AESRSPDataset
{
public:
    std::vector<AESRSPRecord> encrypt_;
    std::vector<AESRSPRecord> decrypt_;

    bool operator==(const AESRSPDataset & other) const
    {
        return encrypt_ == other.encrypt_ && decrypt_ == other.decrypt_;
    }
};

class AESRSPParser : private RSPParser
{
public:
    AESRSPParser(std::istream & input) : RSPParser(input) {}

    AESRSPRecord parse_block();

    AESRSPDataset parse();
};
