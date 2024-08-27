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
    void skip_inline_spaces();
    char current() { return current_; }
    std::string parse_word();
    std::string parse_comment();
    std::string parse_header();
    RSPValue parse_header_value();
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

class AESGCMRSPRecord
{
public:
    AESGCMRSPRecord() {}
    AESGCMRSPRecord(
        const std::vector<uint8_t> & key, const std::vector<uint8_t> & iv, const std::vector<uint8_t> & plaintext,
        const std::vector<uint8_t> & ciphertext, const std::vector<uint8_t> & aad, const std::vector<uint8_t> tag,
        bool fail
    )
        : key_(key), iv_(iv), plaintext_(plaintext), ciphertext_(ciphertext), aad_(aad), tag_(tag), fail_(fail)
    {
    }

    std::vector<uint8_t> key_;
    std::vector<uint8_t> iv_;
    std::vector<uint8_t> plaintext_;
    std::vector<uint8_t> ciphertext_;
    std::vector<uint8_t> aad_;
    std::vector<uint8_t> tag_;
    bool fail_ = false;


    bool operator==(const AESGCMRSPRecord & other) const
    {
        return key_ == other.key_ && iv_ == other.iv_ && plaintext_ == other.plaintext_ &&
               ciphertext_ == other.ciphertext_ && aad_ == other.aad_ && tag_ == other.tag_ && fail_ == other.fail_;
    }
};

using AESGCMRSPDataset = std::vector<AESGCMRSPRecord>;

class AESGCMRSPParser : private RSPParser
{
public:
    AESGCMRSPParser(std::istream & input) : RSPParser(input) {}

    AESGCMRSPRecord parse_block();

    AESGCMRSPDataset parse();
};
