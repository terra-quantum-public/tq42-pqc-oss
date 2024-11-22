#pragma once
#include <array>
#include <cstdint>
#include <fstream>
#include <memory>
#include <string>

#include "aes.h"
#include "rng/random_generator.h"

#define PQC_SYMMETRIC_CONTAINER_KEY_LENGTH 32
#define PQC_SYMMETRIC_CONTAINER_NUM_KEYS 6

#define PQC_SYMMETRIC_CONTAINER_MAX_USE_COUNT 1099511627776ull

const uint32_t PQC_SYMMETRIC_CONTAINER_VERSION = 1;
const uint64_t PQC_SYMMETRIC_CONTAINER_EXPIRATION_TIME = 365 * 24 * 3600;

class SymmetricKeyContainerFile
{
public:
    SymmetricKeyContainerFile(bool create_new, const char * filename);

    bool read(uint8_t * data);
    bool write(const uint8_t * data);

private:
    std::string _fileName;
    std::fstream _file;
};


class SymmetricKeyContainer
{
public:
    using Key = std::array<uint8_t, PQC_SYMMETRIC_CONTAINER_KEY_LENGTH>;

#pragma pack(push, 1)
    class KeyData
    {
    public:
        uint64_t use_count = PQC_SYMMETRIC_CONTAINER_MAX_USE_COUNT;
        Key key;
    };
#pragma pack(pop)

#pragma pack(push, 1)
    struct SymmetricKeyContainerData
    {
        uint32_t version = PQC_SYMMETRIC_CONTAINER_VERSION;
        uint64_t creation_ts;
        KeyData key_data[PQC_SYMMETRIC_CONTAINER_NUM_KEYS];
    };
#pragma pack(pop)

public:
    SymmetricKeyContainer(IRandomGenerator * rng);
    SymmetricKeyContainer(const uint8_t * data, const pqc_aes_key * key, const pqc_aes_iv * iv, IRandomGenerator * rng);
    SymmetricKeyContainer(
        std::shared_ptr<SymmetricKeyContainerFile> file, std::shared_ptr<pqc_aes_key> key,
        std::shared_ptr<pqc_aes_iv> iv, IRandomGenerator * rng
    );

    int get(int index, size_t encrypted_bytes, uint32_t cipher, uint32_t mode, const BufferView & key);

    static size_t data_size() { return sizeof(SymmetricKeyContainerData); }

    void get_data(uint8_t * data, const pqc_aes_key * key, const pqc_aes_iv * iv);

    bool save_as(
        std::shared_ptr<SymmetricKeyContainerFile> file, std::shared_ptr<pqc_aes_key> key,
        std::shared_ptr<pqc_aes_iv> iv
    );

    uint32_t get_version() { return _data.version; }

    uint64_t get_creation_ts() { return _data.creation_ts; }

    uint64_t get_expiration_ts() { return _data.creation_ts + PQC_SYMMETRIC_CONTAINER_EXPIRATION_TIME; }

private:
    int get(int index, uint64_t useCount, const BufferView & key);

    bool save();

    static void encrypt(SymmetricKeyContainerData * data, const pqc_aes_key & master_key, const pqc_aes_iv & iv);
    static void decrypt(SymmetricKeyContainerData * data, const pqc_aes_key & master_key, const pqc_aes_iv & iv);

    void mask(SymmetricKeyContainerData * data);
    void unmask(SymmetricKeyContainerData * data);
    void unmask(const BufferView & key, int index);

private:
    SymmetricKeyContainerData _data;

    using Mask = StackBuffer<4096>;

    std::shared_ptr<Mask> _mask;

    std::shared_ptr<pqc_aes_key> _file_master_key;
    std::shared_ptr<pqc_aes_iv> _file_iv;
    std::shared_ptr<SymmetricKeyContainerFile> _file;
};
