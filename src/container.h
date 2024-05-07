#pragma once
#include "aes.h"
#include <array>
#include <cstdint>
#include <fstream>
#include <memory>
#include <string>

#include "aes.h"

#define PQC_SYMMETRIC_CONTAINER_KEY_LENGTH 32
#define PQC_SYMMETRIC_CONTAINER_NUM_KEYS 6

#define PQC_SYMMETRIC_CONTAINER_MAX_USE_COUNT 1099511627776ull

class SymmetricKeyContainerFile
{
public:
    SymmetricKeyContainerFile(bool create_new, const char * server, const char * client, const char * device);
    SymmetricKeyContainerFile(bool create_new, const char * client_m, const char * client_k);

    bool read(uint8_t * data);
    bool write(const uint8_t * data);

    static std::string get_filename(const char * server, const char * client, const char * device);
    static std::string get_filename(const char * client_m, const char * client_k);

private:
    //	SymmetricKeyContainer _file;
    std::string _fileName;
    std::fstream _file;
};


const uint32_t SimmetricContainerCurrentVersion = 1;


class SymmetricKeyContainer
{
public:
    using Key = std::array<uint8_t, PQC_SYMMETRIC_CONTAINER_KEY_LENGTH>;

#pragma pack(push, 1)
    class KeyData
    {
    public:
        uint64_t use_count = PQC_SYMMETRIC_CONTAINER_MAX_USE_COUNT;
        uint32_t version = SimmetricContainerCurrentVersion;
        Key key;
    };
#pragma pack(pop)

public:
    SymmetricKeyContainer();
    SymmetricKeyContainer(const uint8_t * data, const pqc_aes_key * key, const pqc_aes_iv * iv);
    SymmetricKeyContainer(
        std::shared_ptr<SymmetricKeyContainerFile> file, std::shared_ptr<pqc_aes_key> key, std::shared_ptr<pqc_aes_iv> iv
    );

    static void set_container_path(const char * path);

    int get(int index, size_t encrypted_bytes, uint32_t cipher, uint32_t mechanism, const BufferView & key);

    static size_t data_size() { return sizeof(KeyData) * PQC_SYMMETRIC_CONTAINER_KEY_LENGTH; }

    void get_data(uint8_t * data, const pqc_aes_key * key, const pqc_aes_iv * iv);

    bool save_as(
        std::shared_ptr<SymmetricKeyContainerFile> file, std::shared_ptr<pqc_aes_key> key, std::shared_ptr<pqc_aes_iv> iv
    );

    uint32_t get_version() { return _data->version; };

private:
    int get(int index, uint64_t useCount, const BufferView & key);

    bool save();

    static void encrypt(KeyData * data, const pqc_aes_key & master_key, const pqc_aes_iv & iv);
    static void decrypt(KeyData * data, const pqc_aes_key & master_key, const pqc_aes_iv & iv);

    void mask(KeyData * data);
    void unmask(KeyData * data);
    void unmask(const BufferView & key, int index);

private:
    KeyData _data[PQC_SYMMETRIC_CONTAINER_NUM_KEYS];

    using Mask = StackBuffer<4096>;

    std::shared_ptr<Mask> _mask;

    std::shared_ptr<pqc_aes_key> _file_master_key;
    std::shared_ptr<pqc_aes_iv> _file_iv;
    std::shared_ptr<SymmetricKeyContainerFile> _file;
};
