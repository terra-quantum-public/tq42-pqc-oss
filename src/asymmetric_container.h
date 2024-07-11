#pragma once
#include "aes.h"
#include <fstream>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>


const int OIDnumbers = 10;
const uint32_t PQC_ASYMMETRIC_CONTAINER_VERSION = 1;
const uint64_t PQC_ASYMMETRIC_CONTAINER_EXPIRATION_TIME = 365 * 24 * 3600;

#pragma pack(push, 1)
struct DataAsymmetricContainer
{
    uint32_t version;
    uint32_t AlgType;
    uint32_t OID[OIDnumbers];
    uint64_t creation_ts;
    std::vector<uint8_t> KeyBytes; // always first is public key, second is secret key
};
#pragma pack(pop)

class AsymmetricContainerFile
{
public:
    AsymmetricContainerFile(uint32_t algType, bool create_new, const char * filename);
    bool read(uint32_t cipher, uint8_t * data);
    bool write(uint32_t cipher, const uint8_t * data);

    uint32_t cipher;

private:
    std::string _fileName;
    std::fstream _file;
};


class AsymmetricContainer
{
public:
    AsymmetricContainer(uint32_t algType);
    AsymmetricContainer(uint32_t algType, uint8_t * container_data, const pqc_aes_key * key, const pqc_aes_iv * iv);
    size_t data_size();
    void get_data(uint8_t * destinationData, const pqc_aes_key * key, const pqc_aes_iv * iv);
    size_t put_keys_inside(uint8_t * pk, uint8_t * sk, size_t pkLength, size_t skLength, uint32_t algtype);
    size_t get_keys(uint8_t * pk, uint8_t * sk, size_t pkLength, size_t skLength, uint32_t algtype);
    int save_as(
        std::shared_ptr<AsymmetricContainerFile> file, std::shared_ptr<pqc_aes_key> key, std::shared_ptr<pqc_aes_iv> iv
    );

    uint32_t get_version() { return data.version; }

    uint64_t get_creation_ts() { return data.creation_ts; }

    uint64_t get_expiration_ts() { return data.creation_ts + PQC_ASYMMETRIC_CONTAINER_EXPIRATION_TIME; }

private:
    struct DataAsymmetricContainer data;
};
