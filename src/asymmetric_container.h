#pragma once
#include "aes.h"
#include <fstream>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>


const int OIDnumbers = 10;

#pragma pack(push, 1)
struct DataAsymmetricContainer
{
    uint32_t version;
    uint32_t AlgType;
    // uint32_t length;
    uint32_t OID[OIDnumbers];
    std::vector<uint8_t> KeyBytes; // first ALLWAYS public key; second ALLWAYS secret key
};
#pragma pack(pop)

class AsymmetricContainerFile
{
public:
    AsymmetricContainerFile(
        uint32_t algType, bool create_new, const char * server, const char * client, const char * device
    );
    size_t data_size();
    bool read(uint32_t cipher, uint8_t * data);
    bool write(uint32_t cipher, const uint8_t * data);

    uint32_t cipher;

    static std::string get_filename(const char * server, const char * client, const char * device);
    static std::string get_filename(const char * client_m, const char * client_k);

private:
    std::string _fileName;
    std::fstream _file;
};

const uint32_t AsymmetricContainerCurrentVersion = 1;

class AsymmetricContainer
{
public:
    int asymmetricContainerValid;
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

private:
    struct DataAsymmetricContainer data;
};
