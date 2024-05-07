#include <cstring>
#include <fstream>
#include <string>

#include <pqc/aes.h>
#include <pqc/sha3.h>

#include <aes.h>
#include <buffer.h>
#include <container.h>
#include <rng/rng.h>
#include <sha3.h>


static std::string containerDirectory;

SymmetricKeyContainer::SymmetricKeyContainer()
{
    for (int i = 0; i < PQC_SYMMETRIC_CONTAINER_NUM_KEYS; ++i)
    {
        randombytes(_data[i].key);
    }

    _mask = std::make_shared<Mask>();
    randombytes(*_mask);

    mask(_data);
}

SymmetricKeyContainer::SymmetricKeyContainer(const uint8_t * data, const pqc_aes_key * key, const pqc_aes_iv * iv)
{
    memcpy(_data, data, sizeof(_data));
    decrypt(_data, *key, *iv);

    _mask = std::make_shared<Mask>();
    randombytes(*_mask);

    mask(_data);
}

SymmetricKeyContainer::SymmetricKeyContainer(
    std::shared_ptr<SymmetricKeyContainerFile> file, std::shared_ptr<pqc_aes_key> key, std::shared_ptr<pqc_aes_iv> iv
)
    : _file_master_key(key), _file_iv(iv), _file(file)
{
    file->read(reinterpret_cast<uint8_t *>(_data));
    decrypt(_data, *key, *iv);

    _mask = std::make_shared<Mask>();
    randombytes(*_mask);

    mask(_data);
}

void SymmetricKeyContainer::set_container_path(const char * path) { containerDirectory = path; }

void SymmetricKeyContainer::get_data(uint8_t * data, const pqc_aes_key * key, const pqc_aes_iv * iv)
{
    memcpy(data, _data, sizeof(_data));
    unmask(reinterpret_cast<KeyData *>(data));
    encrypt(reinterpret_cast<KeyData *>(data), *key, *iv);
}

bool SymmetricKeyContainer::save_as(
    std::shared_ptr<SymmetricKeyContainerFile> file, std::shared_ptr<pqc_aes_key> key, std::shared_ptr<pqc_aes_iv> iv
)
{
    _file = file;
    _file_master_key = key;
    _file_iv = iv;
    return save();
}

int SymmetricKeyContainer::get(int index, uint64_t useCount, const BufferView & key)
{
    if (index < 0 || index >= PQC_SYMMETRIC_CONTAINER_NUM_KEYS)
    {
        return PQC_BAD_CONTAINER;
    }

    if (key.size() != PQC_SYMMETRIC_CONTAINER_KEY_LENGTH)
    {
        return PQC_BAD_LEN;
    }

    if (_data[index].use_count < useCount)
    {
        return PQC_CONTAINER_DEPLETED;
    }

    _data[index].use_count -= useCount;

    key.store(_data[index].key);
    unmask(key, index);
    return PQC_OK;
}

bool SymmetricKeyContainer::save()
{
    if (!_file || !_file_master_key || !_file_iv)
    {
        return !_file;
    }

    unmask(_data);

    encrypt(_data, *_file_master_key, *_file_iv);

    _file->write(reinterpret_cast<const uint8_t *>(_data));

    decrypt(_data, *_file_master_key, *_file_iv);
    mask(_data);

    return true;
}

void SymmetricKeyContainer::encrypt(KeyData * data, const pqc_aes_key & master_key, const pqc_aes_iv & iv)
{
    for (int key = 0; key < PQC_SYMMETRIC_CONTAINER_NUM_KEYS; ++key)
    {
        SHA3 hash(PQC_SHA3_256);
        hash.add_data(ConstBufferView(master_key.key, PQC_AES_KEYLEN));
        hash.add_data(ConstBufferView::from_single(key));

        pqc_aes_key local_key = {0};
        memcpy(&local_key, hash.get_hash(), std::min((int)hash.hash_size(), PQC_AES_KEYLEN));

        AES cipher(&local_key, &iv);
        BufferView dataBuf = BufferView(reinterpret_cast<uint8_t *>(&data[key]), sizeof(KeyData));
        cipher.ofb_xcrypt(dataBuf);
    }
}

void SymmetricKeyContainer::decrypt(KeyData * data, const pqc_aes_key & master_key, const pqc_aes_iv & iv)
{
    for (int key = 0; key < PQC_SYMMETRIC_CONTAINER_NUM_KEYS; ++key)
    {
        SHA3 hash(PQC_SHA3_256);
        hash.add_data(ConstBufferView(master_key.key, PQC_AES_KEYLEN));
        hash.add_data(ConstBufferView::from_single(key));

        pqc_aes_key local_key = {0};
        memcpy(&local_key, hash.get_hash(), std::min((int)hash.hash_size(), PQC_AES_KEYLEN));

        AES cipher(&local_key, &iv);
        BufferView dataBuf = BufferView(reinterpret_cast<uint8_t *>(&data[key]), sizeof(KeyData));
        cipher.ofb_xcrypt(dataBuf);
    }
}

void SymmetricKeyContainer::mask(KeyData * data)
{
    for (int i = 0; i < PQC_SYMMETRIC_CONTAINER_NUM_KEYS; ++i)
    {
        unmask(data[i].key, i);
    }
}

void SymmetricKeyContainer::unmask(KeyData * data)
{
    for (int i = 0; i < PQC_SYMMETRIC_CONTAINER_NUM_KEYS; ++i)
    {
        unmask(data[i].key, i);
    }
}

void SymmetricKeyContainer::unmask(const BufferView & key, int index)
{
#ifndef NDEBUG
    if (key.size() != PQC_SYMMETRIC_CONTAINER_KEY_LENGTH)
    {
        throw std::invalid_argument("SymmetricKeyContainer::unmask() called with wrong buffer size");
    }
#endif // _DEBUG

    for (int i = 0; i < PQC_SYMMETRIC_CONTAINER_KEY_LENGTH; ++i)
    {
        key[i] ^= (*_mask)[index * PQC_SYMMETRIC_CONTAINER_KEY_LENGTH + i];
    }
}

SymmetricKeyContainerFile::SymmetricKeyContainerFile(
    bool create_new, const char * server, const char * client, const char * device
)
    : _fileName(get_filename(server, client, device))
{
    if (create_new)
        _file.open(_fileName, _file.out | _file.binary);
    else
        _file.open(_fileName, _file.in | _file.out | _file.binary);

    if (!_file.is_open())
    {
        throw std::ios_base::failure("failed to open container file");
    }
}

SymmetricKeyContainerFile::SymmetricKeyContainerFile(bool create_new, const char * client_m, const char * client_k)
    : _fileName(get_filename(client_m, client_k))
{
    if (create_new)
        _file.open(_fileName, _file.out | _file.binary);
    else
        _file.open(_fileName, _file.in | _file.out | _file.binary);

    if (!_file.is_open())
    {
        throw std::ios_base::failure("failed to open container file");
    }
}

bool SymmetricKeyContainerFile::read(uint8_t * data)
{
    _file.seekg(0);
    _file.read(
        reinterpret_cast<char *>(data), sizeof(SymmetricKeyContainer::KeyData) * PQC_SYMMETRIC_CONTAINER_NUM_KEYS
    );

    if (!_file.good())
    {
        throw std::ios_base::failure("failed to read container file");
    }
    return false;
}

bool SymmetricKeyContainerFile::write(const uint8_t * data)
{
    _file.seekp(0);
    _file.write(
        reinterpret_cast<const char *>(data), sizeof(SymmetricKeyContainer::KeyData) * PQC_SYMMETRIC_CONTAINER_NUM_KEYS
    );

    if (!_file.good())
    {
        throw std::ios_base::failure("failed to write container file");
    }
    return true;
}

int SymmetricKeyContainer::get(
    int index, size_t encrypted_bytes, uint32_t cipher, uint32_t mechanism, const BufferView & key
)
{
    uint64_t useCount;

    if (cipher != PQC_CIPHER_AES)
    {
        return static_cast<int>(PQC_BAD_CIPHER);
    }

    switch (mechanism)
    {
    case PQC_AES_M_ECB:
        useCount = PQC_SYMMETRIC_CONTAINER_MAX_USE_COUNT;
        break;

    case PQC_AES_M_CBC:
        useCount = encrypted_bytes * 2;
        break;

    case PQC_AES_M_OFB:
        useCount = encrypted_bytes;
        break;

    default:
        return PQC_BAD_MECHANISM;
    }

    int result = get(index, useCount, key);

    if (result != PQC_OK)
    {
        return result;
    }

    if (result != PQC_OK)
    {
        return result;
    }

    if (!save())
        return PQC_IO_ERROR;

    return PQC_OK;
}

std::string SymmetricKeyContainerFile::get_filename(const char * server, const char * client, const char * device)
{
    return std::string(server) + "-" + client + "-" + device + ".qkey";
}

std::string SymmetricKeyContainerFile::get_filename(const char * client_m, const char * client_k)
{
    return std::string("2") + client_m + "-" + client_k + ".qkey";
}
