#include <cstring>
#include <ctime>
#include <fstream>

#include <pqc/aes.h>
#include <pqc/container.h>
#include <pqc/sha3.h>

#include <aes.h>
#include <asymmetric_container.h>
#include <buffer.h>
#include <sha3.h>


AsymmetricContainer::AsymmetricContainer(uint32_t algType)
{
    data.version = PQC_ASYMMETRIC_CONTAINER_VERSION;

    data.AlgType = algType;
    for (int i = 0; i < OIDnumbers; i++)
    {
        data.OID[i] = 0;
    }

    data.creation_ts = std::time(nullptr);

    size_t length =
        PQC_cipher_get_length(algType, PQC_LENGTH_PUBLIC) + PQC_cipher_get_length(algType, PQC_LENGTH_PRIVATE);

    data.KeyBytes.resize(length);
}

AsymmetricContainer::AsymmetricContainer(
    uint32_t algType, uint8_t * container_data, const pqc_aes_key * key, const pqc_aes_iv * iv
)
{
    size_t length =
        PQC_cipher_get_length(algType, PQC_LENGTH_PUBLIC) + PQC_cipher_get_length(algType, PQC_LENGTH_PRIVATE);

    data.KeyBytes.resize(length);
    data.AlgType = algType;
    for (int i = 0; i < OIDnumbers; i++)
    {
        data.OID[i] = 0;
    }
    data.creation_ts = std::time(nullptr);

    // decryption
    AES cipher(ConstBufferView::from_single(*key), ConstBufferView::from_single(*iv));
    BufferView dataBuf = BufferView(container_data, data_size());
    cipher.ofb_xcrypt(dataBuf);
    memcpy(data.KeyBytes.data(), container_data, data.KeyBytes.size());
    memcpy(&data.AlgType, container_data + data.KeyBytes.size(), sizeof(data.AlgType));
    memcpy(data.OID, container_data + data.KeyBytes.size() + sizeof(data.AlgType), sizeof(data.OID));
    memcpy(
        &data.creation_ts, container_data + data.KeyBytes.size() + sizeof(data.AlgType) + sizeof(data.OID),
        sizeof(data.creation_ts)
    );
    memcpy(
        &data.version,
        container_data + data.KeyBytes.size() + sizeof(data.AlgType) + sizeof(data.OID) + sizeof(data.creation_ts),
        sizeof(data.version)
    );

    // encryption to encrypt memmory with data was used to create container. This data won't be deleted. Only
    // reencrypted.
    BufferView dataBuf_ = BufferView(reinterpret_cast<uint8_t *>(container_data), data_size());
    cipher.ofb_xcrypt(dataBuf_);
}

size_t AsymmetricContainer::data_size()
{
    return (
        data.KeyBytes.size() + sizeof(data.AlgType) + sizeof(data.OID) + sizeof(data.creation_ts) + sizeof(data.version)
    );
}

void AsymmetricContainer::get_data(uint8_t * destinationData, const pqc_aes_key * key, const pqc_aes_iv * iv)
{
    memcpy(destinationData, data.KeyBytes.data(), data.KeyBytes.size());
    memcpy(destinationData + data.KeyBytes.size(), &data.AlgType, sizeof(data.AlgType));
    memcpy(destinationData + data.KeyBytes.size() + sizeof(data.AlgType), data.OID, sizeof(data.OID));
    memcpy(
        destinationData + data.KeyBytes.size() + sizeof(data.AlgType) + sizeof(data.OID), &data.creation_ts,
        sizeof(data.creation_ts)
    );
    memcpy(
        destinationData + data.KeyBytes.size() + sizeof(data.AlgType) + sizeof(data.OID) + sizeof(data.creation_ts),
        &data.version, sizeof(data.version)
    );

    // encryption
    AES cipher(ConstBufferView::from_single(*key), ConstBufferView::from_single(*iv));
    BufferView dataBuf = BufferView(destinationData, data_size());
    cipher.ofb_xcrypt(dataBuf);
}

size_t
AsymmetricContainer::put_keys_inside(uint8_t * pk, uint8_t * sk, size_t pkLength, size_t skLength, uint32_t algtype)
{
    size_t publicLength = PQC_cipher_get_length(algtype, PQC_LENGTH_PUBLIC);
    size_t secretLength = PQC_cipher_get_length(algtype, PQC_LENGTH_PRIVATE);

    if (pkLength + skLength != data.KeyBytes.size() || publicLength != pkLength || secretLength != skLength)
    {
        return PQC_BAD_LEN;
    }
    if (algtype != data.AlgType || !publicLength || !secretLength)
    {
        return PQC_BAD_CIPHER;
    }

    memcpy(data.KeyBytes.data(), pk, publicLength);
    memcpy(data.KeyBytes.data() + publicLength, sk, secretLength);

    data.creation_ts = std::time(nullptr);

    return PQC_OK;
}

size_t AsymmetricContainer::get_keys(uint8_t * pk, uint8_t * sk, size_t pkLength, size_t skLength, uint32_t algtype)
{
    size_t publicLength = PQC_cipher_get_length(algtype, PQC_LENGTH_PUBLIC);
    size_t secretLength = PQC_cipher_get_length(algtype, PQC_LENGTH_PRIVATE);

    if (pkLength + skLength != data.KeyBytes.size() || publicLength != pkLength || secretLength != skLength)
    {
        return PQC_BAD_LEN;
    }
    if (algtype != data.AlgType || !publicLength || !secretLength)
    {
        return PQC_BAD_CIPHER;
    }
    uint64_t current_ts = std::time(nullptr);
    if (current_ts > get_expiration_ts())
    {
        return PQC_CONTAINER_EXPIRED;
    }

    memcpy(pk, data.KeyBytes.data(), publicLength);
    memcpy(sk, data.KeyBytes.data() + publicLength, secretLength);

    return PQC_OK;
}

int AsymmetricContainer::save_as(
    std::shared_ptr<AsymmetricContainerFile> file, std::shared_ptr<pqc_aes_key> key, std::shared_ptr<pqc_aes_iv> iv
)
{
    if (!file || !key || !iv)
    {
        return 0;
    }

    auto _data = std::make_unique<uint8_t[]>(data_size());

    get_data(_data.get(), key.get(), iv.get());
    bool result = file->write(data.AlgType, _data.get());

    if (result)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

////////////////////////////////////////////       FILE!!! /////////////////////////////////////////////////////////


AsymmetricContainerFile::AsymmetricContainerFile(uint32_t algType, bool create_new, const char * filename)
    : _fileName(filename)
{
    cipher = algType;
}

bool AsymmetricContainerFile::read(uint32_t cipher_, uint8_t * data)
{
    if (!_file.is_open())
    {
        _file.close();
    }

    _file.open(_fileName, _file.in | _file.binary);
    _file.seekg(0);
    _file.read(reinterpret_cast<char *>(data), AsymmetricContainer(cipher_).data_size());

    if (!_file.good())
    {
        throw std::ios_base::failure("failed to read container file");
    }
    _file.close();
    return true;
}

bool AsymmetricContainerFile::write(uint32_t cipher_, const uint8_t * data)
{
    if (!_file.is_open())
    {
        _file.close();
    }
    _file.open(_fileName, _file.out | _file.binary);
    _file.seekp(0);
    _file.write(reinterpret_cast<const char *>(data), AsymmetricContainer(cipher_).data_size());

    if (!_file.good())
    {
        throw std::ios_base::failure("failed to write container file");
    }

    _file.close();
    return true;
}
