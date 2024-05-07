#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#include <pqc/aes.h>
#include <pqc/delete.h>
#include <pqc/mceliece.h>
#include <pqc/random.h>
#include <pqc/sha3.h>

#include <aes.h>
#include <asymmetric_container.h>
#include <buffer.h>
#include <container.h>
#include <core.h>
#include <pbkdf2/pbkdf2.h>
#include <pq17.h>
#include <rng/external_random_generator.h>
#include <rng/rng.h>
#include <secure_delete.h>
#include <sha3.h>


static std::vector<std::unique_ptr<PQC_Context>> contexts;
AlgorithmRegistry algorithm_registry;

SymmetricContext * to_symmetric(std::unique_ptr<PQC_Context> & context)
{
    SymmetricContext * symmetric = dynamic_cast<SymmetricContext *>(context.get());
    if (!symmetric)
        throw UnsupportedOperation();
    return symmetric;
}

KEMContext * to_kem(std::unique_ptr<PQC_Context> & context)
{
    KEMContext * kem = dynamic_cast<KEMContext *>(context.get());
    if (!kem)
        throw UnsupportedOperation();
    return kem;
}

SignatureContext * to_signature(std::unique_ptr<PQC_Context> & context)
{
    SignatureContext * signature = dynamic_cast<SignatureContext *>(context.get());
    if (!signature)
        throw UnsupportedOperation();
    return signature;
}

HashContext * to_hash(std::unique_ptr<PQC_Context> & context)
{
    HashContext * hash = dynamic_cast<HashContext *>(context.get());
    if (!hash)
        throw UnsupportedOperation();
    return hash;
}

const AlgorithmFactory * AlgorithmRegistry::register_factory(std::unique_ptr<const AlgorithmFactory> factory)
{
    uint32_t id = factory->cipher_id();

    if (algorithm_registry_.count(id) > 0)
    {
        throw DuplicateID(id);
    }
    std::swap(algorithm_registry_[id], factory);
    return algorithm_registry_[id].get();
}

const AlgorithmFactory * AlgorithmRegistry::get_factory(uint32_t cipher)
{
    auto iterator = algorithm_registry_.find(cipher);
    if (iterator == algorithm_registry_.end())
    {
        throw UnknownID(cipher);
    }
    return iterator->second.get();
}

void AlgorithmRegistry::set_random_generator(std::unique_ptr<IRandomGenerator> rng)
{
    std::swap(random_generator_, rng);
}

IRandomGenerator & AlgorithmRegistry::get_random_generator()
{
    if (!random_generator_)
    {
        set_random_generator(PQ17prng_engine::default_generator());
    }

    return *random_generator_;
}

CIPHER_HANDLE new_context()
{
    CIPHER_HANDLE h;

    for (h = 0; h < contexts.size(); ++h)
    {
        if (!contexts[h])
        {
            return h;
        }
    }
    contexts.push_back(nullptr);
    return h;
}

bool is_valid_context(CIPHER_HANDLE ctx) { return ctx < contexts.size() && contexts[ctx]; }

#define CHECK_CONTEXT(ctx)                                                                                             \
    if (!is_valid_context(ctx))                                                                                        \
    {                                                                                                                  \
        return PQC_BAD_CONTEXT;                                                                                         \
    }

CIPHER_HANDLE PQC_API PQC_init_context(uint32_t cipher, const uint8_t * key, size_t key_length)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);
        CIPHER_HANDLE ctx = new_context();
        contexts[ctx] = factory->create_context(ConstBufferView(key, key_length));
        return ctx;
    }
    catch (...)
    {
        return PQC_BAD_CIPHER;
    }
}

CIPHER_HANDLE PQC_API
PQC_init_context_iv(uint32_t cipher, const uint8_t * key, size_t key_length, const uint8_t * iv, size_t iv_length)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);
        CIPHER_HANDLE ctx = new_context();
        contexts[ctx] = factory->create_context(ConstBufferView(key, key_length), ConstBufferView(iv, iv_length));
        return ctx;
    }
    catch (...)
    {
        return PQC_BAD_CIPHER;
    }
}

CIPHER_HANDLE PQC_API PQC_init_context_hash(uint32_t algorithm, uint32_t mode)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(algorithm);
        CIPHER_HANDLE ctx = new_context();
        contexts[ctx] = factory->create_context_hash(mode);
        return ctx;
    }
    catch (...)
    {
        return PQC_BAD_CIPHER;
    }
}

size_t PQC_API PQC_set_iv(CIPHER_HANDLE ctx, const uint8_t * iv, size_t iv_len)
{
    CHECK_CONTEXT(ctx);

    try
    {
        contexts[ctx]->set_iv(ConstBufferView(iv, iv_len));
        return PQC_OK;
    }
    catch (BadLength)
    {
        return PQC_BAD_LEN;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
}

size_t PQC_API PQC_encrypt(CIPHER_HANDLE ctx, uint32_t mechanism, uint8_t * buffer, size_t length)
{

    CHECK_CONTEXT(ctx)

    try
    {
        to_symmetric(contexts[ctx])->encrypt(mechanism, BufferView(buffer, length));
        return PQC_OK;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
    catch (BadLength)
    {
        return PQC_BAD_LEN;
    }
    catch (IVNotSet)
    {
        return PQC_NO_IV;
    }
    catch (BadMechanism)
    {
        return PQC_BAD_MECHANISM;
    }
}


size_t PQC_API PQC_decrypt(CIPHER_HANDLE ctx, uint32_t mechanism, uint8_t * buffer, size_t length)
{
    CHECK_CONTEXT(ctx)

    try
    {
        to_symmetric(contexts[ctx])->decrypt(mechanism, BufferView(buffer, length));
        return PQC_OK;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
    catch (BadLength)
    {
        return PQC_BAD_LEN;
    }
    catch (IVNotSet)
    {
        return PQC_NO_IV;
    }
    catch (BadMechanism)
    {
        return PQC_BAD_MECHANISM;
    }
}

size_t PQC_API PQC_close_context(CIPHER_HANDLE ctx)
{
    CHECK_CONTEXT(ctx)

    contexts[ctx].reset();

    return PQC_OK;
}

size_t PQC_API PQC_generate_key_pair(
    uint32_t cipher, uint8_t * public_key, size_t public_size, uint8_t * private_key, size_t private_size
)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);
        factory->generate_keypair(BufferView(public_key, public_size), BufferView(private_key, private_size));
        return PQC_OK;
    }
    catch (UnknownID)
    {
        return PQC_BAD_CIPHER;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
    catch (BadLength)
    {
        return PQC_BAD_LEN;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_kdf(
    const uint8_t * party_a_info, size_t info_length, const uint8_t * shared_secret, size_t shared_length,
    uint8_t * key, size_t key_length
)
{
    size_t sub_pub_info = shared_length * 8;

    for (uint32_t counter = 1; key_length > 0; ++counter)
    {
        SHA3 sha3_variables(PQC_SHA3_512);

        sha3_variables.add_data(ConstBufferView(shared_secret, shared_length));
        sha3_variables.add_data(ConstBufferView(&counter, sizeof(counter)));
        sha3_variables.add_data(ConstBufferView(party_a_info, info_length));
        sha3_variables.add_data(ConstBufferView(&sub_pub_info, sizeof(sub_pub_info)));

        size_t size = std::min(sha3_variables.hash_size(), key_length);
        memcpy(key, sha3_variables.get_hash(), size);

        key += size;
        key_length -= size;
    }

    return PQC_OK;
}

size_t PQC_API PQC_kem_encode_secret(
    uint32_t cipher, uint8_t * message, size_t message_length, const uint8_t * public_key, size_t publickey_length,
    uint8_t * shared_secret, size_t shared_secret_length
)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);
        factory->kem_encode_secret(
            BufferView(message, message_length), ConstBufferView(public_key, publickey_length),
            BufferView(shared_secret, shared_secret_length)
        );
        return PQC_OK;
    }
    catch (BadLength)
    {
        return PQC_BAD_LEN;
    }
    catch (UnknownID)
    {
        return PQC_BAD_CIPHER;
    }
}

size_t PQC_API PQC_kem_decode_secret(
    CIPHER_HANDLE ctx, const uint8_t * message, size_t message_length, uint8_t * shared_secret,
    size_t shared_secret_length
)
{
    CHECK_CONTEXT(ctx);

    try
    {
        to_kem(contexts[ctx])
            ->kem_decode_secret(
                ConstBufferView(message, message_length), BufferView(shared_secret, shared_secret_length)
            );
    }
    catch (BadLength)
    {
        return PQC_BAD_LEN;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }

    return PQC_OK;
}

size_t PQC_API PQC_kem_encode(
    uint32_t cipher, uint8_t * message, size_t message_length, const uint8_t * party_a_info, size_t info_length,
    const uint8_t * public_key, size_t key_length, uint8_t * shared_key, size_t shared_key_length
)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);

        size_t size = factory->get_length(PQC_LENGTH_SHARED);
        std::vector<uint8_t> secret(size, 0);

        size_t result =
            PQC_kem_encode_secret(cipher, message, message_length, public_key, key_length, secret.data(), size);
        if (result != PQC_OK)
            return result;
        return PQC_kdf(secret.data(), size, party_a_info, info_length, shared_key, shared_key_length);
    }
    catch (UnknownID)
    {
        return PQC_BAD_CIPHER;
    }
}

size_t PQC_API PQC_kem_decode(
    CIPHER_HANDLE ctx, const uint8_t * message, size_t message_length, const uint8_t * party_a_info, size_t info_length,
    uint8_t * shared_key, size_t shared_key_length
)
{
    CHECK_CONTEXT(ctx);

    try
    {
        size_t size = contexts[ctx]->get_length(PQC_LENGTH_SHARED);
        std::vector<uint8_t> secret(size, 0);

        size_t result = PQC_kem_decode_secret(ctx, message, message_length, secret.data(), size);
        if (result != PQC_OK)
            return result;
        return PQC_kdf(secret.data(), size, party_a_info, info_length, shared_key, shared_key_length);
    }
    catch (UnknownID)
    {
        return PQC_BAD_CIPHER;
    }
}

size_t PQC_API
PQC_sign(CIPHER_HANDLE ctx, const uint8_t * buffer, size_t length, uint8_t * signature, size_t signature_len)
{
    CHECK_CONTEXT(ctx);

    try
    {
        to_signature(contexts[ctx])->sign(ConstBufferView(buffer, length), BufferView(signature, signature_len));
        return PQC_OK;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
    catch (BadLength)
    {
        return PQC_BAD_LEN;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_verify(
    uint32_t cipher, const uint8_t * public_key, size_t public_keylen, const uint8_t * buffer, size_t length,
    const uint8_t * signature, size_t signature_len
)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);

        if (factory->verify(
                ConstBufferView(public_key, public_keylen), ConstBufferView(buffer, length),
                ConstBufferView(signature, signature_len)
            ))
            return PQC_OK;
        return PQC_BAD_SIGNATURE;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
    catch (UnknownID)
    {
        return PQC_BAD_CIPHER;
    }

    catch (BadLength)

    {
        return PQC_BAD_LEN;
    }
}

size_t PQC_API PQC_add_data(CIPHER_HANDLE ctx, const uint8_t * buffer, size_t length)
{
    CHECK_CONTEXT(ctx);

    try
    {
        to_hash(contexts[ctx])->add_data(ConstBufferView(buffer, length));
        return PQC_OK;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
}

size_t PQC_API PQC_hash_size(CIPHER_HANDLE ctx)
{
    try
    {
        return to_hash(contexts[ctx])->hash_size();
    }
    catch (...)
    {
        return 0;
    }
}

size_t PQC_API PQC_get_hash(CIPHER_HANDLE ctx, uint8_t * hash, size_t hash_length)
{
    CHECK_CONTEXT(ctx);

    try
    {
        to_hash(contexts[ctx])->get_hash(BufferView(hash, hash_length));
        return PQC_OK;
    }
    catch (BadLength)
    {
        return PQC_BAD_LEN;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
}


void PQC_random_from_external(_get_external_random get_ext_random)
{
    algorithm_registry.set_random_generator(std::make_unique<ExternalRandomGenerator>(get_ext_random));
}


size_t PQC_API PQC_random_from_pq_17(const uint8_t * key, size_t key_len, const uint8_t * iv, size_t iv_len)
{
    if (key_len != PQC_AES_KEYLEN || iv_len != PQC_AES_IVLEN)
    {
        return PQC_BAD_LEN;
    }

    algorithm_registry.set_random_generator(
        std::make_unique<PQ17prng_engine>((const pqc_aes_key *)key, (const pqc_aes_iv *)iv)
    );

    return PQC_OK;
}

void PQC_API PQC_random_bytes(void * x, size_t length) { return randombytes(BufferView(x, length)); }

void PQC_API PQC_set_container_path(const char * path) { SymmetricKeyContainer::set_container_path(path); }

//---------------------------------------------------- Symmetric Container
//----------------------------------------------------

std::vector<std::shared_ptr<SymmetricKeyContainer>> symmetric_containers;

PQC_CONTAINER_HANDLE store_new_symmetric_container(std::shared_ptr<SymmetricKeyContainer> container)
{
    for (size_t i = 0; i < symmetric_containers.size(); ++i)
    {
        if (!symmetric_containers[i])
        {
            symmetric_containers[i] = container;
            return i;
        }
    }

    symmetric_containers.push_back(container);
    return symmetric_containers.size() - 1;
}

PQC_CONTAINER_HANDLE PQC_API PQC_symmetric_container_create()
{
    return store_new_symmetric_container(std::make_shared<SymmetricKeyContainer>());
}

size_t PQC_symmetric_container_size(PQC_CONTAINER_HANDLE container) { return SymmetricKeyContainer::data_size(); }

bool is_valid_container(PQC_CONTAINER_HANDLE ctx)
{
    return ctx < symmetric_containers.size() && symmetric_containers[ctx];
}

#define CHECK_CONTAINER(ctx)                                                                                           \
    if (!is_valid_container(ctx))                                                                                      \
    {                                                                                                                  \
        return PQC_BAD_CONTAINER;                                                                                       \
    }


size_t PQC_API PQC_symmetric_container_get_data(
    PQC_CONTAINER_HANDLE container, uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length,
    const uint8_t * iv, size_t iv_length
)
{
    CHECK_CONTAINER(container);

    if (data_length != SymmetricKeyContainer::data_size() || key_length != PQC_AES_KEYLEN || iv_length != PQC_AES_IVLEN)
    {
        return PQC_BAD_LEN;
    }

    symmetric_containers[container]->get_data(
        container_data, reinterpret_cast<const pqc_aes_key *>(key), reinterpret_cast<const pqc_aes_iv *>(iv)
    );

    return PQC_OK;
}

PQC_CONTAINER_HANDLE PQC_API PQC_symmetric_container_from_data(
    const uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length, const uint8_t * iv,
    size_t iv_length
)
{
    if (data_length != SymmetricKeyContainer::data_size() || key_length != PQC_AES_KEYLEN || iv_length != PQC_AES_IVLEN)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }

    return store_new_symmetric_container(std::make_shared<SymmetricKeyContainer>(
        container_data, reinterpret_cast<const pqc_aes_key *>(key), reinterpret_cast<const pqc_aes_iv *>(iv)
    ));
}

size_t PQC_API PQC_symmetric_container_get_key(
    PQC_CONTAINER_HANDLE container, int index, size_t bytes_encoded, uint32_t cipher, uint32_t method, uint8_t * key,
    size_t key_length
)
{
    CHECK_CONTAINER(container);

    return symmetric_containers[container]->get(index, bytes_encoded, cipher, method, BufferView(key, key_length));
}

PQC_CONTAINER_HANDLE PQC_API PQC_symmetric_container_open(
    const char * server, const char * client, const char * device, const char * password, const char * salt
)
{
    try
    {
        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();

        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.add_data(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.get_hash(), std::min<size_t>(sha3.hash_size(), 64));

        pbkdf_2(
            strlen(password), reinterpret_cast<const uint8_t *>(password), PQC_AES_KEYLEN / sizeof(int),
            reinterpret_cast<int *>(master_key.get()), buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN
        );

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        return store_new_symmetric_container(std::make_shared<SymmetricKeyContainer>(
            std::make_shared<SymmetricKeyContainerFile>(false, server, client, device), master_key, iv
        ));
    }
    catch (const std::ios_base::failure &)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }
}

PQC_CONTAINER_HANDLE PQC_API
PQC_symmetric_container_pair_open(const char * client_m, const char * client_k, const char * password, const char * salt)
{
    try
    {
        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();

        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.add_data(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.get_hash(), std::min<size_t>(sha3.hash_size(), 64));

        pbkdf_2(
            strlen(password), reinterpret_cast<const uint8_t *>(password), PQC_AES_KEYLEN / sizeof(int),
            reinterpret_cast<int *>(master_key.get()), buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN
        );

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        return store_new_symmetric_container(std::make_shared<SymmetricKeyContainer>(
            std::make_shared<SymmetricKeyContainerFile>(false, client_m, client_k), master_key, iv
        ));
    }
    catch (const std::ios_base::failure &)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }
}

size_t PQC_API PQC_symmetric_container_save_as(
    PQC_CONTAINER_HANDLE container, const char * server, const char * client, const char * device, const char * password,
    const char * salt
)
{
    CHECK_CONTAINER(container);

    try
    {
        std::shared_ptr<SymmetricKeyContainerFile> file =
            std::make_shared<SymmetricKeyContainerFile>(true, server, client, device);

        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();

        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.add_data(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.get_hash(), std::min<size_t>(sha3.hash_size(), 64));

        pbkdf_2(
            strlen(password), reinterpret_cast<const uint8_t *>(password), PQC_AES_KEYLEN / sizeof(int),
            reinterpret_cast<int *>(master_key.get()), buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN
        );

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        if (symmetric_containers[container]->save_as(file, master_key, iv))
            return PQC_OK;
        else
            return PQC_IO_ERROR;
    }
    catch (const std::ios_base::failure &)
    {
        return PQC_IO_ERROR;
    }
}

size_t PQC_API PQC_symmetric_container_save_as_pair(
    PQC_CONTAINER_HANDLE container, const char * client_m, const char * client_k, const char * password,
    const char * salt
)
{
    CHECK_CONTAINER(container);

    try
    {
        std::shared_ptr<SymmetricKeyContainerFile> file =
            std::make_shared<SymmetricKeyContainerFile>(true, client_m, client_k);

        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();

        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.add_data(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.get_hash(), std::min<size_t>(sha3.hash_size(), 64));

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        pbkdf_2(
            strlen(password), reinterpret_cast<const uint8_t *>(password), PQC_AES_KEYLEN / sizeof(int),
            reinterpret_cast<int *>(master_key.get()), buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN
        );

        if (symmetric_containers[container]->save_as(file, master_key, iv))
            return PQC_OK;
        else
            return PQC_IO_ERROR;
    }
    catch (const std::ios_base::failure &)
    {
        return PQC_IO_ERROR;
    }
}

size_t PQC_API PQC_symmetric_container_close(PQC_CONTAINER_HANDLE container)
{
    if (container >= symmetric_containers.size() || !symmetric_containers[container])
    {
        return PQC_BAD_CONTAINER;
    }

    symmetric_containers[container].reset();

    return PQC_OK;
}


//---------------------------------------------------- Asymmetric Container
//----------------------------------------------------


std::vector<std::shared_ptr<AsymmetricContainer>> asymmetric_containers;

bool is_valid_asymmetric_container(PQC_CONTAINER_HANDLE ctx)
{
    return ctx < asymmetric_containers.size() && asymmetric_containers[ctx];
}

#define CHECK_ASYMMETRIC_CONTAINER(ctx)                                                                                \
    if (!is_valid_asymmetric_container(ctx))                                                                           \
    {                                                                                                                  \
        return PQC_BAD_CONTAINER;                                                                                       \
    }

PQC_CONTAINER_HANDLE store_new_asymmetric_container(std::shared_ptr<AsymmetricContainer> container)
{
    for (size_t i = 0; i < asymmetric_containers.size(); ++i)
    {
        if (!asymmetric_containers[i])
        {
            asymmetric_containers[i] = container;
            return i;
        }
    }

    asymmetric_containers.push_back(container);
    return asymmetric_containers.size() - 1;
}


PQC_CONTAINER_HANDLE PQC_API PQC_asymmetric_container_create(uint32_t cipher)
{
    return store_new_asymmetric_container(std::make_shared<AsymmetricContainer>(cipher));
}

size_t PQC_API PQC_asymmetric_container_size(PQC_CONTAINER_HANDLE container)
{
    CHECK_ASYMMETRIC_CONTAINER(container);
    return asymmetric_containers[container]->data_size();
}

size_t PQC_asymmetric_container_size_special(uint32_t cipher, uint16_t mode)
{
    // it is cipher check! Not public key
    if (PQC_get_length(cipher, PQC_LENGTH_PUBLIC) == 0)
    {
        return PQC_BAD_CIPHER;
    }
    if (mode)
    {
        return PQC_BAD_CIPHER;
    }
    AsymmetricContainer container(cipher);
    return container.data_size();
}


size_t PQC_API PQC_asymmetric_container_get_data(
    PQC_CONTAINER_HANDLE container, uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length,
    const uint8_t * iv, size_t iv_length
)
{
    CHECK_ASYMMETRIC_CONTAINER(container);

    if (data_length != PQC_asymmetric_container_size(container) || key_length != PQC_AES_KEYLEN ||
        iv_length != PQC_AES_IVLEN)
    {
        return PQC_BAD_LEN;
    }

    asymmetric_containers[container]->get_data(
        container_data, reinterpret_cast<const pqc_aes_key *>(key), reinterpret_cast<const pqc_aes_iv *>(iv)
    );

    return PQC_OK;
}


PQC_CONTAINER_HANDLE PQC_API PQC_asymmetric_container_from_data(
    uint32_t cipher, const uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length,
    const uint8_t * iv, size_t iv_length
)
{
    // it is cipher check! Not public key
    if (PQC_get_length(cipher, PQC_LENGTH_PUBLIC) == 0)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }

    if (data_length != AsymmetricContainer(cipher).data_size() || key_length != PQC_AES_KEYLEN ||
        iv_length != PQC_AES_IVLEN)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }

    auto _data = std::make_unique<uint8_t[]>(data_length);
    memcpy(_data.get(), container_data, data_length);

    PQC_CONTAINER_HANDLE result = store_new_asymmetric_container(std::make_shared<AsymmetricContainer>(
        cipher, _data.get(), reinterpret_cast<const pqc_aes_key *>(key), reinterpret_cast<const pqc_aes_iv *>(iv)
    ));

    return result;
}

size_t PQC_API PQC_asymmetric_container_put_keys(
    uint32_t cipher, PQC_CONTAINER_HANDLE container, uint8_t * pk, size_t pk_length, uint8_t * sk, size_t sk_length
)
{
    CHECK_ASYMMETRIC_CONTAINER(container);
    return asymmetric_containers[container]->put_keys_inside(pk, sk, pk_length, sk_length, cipher);
}

size_t PQC_API PQC_asymmetric_container_get_keys(
    uint32_t cipher, PQC_CONTAINER_HANDLE container, uint8_t * pk, size_t pk_length, uint8_t * sk, size_t sk_length
)
{
    CHECK_ASYMMETRIC_CONTAINER(container);
    return asymmetric_containers[container]->get_keys(pk, sk, pk_length, sk_length, cipher);
}


size_t PQC_API PQC_asymmetric_container_save_as(
    uint32_t cipher, PQC_CONTAINER_HANDLE container, const char * server, const char * client, const char * device,
    const char * password, const char * salt
)
{
    CHECK_ASYMMETRIC_CONTAINER(container);

    try
    {
        std::shared_ptr<AsymmetricContainerFile> file =
            std::make_shared<AsymmetricContainerFile>(cipher, true, server, client, device);

        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();

        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.add_data(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.get_hash(), std::min<size_t>(sha3.hash_size(), 64));

        pbkdf_2(
            strlen(password), reinterpret_cast<const uint8_t *>(password), PQC_AES_KEYLEN / sizeof(int),
            reinterpret_cast<int *>(master_key.get()), buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN
        );

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        if (asymmetric_containers[container]->save_as(file, master_key, iv))
            return PQC_OK;
        else
            return PQC_IO_ERROR;
    }

    catch (const std::ios_base::failure &)
    {
        return PQC_IO_ERROR;
    }
}


PQC_CONTAINER_HANDLE PQC_API PQC_asymmetric_container_open(
    uint32_t cipher, const char * server, const char * client, const char * device, const char * password,
    const char * salt
)
{
    PQC_CONTAINER_HANDLE returnContainer = PQC_FAILED_TO_CREATE_CONTAINER;
    try
    {
        std::shared_ptr<AsymmetricContainerFile> file =
            std::make_shared<AsymmetricContainerFile>(cipher, true, server, client, device);

        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();

        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.add_data(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.get_hash(), std::min<size_t>(sha3.hash_size(), 64));

        pbkdf_2(
            strlen(password), reinterpret_cast<const uint8_t *>(password), PQC_AES_KEYLEN / sizeof(int),
            reinterpret_cast<int *>(master_key.get()), buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN
        );

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        // get encrypted data from file
        auto _data = std::make_unique<uint8_t[]>(AsymmetricContainer(cipher).data_size());

        bool result = file->read(cipher, _data.get());

        if (result)
        {
            returnContainer = store_new_asymmetric_container(
                std::make_shared<AsymmetricContainer>(cipher, _data.get(), master_key.get(), iv.get())
            );
        }

        if (!result)
        {
            return PQC_FAILED_TO_CREATE_CONTAINER;
        }
    }
    catch (const std::ios_base::failure &)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }

    return returnContainer;
}


size_t PQC_API PQC_asymmetric_container_close(PQC_CONTAINER_HANDLE container)
{

    if (container >= asymmetric_containers.size() || !asymmetric_containers[container])
    {
        return PQC_BAD_CONTAINER;
    }
    asymmetric_containers[container].reset();
    return PQC_OK;
}

size_t PQC_API PQC_context_get_length(CIPHER_HANDLE context, uint32_t type)
{
    if (!is_valid_context(context))
        return 0;

    return contexts[context]->get_length(type);
}

size_t PQC_API PQC_get_length(uint32_t cipher, uint32_t type)
{
    try
    {
        return algorithm_registry.get_factory(cipher)->get_length(type);
    }
    catch (...)
    {
        return 0;
    }
}

size_t PQC_API PQC_file_delete(const char * filename)
{
    if (!file_delete(filename))
        return PQC_IO_ERROR;

    return PQC_OK;
}

size_t PQC_API PQC_symmetric_container_delete(const char * server, const char * client, const char * device)
{
    std::string filename = SymmetricKeyContainerFile::get_filename(server, client, device);
    return PQC_file_delete(filename.c_str());
}

size_t PQC_API PQC_symmetric_container_pair_delete(const char * client_m, const char * client_k)
{
    std::string filename = SymmetricKeyContainerFile::get_filename(client_m, client_k);
    return PQC_file_delete(filename.c_str());
}

size_t PQC_API PQC_asymmetric_container_delete(const char * server, const char * client, const char * device)
{
    std::string filename = AsymmetricContainerFile::get_filename(server, client, device);
    return PQC_file_delete(filename.c_str());
}
