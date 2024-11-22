#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#include <pqc/aes.h>
#include <pqc/container.h>
#include <pqc/delete.h>
#include <pqc/kdf.h>
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
#include <registry.h>
#include <rng/external_random_generator.h>
#include <secure_delete.h>
#include <sha3.h>

static Registry<CIPHER_HANDLE, PQC_Context> contexts;


AlgorithmRegistry algorithm_registry;

void check_size_or_empty(const ConstBufferView & buffer, size_t expected_size)
{
    if (buffer.const_data() && buffer.size() != expected_size)
    {
        throw BadLength();
    }
}

SymmetricContext * to_symmetric(PQC_Context * context)
{
    SymmetricContext * symmetric = dynamic_cast<SymmetricContext *>(context);
    if (!symmetric)
        throw UnsupportedOperation();
    return symmetric;
}

AsymmetricContext * to_asymmetric(PQC_Context * context)
{
    AsymmetricContext * asymmetric = dynamic_cast<AsymmetricContext *>(context);
    if (!asymmetric)
        throw UnsupportedOperation();
    return asymmetric;
}


KEMContext * to_kem(PQC_Context * context)
{
    KEMContext * kem = dynamic_cast<KEMContext *>(context);
    if (!kem)
        throw UnsupportedOperation();
    return kem;
}

SignatureContext * to_signature(PQC_Context * context)
{
    SignatureContext * signature = dynamic_cast<SignatureContext *>(context);
    if (!signature)
        throw UnsupportedOperation();
    return signature;
}

HashContext * to_hash(PQC_Context * context)
{
    HashContext * hash = dynamic_cast<HashContext *>(context);
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

void PQC_Context::set_random_generator(std::unique_ptr<IRandomGenerator> rng) { std::swap(random_generator_, rng); }

IRandomGenerator & PQC_Context::get_random_generator()
{
    if (!random_generator_)
    {
        set_random_generator(PQ17prng_engine::default_generator());
    }

    return *random_generator_;
}


CIPHER_HANDLE PQC_API PQC_context_init(uint32_t cipher, const uint8_t * key, size_t key_length)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);

        return contexts.add(factory->create_context(ConstBufferView(key, key_length)));
    }
    catch (...)
    {
        return PQC_BAD_CIPHER;
    }
}

CIPHER_HANDLE PQC_API
PQC_context_init_iv(uint32_t cipher, const uint8_t * key, size_t key_length, const uint8_t * iv, size_t iv_length)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);
        return contexts.add(factory->create_context(ConstBufferView(key, key_length), ConstBufferView(iv, iv_length)));
    }
    catch (...)
    {
        return PQC_BAD_CIPHER;
    }
}

CIPHER_HANDLE PQC_API PQC_context_init_hash(uint32_t algorithm, uint32_t mode)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(algorithm);
        return contexts.add(factory->create_context_hash(mode));
    }
    catch (...)
    {
        return PQC_BAD_CIPHER;
    }
}

CIPHER_HANDLE
PQC_context_init_asymmetric(
    uint32_t cipher, uint8_t * public_key, size_t public_size, uint8_t * private_key, size_t private_size
)
{
    try
    {
        const AlgorithmFactory * factory = algorithm_registry.get_factory(cipher);
        return contexts.add(factory->create_context_asymmetric(
            ConstBufferView(public_key, public_size), ConstBufferView(private_key, private_size)
        ));
    }
    catch (...)
    {
        return PQC_BAD_CIPHER;
    }
}

CIPHER_HANDLE PQC_API PQC_context_init_randomsource()
{
    try
    {
        return contexts.add(std::make_unique<PQC_Context>());
    }
    catch (...)
    {
        return PQC_BAD_CIPHER;
    }
}

size_t PQC_API PQC_context_set_iv(CIPHER_HANDLE ctx, const uint8_t * iv, size_t iv_len)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        context->set_iv(ConstBufferView(iv, iv_len));
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
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_symmetric_encrypt(CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_symmetric(context)->encrypt(mode, BufferView(buffer, length));
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
    catch (BadMode)
    {
        return PQC_BAD_MODE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}


size_t PQC_API PQC_symmetric_decrypt(CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_symmetric(context)->decrypt(mode, BufferView(buffer, length));
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
    catch (BadMode)
    {
        return PQC_BAD_MODE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_aead_encrypt(
    CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length, const uint8_t * aad, size_t aad_length,
    uint8_t * auth_tag, size_t auth_tag_len
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_symmetric(context)->aead_encrypt(
            mode, BufferView(buffer, length), ConstBufferView(aad, aad_length), BufferView(auth_tag, auth_tag_len)
        );
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
    catch (BadMode)
    {
        return PQC_BAD_MODE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_aead_decrypt(
    CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length, const uint8_t * aad, size_t aad_length,
    const uint8_t * auth_tag, size_t auth_tag_len
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_symmetric(context)->aead_decrypt(
            mode, BufferView(buffer, length), ConstBufferView(aad, aad_length), ConstBufferView(auth_tag, auth_tag_len)
        );
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
    catch (BadMode)
    {
        return PQC_BAD_MODE;
    }
    catch (AEADVerificationError)
    {
        return PQC_AUTHENTICATION_FAILURE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_aead_check(
    CIPHER_HANDLE ctx, uint32_t mode, uint8_t * buffer, size_t length, const uint8_t * aad, size_t aad_length,
    const uint8_t * auth_tag, size_t auth_tag_len
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        if (to_symmetric(context)->aead_check(
                mode, BufferView(buffer, length), ConstBufferView(aad, aad_length),
                ConstBufferView(auth_tag, auth_tag_len)
            ))
        {
            return PQC_OK;
        }
        return PQC_AUTHENTICATION_FAILURE;
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
    catch (BadMode)
    {
        return PQC_BAD_MODE;
    }
    catch (AEADVerificationError)
    {
        return PQC_AUTHENTICATION_FAILURE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_context_close(CIPHER_HANDLE ctx)
{
    contexts.remove(ctx);
    return PQC_OK;
}

size_t PQC_API PQC_context_keypair_generate(CIPHER_HANDLE ctx)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_asymmetric(context)->generate_keypair();
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
    catch (RandomFailure)
    {
        return PQC_RANDOM_FAILURE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_keypair_generate(
    uint32_t cipher, uint8_t * public_key, size_t public_size, uint8_t * private_key, size_t private_size
)
{
    CIPHER_HANDLE context = PQC_context_init_asymmetric(cipher, nullptr, 0, nullptr, 0);

    if (context == PQC_BAD_CONTEXT)
    {
        return PQC_BAD_CIPHER;
    }

    size_t result = PQC_context_keypair_generate(context);
    if (result != PQC_OK)
    {
        PQC_context_close(context);
        return result;
    }

    result = PQC_context_get_keypair(context, public_key, public_size, private_key, private_size);
    PQC_context_close(context);
    return result;
}

size_t PQC_API PQC_context_get_keypair(
    CIPHER_HANDLE ctx, uint8_t * public_key, size_t public_size, uint8_t * private_key, size_t private_size
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_asymmetric(context)->get_keypair(BufferView(public_key, public_size), BufferView(private_key, private_size));
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
    catch (KeyNotSet)
    {
        return PQC_KEY_NOT_SET;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_context_get_public_key(CIPHER_HANDLE ctx, uint8_t * public_key, size_t public_size)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_asymmetric(context)->get_public_key(BufferView(public_key, public_size));
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
    catch (KeyNotSet)
    {
        return PQC_KEY_NOT_SET;
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

        sha3_variables.update(ConstBufferView(shared_secret, shared_length));
        sha3_variables.update(ConstBufferView(&counter, sizeof(counter)));
        sha3_variables.update(ConstBufferView(party_a_info, info_length));
        sha3_variables.update(ConstBufferView(&sub_pub_info, sizeof(sub_pub_info)));

        size_t size = std::min(sha3_variables.hash_size(), key_length);
        memcpy(key, sha3_variables.retrieve(), size);

        key += size;
        key_length -= size;
    }

    return PQC_OK;
}

size_t PQC_API PQC_kem_encapsulate_secret(
    CIPHER_HANDLE ctx, uint8_t * message, size_t message_length, uint8_t * shared_secret, size_t shared_secret_length
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_kem(context)->kem_encapsulate_secret(
            BufferView(message, message_length), BufferView(shared_secret, shared_secret_length)
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
    catch (KeyNotSet)
    {
        return PQC_KEY_NOT_SET;
    }
    catch (RandomFailure)
    {
        return PQC_RANDOM_FAILURE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_kem_decapsulate_secret(
    CIPHER_HANDLE ctx, const uint8_t * message, size_t message_length, uint8_t * shared_secret,
    size_t shared_secret_length
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_kem(context)->kem_decapsulate_secret(
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
    catch (KeyNotSet)
    {
        return PQC_KEY_NOT_SET;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }

    return PQC_OK;
}

size_t PQC_API PQC_kem_encapsulate(
    CIPHER_HANDLE ctx, uint8_t * message, size_t message_length, const uint8_t * party_a_info, size_t info_length,
    uint8_t * shared_key, size_t shared_key_length
)
{
    size_t size = PQC_context_get_length(ctx, PQC_LENGTH_SHARED);
    if (size == 0)
    {
        return PQC_BAD_CONTEXT;
    }
    std::vector<uint8_t> secret(size, 0);

    size_t result = PQC_kem_encapsulate_secret(ctx, message, message_length, secret.data(), size);
    if (result != PQC_OK)
        return result;
    return PQC_kdf(secret.data(), size, party_a_info, info_length, shared_key, shared_key_length);
}

size_t PQC_API PQC_kem_decapsulate(
    CIPHER_HANDLE ctx, const uint8_t * message, size_t message_length, const uint8_t * party_a_info, size_t info_length,
    uint8_t * shared_key, size_t shared_key_length
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        size_t size = context->get_length(PQC_LENGTH_SHARED);
        std::vector<uint8_t> secret(size, 0);

        size_t result = PQC_kem_decapsulate_secret(ctx, message, message_length, secret.data(), size);
        if (result != PQC_OK)
            return result;
        return PQC_kdf(secret.data(), size, party_a_info, info_length, shared_key, shared_key_length);
    }
    catch (UnknownID)
    {
        return PQC_BAD_CIPHER;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_signature_create(
    CIPHER_HANDLE ctx, const uint8_t * buffer, size_t length, uint8_t * signature, size_t signature_len
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_signature(context)->create_signature(ConstBufferView(buffer, length), BufferView(signature, signature_len));
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
    catch (KeyNotSet)
    {
        return PQC_KEY_NOT_SET;
    }
    catch (RandomFailure)
    {
        return PQC_RANDOM_FAILURE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_signature_verify(
    CIPHER_HANDLE ctx, const uint8_t * buffer, size_t length, const uint8_t * signature, size_t signature_len
)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        if (to_signature(context)->verify_signature(
                ConstBufferView(buffer, length), ConstBufferView(signature, signature_len)
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
    catch (KeyNotSet)
    {
        return PQC_KEY_NOT_SET;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_hash_update(CIPHER_HANDLE ctx, const uint8_t * buffer, size_t length)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_hash(context)->update(ConstBufferView(buffer, length));
        return PQC_OK;
    }
    catch (UnsupportedOperation)
    {
        return PQC_BAD_CIPHER;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}

size_t PQC_API PQC_hash_size(CIPHER_HANDLE ctx)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        return to_hash(context)->hash_size();
    }
    catch (...)
    {
        return 0;
    }
}

size_t PQC_API PQC_hash_retrieve(CIPHER_HANDLE ctx, uint8_t * hash, size_t hash_length)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        to_hash(context)->retrieve(BufferView(hash, hash_length));
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
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}


size_t PQC_context_random_set_external(CIPHER_HANDLE ctx, _get_external_random get_ext_random)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    context->set_random_generator(std::make_unique<ExternalRandomGenerator>(get_ext_random));

    return PQC_OK;
}


size_t PQC_API
PQC_context_random_set_pq_17(CIPHER_HANDLE ctx, const uint8_t * key, size_t key_len, const uint8_t * iv, size_t iv_len)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    if (key_len != PQC_AES_KEYLEN || iv_len != PQC_AES_IVLEN)
    {
        return PQC_BAD_LEN;
    }

    context->set_random_generator(std::make_unique<PQ17prng_engine>((const pqc_aes_key *)key, (const pqc_aes_iv *)iv));

    return PQC_OK;
}

size_t PQC_API PQC_context_random_get_bytes(CIPHER_HANDLE ctx, void * x, size_t length)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        context->get_random_generator().random_bytes(BufferView(x, length));
    }
    catch (RandomFailure)
    {
        return PQC_RANDOM_FAILURE;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
    return PQC_OK;
}

//---------------------------------------------------- Symmetric Container
//----------------------------------------------------

Registry<PQC_CONTAINER_HANDLE, SymmetricKeyContainer> symmetric_containers;

PQC_CONTAINER_HANDLE PQC_API PQC_symmetric_container_create(CIPHER_HANDLE ctx)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }
    try
    {
        return symmetric_containers.add(std::make_unique<SymmetricKeyContainer>(&context->get_random_generator()));
    }
    catch (RandomFailure)
    {
        return PQC_RANDOM_FAILURE;
    }
}

uint32_t PQC_API PQC_symmetric_container_get_version(PQC_CONTAINER_HANDLE handle)
{
    SymmetricKeyContainer * container = symmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }

    return container->get_version();
}

uint64_t PQC_API PQC_symmetric_container_get_creation_time(PQC_CONTAINER_HANDLE handle)
{
    SymmetricKeyContainer * container = symmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }

    return container->get_creation_ts();
}

size_t PQC_symmetric_container_size(PQC_CONTAINER_HANDLE container) { return SymmetricKeyContainer::data_size(); }

uint64_t PQC_API PQC_symmetric_container_get_expiration_time(PQC_CONTAINER_HANDLE handle)
{
    SymmetricKeyContainer * container = symmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }

    return container->get_expiration_ts();
}

size_t PQC_API PQC_symmetric_container_get_data(
    PQC_CONTAINER_HANDLE handle, uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length,
    const uint8_t * iv, size_t iv_length
)
{
    SymmetricKeyContainer * container = symmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }

    if (data_length != SymmetricKeyContainer::data_size() || key_length != PQC_AES_KEYLEN || iv_length != PQC_AES_IVLEN)
    {
        return PQC_BAD_LEN;
    }

    container->get_data(
        container_data, reinterpret_cast<const pqc_aes_key *>(key), reinterpret_cast<const pqc_aes_iv *>(iv)
    );

    return PQC_OK;
}

PQC_CONTAINER_HANDLE PQC_API PQC_symmetric_container_from_data(
    CIPHER_HANDLE ctx, const uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length,
    const uint8_t * iv, size_t iv_length
)
{
    if (data_length != SymmetricKeyContainer::data_size() || key_length != PQC_AES_KEYLEN || iv_length != PQC_AES_IVLEN)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }

    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }

    try
    {
        return symmetric_containers.add(std::make_unique<SymmetricKeyContainer>(
            container_data, reinterpret_cast<const pqc_aes_key *>(key), reinterpret_cast<const pqc_aes_iv *>(iv),
            &context->get_random_generator()
        ));
    }
    catch (RandomFailure)
    {
        return PQC_RANDOM_FAILURE;
    }
}

size_t PQC_API PQC_symmetric_container_get_key(
    PQC_CONTAINER_HANDLE handle, int index, size_t bytes_encoded, uint32_t cipher, uint32_t method, uint8_t * key,
    size_t key_length
)
{
    SymmetricKeyContainer * container = symmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }

    return container->get(index, bytes_encoded, cipher, method, BufferView(key, key_length));
}

size_t PQC_API PQC_pbkdf_2(
    int mode, size_t hash_length, size_t password_length, const uint8_t * password, size_t key_length,
    uint8_t * derived_key, size_t derived_key_length, uint8_t * salt, size_t salt_length, size_t iterations
)
{
    return pbkdf_2(
        mode, hash_length, password_length, password, key_length, derived_key, derived_key_length, salt, salt_length,
        iterations
    );
}


PQC_CONTAINER_HANDLE PQC_API
PQC_symmetric_container_open(CIPHER_HANDLE ctx, const char * filename, const char * password, const char * salt)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }
    try
    {
        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();

        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.update(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.retrieve(), std::min<size_t>(sha3.hash_size(), 64));
        size_t hash_length = 256;
        size_t iterations = 10000;
        size_t result = pbkdf_2(
            PQC_PBKDF2_HMAC_SHA3, hash_length, strlen(password), reinterpret_cast<const uint8_t *>(password),
            PQC_AES_KEYLEN / sizeof(int), reinterpret_cast<uint8_t *>(master_key.get()), PQC_AES_KEYLEN / 8,
            buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN, iterations
        );
        if (result != 0)
        {
            return PQC_FAILED_TO_CREATE_CONTAINER;
        }

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);
        try
        {
            return symmetric_containers.add(std::make_unique<SymmetricKeyContainer>(
                std::make_shared<SymmetricKeyContainerFile>(false, filename), master_key, iv,
                &context->get_random_generator()
            ));
        }
        catch (RandomFailure)
        {
            return PQC_RANDOM_FAILURE;
        }
    }
    catch (const std::ios_base::failure &)
    {
        return PQC_FAILED_TO_CREATE_CONTAINER;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}


size_t PQC_API PQC_symmetric_container_save_as(
    PQC_CONTAINER_HANDLE handle, const char * filename, const char * password, const char * salt
)
{
    SymmetricKeyContainer * container = symmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }

    try
    {
        std::shared_ptr<SymmetricKeyContainerFile> file = std::make_shared<SymmetricKeyContainerFile>(true, filename);

        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();

        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.update(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.retrieve(), std::min<size_t>(sha3.hash_size(), 64));
        size_t hash_length = 256;
        size_t iterations = 10000;
        size_t result = pbkdf_2(
            PQC_PBKDF2_HMAC_SHA3, hash_length, strlen(password), reinterpret_cast<const uint8_t *>(password),
            PQC_AES_KEYLEN / sizeof(int), reinterpret_cast<uint8_t *>(master_key.get()), PQC_AES_KEYLEN / 8,
            buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN, iterations
        );
        if (result != 0)
        {
            return PQC_IO_ERROR;
        }

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        if (container->save_as(file, master_key, iv))
            return PQC_OK;
        else
            return PQC_IO_ERROR;
    }
    catch (const std::ios_base::failure &)
    {
        return PQC_IO_ERROR;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}


size_t PQC_API PQC_symmetric_container_close(PQC_CONTAINER_HANDLE container)
{
    symmetric_containers.remove(container);
    return PQC_OK;
}


//---------------------------------------------------- Asymmetric Container
//----------------------------------------------------


Registry<PQC_CONTAINER_HANDLE, AsymmetricContainer> asymmetric_containers;

PQC_CONTAINER_HANDLE PQC_API PQC_asymmetric_container_create(uint32_t cipher)
{
    return asymmetric_containers.add(std::make_unique<AsymmetricContainer>(cipher));
}

size_t PQC_API PQC_asymmetric_container_size(PQC_CONTAINER_HANDLE handle)
{
    AsymmetricContainer * container = asymmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }
    return container->data_size();
}

uint32_t PQC_API PQC_asymmetric_container_get_version(PQC_CONTAINER_HANDLE handle)
{
    AsymmetricContainer * container = asymmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }
    return container->get_version();
}

uint64_t PQC_API PQC_asymmetric_container_get_creation_time(PQC_CONTAINER_HANDLE handle)
{
    AsymmetricContainer * container = asymmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }
    return container->get_creation_ts();
}

uint64_t PQC_API PQC_asymmetric_container_get_expiration_time(PQC_CONTAINER_HANDLE handle)
{
    AsymmetricContainer * container = asymmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }
    return container->get_expiration_ts();
}

size_t PQC_asymmetric_container_size_special(uint32_t cipher, uint16_t mode)
{
    // it is cipher check! Not public key
    if (PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC) == 0)
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
    PQC_CONTAINER_HANDLE handle, uint8_t * container_data, size_t data_length, const uint8_t * key, size_t key_length,
    const uint8_t * iv, size_t iv_length
)
{
    AsymmetricContainer * container = asymmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }

    if (data_length != container->data_size() || key_length != PQC_AES_KEYLEN || iv_length != PQC_AES_IVLEN)
    {
        return PQC_BAD_LEN;
    }

    container->get_data(
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
    if (PQC_cipher_get_length(cipher, PQC_LENGTH_PUBLIC) == 0)
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

    PQC_CONTAINER_HANDLE result = asymmetric_containers.add(std::make_unique<AsymmetricContainer>(
        cipher, _data.get(), reinterpret_cast<const pqc_aes_key *>(key), reinterpret_cast<const pqc_aes_iv *>(iv)
    ));

    return result;
}

size_t PQC_API PQC_asymmetric_container_put_keys(
    uint32_t cipher, PQC_CONTAINER_HANDLE handle, uint8_t * pk, size_t pk_length, uint8_t * sk, size_t sk_length
)
{
    AsymmetricContainer * container = asymmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }
    return container->put_keys_inside(pk, sk, pk_length, sk_length, cipher);
}

size_t PQC_API PQC_asymmetric_container_get_keys(
    uint32_t cipher, PQC_CONTAINER_HANDLE handle, uint8_t * pk, size_t pk_length, uint8_t * sk, size_t sk_length
)
{
    AsymmetricContainer * container = asymmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }
    return container->get_keys(pk, sk, pk_length, sk_length, cipher);
}


size_t PQC_API PQC_asymmetric_container_save_as(
    uint32_t cipher, PQC_CONTAINER_HANDLE handle, const char * filename, const char * password, const char * salt
)
{
    AsymmetricContainer * container = asymmetric_containers.get(handle);
    if (!container)
    {
        return PQC_BAD_CONTAINER;
    }

    try
    {
        std::shared_ptr<AsymmetricContainerFile> file =
            std::make_shared<AsymmetricContainerFile>(cipher, true, filename);

        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();
        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.update(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.retrieve(), std::min<size_t>(sha3.hash_size(), 64));
        size_t hash_length = 256;
        size_t iterations = 10000;
        size_t pbkdfResult = pbkdf_2(
            PQC_PBKDF2_HMAC_SHA3, hash_length, strlen(password), reinterpret_cast<const uint8_t *>(password),
            PQC_AES_KEYLEN / sizeof(int), reinterpret_cast<uint8_t *>(master_key.get()), PQC_AES_KEYLEN / 8,
            buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN, iterations
        );
        if (pbkdfResult != 0)
        {
            return PQC_IO_ERROR;
        }

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        if (container->save_as(file, master_key, iv))
            return PQC_OK;
        else
            return PQC_IO_ERROR;
    }
    catch (const std::ios_base::failure &)
    {
        return PQC_IO_ERROR;
    }
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }
}


PQC_CONTAINER_HANDLE PQC_API
PQC_asymmetric_container_open(uint32_t cipher, const char * filename, const char * password, const char * salt)
{
    PQC_CONTAINER_HANDLE returnContainer = PQC_FAILED_TO_CREATE_CONTAINER;
    try
    {
        std::shared_ptr<AsymmetricContainerFile> file =
            std::make_shared<AsymmetricContainerFile>(cipher, true, filename);

        std::shared_ptr<pqc_aes_key> master_key = std::make_shared<pqc_aes_key>();
        uint8_t buffer[64] = {0};
        SHA3 sha3(PQC_SHA3_512);
        sha3.update(ConstBufferView(salt, strlen(salt)));
        memcpy(buffer, sha3.retrieve(), std::min<size_t>(sha3.hash_size(), 64));
        size_t hash_length = 256;
        size_t iterations = 10000;
        size_t pbkdfResult = pbkdf_2(
            PQC_PBKDF2_HMAC_SHA3, hash_length, strlen(password), reinterpret_cast<const uint8_t *>(password),
            PQC_AES_KEYLEN / sizeof(int), reinterpret_cast<uint8_t *>(master_key.get()), PQC_AES_KEYLEN / 8,
            buffer + PQC_AES_IVLEN, 64 - PQC_AES_IVLEN, iterations
        );
        if (pbkdfResult != 0)
        {
            return PQC_FAILED_TO_CREATE_CONTAINER;
        }

        std::shared_ptr<pqc_aes_iv> iv = std::make_shared<pqc_aes_iv>();
        memcpy(iv.get(), buffer, PQC_AES_IVLEN);

        // get encrypted data from file
        auto _data = std::make_unique<uint8_t[]>(AsymmetricContainer(cipher).data_size());

        bool result = file->read(cipher, _data.get());

        if (result)
        {
            returnContainer = asymmetric_containers.add(
                std::make_unique<AsymmetricContainer>(cipher, _data.get(), master_key.get(), iv.get())
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
    catch (...)
    {
        return PQC_INTERNAL_ERROR;
    }

    return returnContainer;
}

size_t PQC_API PQC_asymmetric_container_close(PQC_CONTAINER_HANDLE container)
{
    asymmetric_containers.remove(container);
    return PQC_OK;
}

size_t PQC_API PQC_context_get_length(CIPHER_HANDLE ctx, uint32_t type)
{
    PQC_Context * context = contexts.get(ctx);
    if (!context)
    {
        return 0;
    }

    return context->get_length(type);
}

size_t PQC_API PQC_cipher_get_length(uint32_t cipher, uint32_t type)
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

size_t PQC_API PQC_file_delete(CIPHER_HANDLE handle, const char * filename)
{
    PQC_Context * context = contexts.get(handle);
    if (!context)
    {
        return PQC_BAD_CONTEXT;
    }

    try
    {
        if (!file_delete(filename, &context->get_random_generator()))
            return PQC_IO_ERROR;
    }
    catch (RandomFailure)
    {
        return PQC_RANDOM_FAILURE;
    }
    return PQC_OK;
}

size_t PQC_API PQC_symmetric_container_delete(CIPHER_HANDLE handle, const char * filename)
{
    return PQC_file_delete(handle, filename);
}

size_t PQC_API PQC_asymmetric_container_delete(CIPHER_HANDLE handle, const char * filename)
{
    return PQC_file_delete(handle, filename);
}
