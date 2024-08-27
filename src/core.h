#pragma once

#include <cstring>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include <pqc/common.h>

#include <buffer.h>
#include <rng/random_generator.h>


class PQException
{
};

class PQCipherException
{
public:
    PQCipherException(uint32_t cipher_id) : cipher_id_(cipher_id) {}

    uint32_t cipher_id() const { return cipher_id_; }

private:
    uint32_t cipher_id_;
};

class DuplicateID : public PQCipherException
{
public:
    DuplicateID(uint32_t cipher_id) : PQCipherException(cipher_id) {}
};

class UnknownID : public PQCipherException
{
public:
    UnknownID(uint32_t cipher_id) : PQCipherException(cipher_id) {}
};

class UnsupportedOperation : public PQException
{
};

class BadLength : public PQException
{
};

class IVNotSet : public PQException
{
};

class BadMode : public PQException
{
};

class InternalError : public PQException
{
};

class AEADVerificationError : public PQException
{
};

#define PQC_CIPHER_EMPTY std::numeric_limits<uint32_t>::max()

class PQC_Context
{
public:
    PQC_Context(){};
    PQC_Context(const PQC_Context &) = delete;
    PQC_Context & operator=(const PQC_Context &) = delete;

    virtual void set_iv(const ConstBufferView & iv) { throw UnsupportedOperation(); }

    virtual size_t get_length(uint32_t type) const { return 0; }

    virtual ~PQC_Context(){};
};

class SymmetricContext : public PQC_Context
{
public:
    virtual void encrypt(uint32_t mode, const BufferView & data) { throw UnsupportedOperation(); }
    virtual void decrypt(uint32_t mode, const BufferView & data) { throw UnsupportedOperation(); }
    virtual void
    aead_encrypt(uint32_t mode, const BufferView & data, const ConstBufferView & aad, const BufferView & auth_tag)
    {
        throw UnsupportedOperation();
    }
    virtual void
    aead_decrypt(uint32_t mode, const BufferView & data, const ConstBufferView & aad, const ConstBufferView & auth_tag)
    {
        throw UnsupportedOperation();
    }
    virtual bool
    aead_check(uint32_t mode, const BufferView & data, const ConstBufferView & aad, const ConstBufferView & auth_tag)
    {
        throw UnsupportedOperation();
    }
};

class KEMContext : public PQC_Context
{
public:
    virtual void kem_decode_secret(ConstBufferView message, BufferView shared_secret) const
    {
        throw UnsupportedOperation();
    }
};

class SignatureContext : public PQC_Context
{
public:
    virtual void sign(const ConstBufferView & buffer, const BufferView & signature) const
    {
        throw UnsupportedOperation();
    }
};

class HashContext : public PQC_Context
{
public:
    virtual void add_data(const ConstBufferView & data) { throw UnsupportedOperation(); }
    virtual size_t hash_size() const { return 0; }
    virtual void get_hash(const BufferView & hash) { throw UnsupportedOperation(); }
};

SymmetricContext * to_symmetric(std::unique_ptr<PQC_Context> & context);
KEMContext * to_kem(std::unique_ptr<PQC_Context> & context);
SignatureContext * to_signature(std::unique_ptr<PQC_Context> & context);
HashContext * to_hash(std::unique_ptr<PQC_Context> & context);


class AlgorithmFactory
{
public:
    virtual ~AlgorithmFactory() {}

    virtual uint32_t cipher_id() const = 0;
    virtual std::unique_ptr<PQC_Context> create_context(const ConstBufferView & private_key) const
    {
        throw UnsupportedOperation();
    }

    virtual std::unique_ptr<PQC_Context>
    create_context(const ConstBufferView & private_key, const ConstBufferView & iv) const
    {
        throw UnsupportedOperation();
    }

    virtual std::unique_ptr<PQC_Context> create_context_hash(uint32_t mode) const { throw UnsupportedOperation(); }

    virtual void generate_keypair(const BufferView & public_key, const BufferView & private_key) const
    {
        throw UnsupportedOperation();
    }

    virtual void kem_encode_secret(
        const BufferView & message, const ConstBufferView public_key, const BufferView & shared_secret
    ) const
    {
        throw UnsupportedOperation();
    }

    virtual bool
    verify(const ConstBufferView & public_key, const ConstBufferView buffer, const ConstBufferView signature) const
    {
        throw UnsupportedOperation();
    }

    virtual size_t get_length(uint32_t type) const = 0;
};

class AlgorithmRegistry
{
public:
    AlgorithmRegistry();

    const AlgorithmFactory * register_factory(std::unique_ptr<const AlgorithmFactory> factory);

    const AlgorithmFactory * get_factory(uint32_t cipher);

    void set_random_generator(std::unique_ptr<IRandomGenerator> rng);

    IRandomGenerator & get_random_generator();

private:
    std::unordered_map<uint32_t, std::unique_ptr<const AlgorithmFactory>> algorithm_registry_;
    std::unique_ptr<IRandomGenerator> random_generator_;
};

extern AlgorithmRegistry algorithm_registry;
