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

class KeyNotSet : public PQException
{
};

class RandomFailure : public PQException
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

    void set_random_generator(std::unique_ptr<IRandomGenerator> rng);

    IRandomGenerator & get_random_generator();

private:
    std::unique_ptr<IRandomGenerator> random_generator_;
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

class AsymmetricContext : public PQC_Context
{
public:
    AsymmetricContext(const ConstBufferView & public_key_view, const ConstBufferView & private_key_view)
    {
        if (public_key_view.const_data() && public_key_view.size() > 0)
        {
            public_key_.resize(public_key_view.size());
            BufferView(public_key_.data(), public_key_.size()).store(public_key_view);
        }
        if (private_key_view.const_data() && private_key_view.size() > 0)
        {
            private_key_.resize(private_key_view.size());
            BufferView(private_key_.data(), private_key_.size()).store(private_key_view);
        }
    }

    virtual void generate_keypair() { throw UnsupportedOperation(); }

    virtual void get_keypair(const BufferView & public_key_view, const BufferView & private_key_view)
    {
        if (public_key_view.size() != this->public_key().size())
        {
            throw BadLength();
        }
        if (private_key_view.size() != this->private_key().size())
        {
            throw BadLength();
        }
        public_key_view.store(this->public_key());
        private_key_view.store(this->private_key());
    }

    virtual void get_public_key(const BufferView & public_key_view)
    {
        if (public_key_view.size() != this->public_key().size())
        {
            throw BadLength();
        }
        public_key_view.store(this->public_key());
    }

protected:
    ConstBufferView public_key() const
    {
        if (public_key_.size() == 0)
        {
            throw KeyNotSet();
        }
        return ConstBufferView(public_key_.data(), public_key_.size());
    }

    ConstBufferView private_key() const
    {
        if (private_key_.size() == 0)
        {
            throw KeyNotSet();
        }
        return ConstBufferView(private_key_.data(), private_key_.size());
    }

    std::tuple<BufferView, BufferView> allocate_keys(size_t public_key_size, size_t private_key_size)
    {
        public_key_.resize(public_key_size);
        private_key_.resize(private_key_size);
        return std::make_tuple(
            BufferView(public_key_.data(), public_key_.size()), BufferView(private_key_.data(), private_key_.size())
        );
    }

private:
    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> private_key_;
};

class KEMContext : public AsymmetricContext
{
public:
    KEMContext(const ConstBufferView & public_key, const ConstBufferView & private_key)
        : AsymmetricContext(public_key, private_key)
    {
    }

    virtual void kem_encapsulate_secret(const BufferView & message, const BufferView & shared_secret)
    {
        throw UnsupportedOperation();
    }

    virtual void kem_decapsulate_secret(ConstBufferView message, BufferView shared_secret) const
    {
        throw UnsupportedOperation();
    }
};

class SignatureContext : public AsymmetricContext
{
public:
    SignatureContext(const ConstBufferView & public_key, const ConstBufferView & private_key)
        : AsymmetricContext(public_key, private_key)
    {
    }

    virtual void create_signature(const ConstBufferView & buffer, const BufferView & signature)
    {
        throw UnsupportedOperation();
    }

    virtual bool verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const
    {
        throw UnsupportedOperation();
    }
};

class HashContext : public PQC_Context
{
public:
    virtual void update(const ConstBufferView & data) { throw UnsupportedOperation(); }
    virtual size_t hash_size() const { return 0; }
    virtual void retrieve(const BufferView & hash) { throw UnsupportedOperation(); }
};

SymmetricContext * to_symmetric(std::unique_ptr<PQC_Context> & context);
AsymmetricContext * to_asymmetric(std::unique_ptr<PQC_Context> & context);
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

    virtual std::unique_ptr<PQC_Context>
    create_context_asymmetric(const ConstBufferView & public_key, const ConstBufferView & private_key) const
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

private:
    std::unordered_map<uint32_t, std::unique_ptr<const AlgorithmFactory>> algorithm_registry_;
};

void check_size_or_empty(const ConstBufferView & buffer, size_t expected_size);

extern AlgorithmRegistry algorithm_registry;
