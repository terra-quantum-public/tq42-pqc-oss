#pragma once

#include <cstdint>

#include <pqc/ml-dsa.h>

#include <buffer.h>
#include <core.h>


class MLDSAFactory : public AlgorithmFactory
{
public:
    MLDSAFactory();

    virtual uint32_t cipher_id() const override;

    virtual std::unique_ptr<PQC_Context> create_context(const ConstBufferView & private_key) const override;

    virtual void generate_keypair(const BufferView & public_key, const BufferView & private_key) const override;

    virtual bool verify(
        const ConstBufferView & public_key, const ConstBufferView buffer, const ConstBufferView signature
    ) const override;

    virtual size_t get_length(uint32_t type) const override;
};

class MLDSAContext : public SignatureContext
{
public:
    MLDSAContext(const pqc_ml_dsa_private_key * private_key) : private_key_(*private_key) {}

    virtual size_t get_length(uint32_t type) const override;

    virtual void sign(const ConstBufferView & buffer, const BufferView & signature) const override;

private:
    pqc_ml_dsa_private_key private_key_;
};
