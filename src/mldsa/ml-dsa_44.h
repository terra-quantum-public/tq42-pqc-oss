#pragma once

#include <cstdint>

#include <pqc/ml-dsa.h>

#include <buffer.h>
#include <core.h>


class MLDSAFactory_44 : public AlgorithmFactory
{
public:
    MLDSAFactory_44();

    virtual uint32_t cipher_id() const override;

    virtual std::unique_ptr<PQC_Context>
    create_context_asymmetric(const ConstBufferView & public_key, const ConstBufferView & private_key) const override;

    virtual size_t get_length(uint32_t type) const override;
};

class MLDSAContext_44 : public SignatureContext
{
public:
    MLDSAContext_44(const ConstBufferView & public_key, const ConstBufferView & private_key)
        : SignatureContext(public_key, private_key)
    {
    }

    virtual size_t get_length(uint32_t type) const override;

    virtual void generate_keypair() override;

    virtual void create_signature(const ConstBufferView & buffer, const BufferView & signature) override;

    virtual bool verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const override;
};
