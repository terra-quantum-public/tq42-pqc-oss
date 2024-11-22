#pragma once

#include <cstdint>

#include <pqc/falcon.h>

#include <buffer.h>
#include <core.h>
#include <falcon/falcon.h>


class FalconFactory : public AlgorithmFactory
{
public:
    FalconFactory();

    virtual uint32_t cipher_id() const override;

    virtual std::unique_ptr<PQC_Context>
    create_context_asymmetric(const ConstBufferView & public_key, const ConstBufferView & private_key) const override;

    virtual size_t get_length(uint32_t type) const override;
};

class FalconContext : public SignatureContext
{
public:
    FalconContext(const ConstBufferView & public_key, const ConstBufferView & private_key)
        : SignatureContext(public_key, private_key)
    {
    }

    virtual size_t get_length(uint32_t type) const override;

    virtual void generate_keypair() override;

    virtual void create_signature(const ConstBufferView & buffer, const BufferView & signature) override;

    virtual bool verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const override;
};
