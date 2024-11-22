#pragma once

#include <array>

#include <pqc/mceliece.h>

#include <buffer.h>
#include <core.h>


class McElieceFactory : public AlgorithmFactory
{
public:
    virtual uint32_t cipher_id() const override;

    virtual std::unique_ptr<PQC_Context>
    create_context_asymmetric(const ConstBufferView & public_key, const ConstBufferView & private_key) const override;

    virtual size_t get_length(uint32_t type) const override;
};

class McElieceContext : public KEMContext
{
public:
    McElieceContext(const ConstBufferView & public_key, const ConstBufferView & private_key)
        : KEMContext(public_key, private_key)
    {
    }

    virtual void generate_keypair() override;

    virtual void kem_encapsulate_secret(const BufferView & message, const BufferView & shared_secret) override;

    virtual void kem_decapsulate_secret(ConstBufferView message, BufferView shared_secret) const override;

    virtual size_t get_length(uint32_t type) const override;
};
