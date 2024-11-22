#pragma once

#include <pqc/kyber.h>

#include <buffer.h>
#include <core.h>

#include "params.h"

template <size_t MODE> class KyberContext : public KEMContext
{
public:
    KyberContext(const ConstBufferView & public_key, const ConstBufferView & private_key)
        : KEMContext(public_key, private_key)
    {
    }


    virtual size_t get_length(uint32_t type) const override;

    virtual void generate_keypair() override;

    virtual void kem_decapsulate_secret(ConstBufferView message, BufferView shared_secret) const override;
    virtual void kem_encapsulate_secret(const BufferView & message, const BufferView & shared_secret) override;
};


template <size_t MODE> class KyberFactory : public AlgorithmFactory
{
public:
    virtual uint32_t cipher_id() const override;

    virtual std::unique_ptr<PQC_Context>
    create_context_asymmetric(const ConstBufferView & public_key, const ConstBufferView & private_key) const override;

    virtual size_t get_length(uint32_t type) const override;
};
