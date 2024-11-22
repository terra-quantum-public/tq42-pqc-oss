#pragma once

#include <cstdint>
#include <vector>

#include <buffer.h>
#include <core.h>

#include "params.h"

template <size_t MODE> class SLHDSAContext : public SignatureContext
{
public:
    SLHDSAContext(const ConstBufferView & public_key, const ConstBufferView & private_key);

    virtual size_t get_length(uint32_t type) const override;

    virtual void generate_keypair() override;

    virtual void create_signature(const ConstBufferView & buffer, const BufferView & signature) override;

    virtual bool verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const override;
};

template <size_t MODE> class SLHDSAFactory : public AlgorithmFactory
{
public:
    SLHDSAFactory();

    virtual uint32_t cipher_id() const override;

    virtual std::unique_ptr<PQC_Context>
    create_context_asymmetric(const ConstBufferView & public_key, const ConstBufferView & private_key) const override
    {
        check_size_or_empty(private_key, slh_dsa::ParameterSets[MODE].PRIVATE_KEY_LEN);
        check_size_or_empty(public_key, slh_dsa::ParameterSets[MODE].PUBLIC_KEY_LEN);
        return std::make_unique<SLHDSAContext<MODE>>(public_key, private_key);
    }

    virtual size_t get_length(uint32_t type) const override;
};
