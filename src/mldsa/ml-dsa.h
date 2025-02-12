#pragma once

#include <cstdint>

#include <buffer.h>
#include <core.h>

#include "params.h"

template <size_t MODE> class MLDSAContext : public SignatureContext
{
public:
    MLDSAContext(const ConstBufferView & public_key, const ConstBufferView & private_key);

    virtual size_t get_length(uint32_t type) const override;

    virtual void set_iv(const ConstBufferView & iv) override;

    virtual void generate_keypair() override;

    virtual void create_signature(const ConstBufferView & buffer, const BufferView & signature) override;

    virtual bool verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const override;

private:
    StackBuffer<mldsa::MAX_CONTEXT_LEN> context;
    size_t context_len;
};

template <size_t MODE> class MLDSAFactory : public AlgorithmFactory
{
public:
    MLDSAFactory();

    virtual uint32_t cipher_id() const override;

    virtual std::unique_ptr<PQC_Context>
    create_context_asymmetric(const ConstBufferView & public_key, const ConstBufferView & private_key) const override
    {
        check_size_or_empty(private_key, mldsa::ParameterSets[MODE].PRIVATE_KEY_LEN);
        check_size_or_empty(public_key, mldsa::ParameterSets[MODE].PUBLIC_KEY_LEN);
        return std::make_unique<MLDSAContext<MODE>>(public_key, private_key);
    }

    virtual size_t get_length(uint32_t type) const override;
};
