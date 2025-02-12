#pragma once

#include <cstddef>
#include <cstdint>

#include <pqc/aes.h>

#include <buffer.h>
#include <core.h>

class AES : public SymmetricContext
{
public:
    AES(const ConstBufferView & key);
    AES(const ConstBufferView & key, const ConstBufferView & iv);

    virtual void encrypt(uint32_t mode, const BufferView & data) override;
    virtual void decrypt(uint32_t mode, const BufferView & data) override;

    virtual void aead_encrypt(
        uint32_t mode, const BufferView & data, const ConstBufferView & aad, const BufferView & auth_tag
    ) override;
    virtual void aead_decrypt(
        uint32_t mode, const BufferView & data, const ConstBufferView & aad, const ConstBufferView & auth_tag
    ) override;

    virtual bool aead_check(
        uint32_t mode, const BufferView & data, const ConstBufferView & aad, const ConstBufferView & auth_tag
    ) override;


    virtual void set_iv(const ConstBufferView & iv) override;

    // #TODO ECB mode encrypts message blocks independently of each other
    //                      which makes it possible to encrypt them in parallel
    //                      thereby speeding up the work
    void ecb_encrypt(const BufferView & data);
    void ecb_decrypt(const BufferView & data);

    // CBC
    // buffer size MUST be multiple of AES_BLOCKLEN;
    // NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
    //        no IV should ever be reused with the same key
    void cbc_encrypt_buffer(const BufferView & data);
    void cbc_decrypt_buffer(const BufferView & data);

    void ofb_xcrypt(BufferView data);

    // CTR
    void ctr_xcrypt(const BufferView & data);

    bool is_iv_set() const { return IvSet_; }

    virtual size_t get_length(uint32_t type) const override;

    void gcm_xcrypt(const BufferView & data);
    void gcm_get_auth_tag(
        const ConstBufferView & iv_view, const ConstBufferView & data, const ConstBufferView & aad,
        const BufferView & auth_tag
    );
    bool
    gcm_check_auth_tag(const ConstBufferView & data, const ConstBufferView & aad, const ConstBufferView & auth_tag);

private:
    StackBuffer<PQC_AES_keyExpSize> RoundKey_;
    StackBuffer<PQC_AES_IVLEN> Iv_;
    uint8_t IvSet_ = false;
    uint32_t IvOffset_ = 0;
};

class AESFactory : public AlgorithmFactory
{
public:
    AESFactory();

    virtual uint32_t cipher_id() const override;

    virtual std::unique_ptr<PQC_Context> create_context(const ConstBufferView & private_key) const override;

    virtual std::unique_ptr<PQC_Context>
    create_context(const ConstBufferView & private_key, const ConstBufferView & iv) const override;

    virtual size_t get_length(uint32_t type) const override;
};
