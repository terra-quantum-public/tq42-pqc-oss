#pragma once

#include <cstddef>
#include <cstdint>

#include <pqc/aes.h>

#include <buffer.h>
#include <core.h>

class AES : public SymmetricContext
{
public:
    AES(const pqc_aes_key * key);
    AES(const pqc_aes_key * key, const pqc_aes_iv * iv);

    virtual void encrypt(uint32_t mode, const BufferView & data) override;
    virtual void decrypt(uint32_t mode, const BufferView & data) override;

    virtual void set_iv(const ConstBufferView & iv) override;

    // #TODO ECB mode encrypts message blocks independently of each other
    //                      which makes it possible to encrypt them in parallel
    //                      thereby speeding up the work
    void ecb_encrypt(const BufferView & data);
    void ecb_decrypt(const BufferView & data);

    // CBC
    // buffer size MUST be mutile of AES_BLOCKLEN;
    // NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
    //        no IV should ever be reused with the same key
    void cbc_encrypt_buffer(const BufferView & data);
    void cbc_decrypt_buffer(const BufferView & data);

    void ofb_xcrypt(const BufferView & data);

    // CTR
    void ctr_xcrypt(const BufferView & data);

    bool is_iv_set() const { return IvSet; }

    virtual size_t get_length(uint32_t type) const override;

private:
    uint8_t RoundKey[PQC_AES_keyExpSize] = {0};
    uint8_t Iv[PQC_AES_IVLEN] = {0};
    uint8_t IvSet = false;
    uint32_t IvOffset = 0;
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
