#include "ml-kem.h"

#include <pqc/ml-kem.h>

#include <buffer.h>
#include <mlkem/indcpa.h>
#include <mlkem/params.h>
#include <mlkem/symmetric.h>
#include <mlkem/verify.h>
#include <rng/rng.h>


uint32_t MLKEMFactory::cipher_id() const { return PQC_CIPHER_ML_KEM; }

std::unique_ptr<PQC_Context> MLKEMFactory::create_context(const ConstBufferView & private_key) const
{
    if (private_key.size() != PQC_ML_KEM_PRIVATE_KEYLEN)
    {
        throw BadLength();
    }
    return std::make_unique<MLKEMContext>(reinterpret_cast<const pqc_ml_kem_private_key *>(private_key.const_data()));
}

void MLKEMFactory::generate_keypair(const BufferView & public_key, const BufferView & private_key) const
{
    if (private_key.size() != PQC_ML_KEM_PRIVATE_KEYLEN || public_key.size() != PQC_ML_KEM_PUBLIC_KEYLEN)
    {
        throw BadLength();
    }
    indcpa_keypair_mlkem(public_key, private_key.mid(0, KYBER_INDCPA_SECRETKEYBYTES));
    private_key.mid(KYBER_INDCPA_SECRETKEYBYTES, PQC_ML_KEM_PUBLIC_KEYLEN).store(public_key);
    hash_h(private_key.data() + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, public_key.data(), KYBER_PUBLICKEYBYTES);
    randombytes(private_key.mid(KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES));
}

void MLKEMFactory::kem_encode_secret(
    const BufferView & message, const ConstBufferView public_key, const BufferView & shared_secret
) const
{
    if (message.size() != PQC_ML_KEM_MESSAGE_LENGTH || shared_secret.size() != PQC_ML_KEM_SHARED_LENGTH ||
        public_key.size() != PQC_ML_KEM_PUBLIC_KEYLEN)
    {
        throw BadLength();
    }

    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];

    randombytes(BufferView(&buf, KYBER_SYMBYTES));

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf + KYBER_SYMBYTES, public_key.const_data(), KYBER_PUBLICKEYBYTES);
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(message.data(), buf, public_key.const_data(), kr + KYBER_SYMBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr + KYBER_SYMBYTES, message.data(), KYBER_CIPHERTEXTBYTES);
    shared_secret.store(ConstBufferView(kr, KYBER_SYMBYTES));
}

size_t MLKEMFactory::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_PUBLIC:
        return PQC_ML_KEM_PUBLIC_KEYLEN;
    case PQC_LENGTH_PRIVATE:
        return PQC_ML_KEM_PRIVATE_KEYLEN;
    case PQC_LENGTH_MESSAGE:
        return PQC_ML_KEM_MESSAGE_LENGTH;
    case PQC_LENGTH_SHARED:
        return PQC_ML_KEM_SHARED_LENGTH;
    }
    return 0;
}

void MLKEMContext::kem_decode_secret(ConstBufferView message, BufferView shared_secret) const
{
    if (message.size() != PQC_ML_KEM_MESSAGE_LENGTH || shared_secret.size() != PQC_ML_KEM_SHARED_LENGTH)
    {
        throw BadLength();
    }

    size_t i;
    int fail;
    uint8_t buf[2 * KYBER_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * KYBER_SYMBYTES];
    uint8_t cmp[KYBER_CIPHERTEXTBYTES];

    const uint8_t * sk = ConstBufferView(private_key_).const_data();
    const uint8_t * pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    indcpa_dec(buf, message.const_data(), sk);

    /* Multitarget countermeasure for coins + contributory KEM */
    for (i = 0; i < KYBER_SYMBYTES; i++)
        buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];
    hash_g(kr, buf, 2 * KYBER_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES */
    indcpa_enc(cmp, buf, pk, kr + KYBER_SYMBYTES);

    fail = verify(message.const_data(), cmp, KYBER_CIPHERTEXTBYTES);

    /* overwrite coins in kr with H(c) */
    hash_h(kr + KYBER_SYMBYTES, message.const_data(), KYBER_CIPHERTEXTBYTES);

    /* Overwrite pre-k with z on re-encryption failure */
    cmov(kr, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES, static_cast<uint8_t>(fail));

    if (fail)
    {
        uint8_t z_ct[KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES];
        BufferView x(z_ct, KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES);
        x.mid(0, KYBER_SYMBYTES).store(ConstBufferView(kr, KYBER_SYMBYTES));
        x.mid(KYBER_SYMBYTES, KYBER_CIPHERTEXTBYTES).store(message);
        kdf(shared_secret.data(), x.const_data(), x.size());
    }
    else
    {
        shared_secret.store(ConstBufferView(kr, KYBER_SYMBYTES));
    }
}

size_t MLKEMContext::get_length(uint32_t type) const { return MLKEMFactory().get_length(type); }
