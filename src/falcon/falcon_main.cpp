#include "falcon_main.h"
#include "falcon.h"

FalconFactory::FalconFactory() {}

uint32_t FalconFactory::cipher_id() const { return PQC_CIPHER_FALCON; }


std::unique_ptr<PQC_Context>
FalconFactory::create_context_asymmetric(const ConstBufferView & public_key, const ConstBufferView & private_key) const
{
    check_size_or_empty(private_key, PQC_FALCON_PRIVATE_KEYLEN);
    check_size_or_empty(public_key, PQC_FALCON_PUBLIC_KEYLEN);
    return std::make_unique<FalconContext>(public_key, private_key);
}

static inline uint8_t * align_u_16(void * use)
{
    uint8_t * ause;

    ause = (uint8_t *)use;
    if (((uintptr_t)ause & 1u) != 0)
    {
        ause++;
    }
    return ause;
}

static inline uint8_t * align_u_64(void * use)
{
    uint8_t * ause;
    unsigned flag;

    ause = (uint8_t *)use;
    flag = (uintptr_t)ause & 7u;
    if (flag != 0)
    {
        ause += 8u - flag;
    }
    return ause;
}


void FalconContext::generate_keypair()
{
    auto [public_key_view, private_key_view] = allocate_keys(PQC_FALCON_PUBLIC_KEYLEN, PQC_FALCON_PRIVATE_KEYLEN);

    shake256_context ctx;
    uint8_t seed[48];
    uint8_t tmp[PQC_FALCON_TMPSIZE_KEYGEN(10)];
    get_random_generator().random_bytes(BufferView(&seed, sizeof(seed)));
    shake_256_init_prng_from_seed(&ctx, ConstBufferView(&seed, sizeof(seed)));

    int result = 0;
    size_t pubkey_size = public_key_view.size();

    int8_t *a, *b, *A;
    uint16_t * h;
    uint8_t * ause;
    size_t elemNum, counter, flag, seckey_size;
    uint8_t *seckey, *pk;
    unsigned oldcw;


    if (private_key_view.size() < PQC_FALCON_PRIVKEY_SIZE(10) ||
        (public_key_view.data() != NULL && pubkey_size < PQC_FALCON_PUBKEY_SIZE(10)))
    {
        result = FALCON_ERR_SIZE;
    }

    elemNum = (size_t)1 << 10;
    a = (int8_t *)tmp;
    b = a + elemNum;
    A = b + elemNum;
    ause = align_u_64(A + elemNum);
    oldcw = set_fpu_cw(2);
    keygen((inner_shake256_context *)&ctx, a, b, A, NULL, NULL, 10, ause);
    set_fpu_cw(oldcw);


    seckey = private_key_view.data();
    seckey_size = PQC_FALCON_PRIVKEY_SIZE(10);
    seckey[0] = 0x50 + static_cast<uint8_t>(10);
    counter = 1;
    flag = trim_i_8_encode(seckey + counter, seckey_size - counter, a, 10, max_fg_bits[10]);
    if (flag == 0)
    {
        result = FALCON_ERR_INTERNAL;
    }
    counter += flag;
    flag = trim_i_8_encode(seckey + counter, seckey_size - counter, b, 10, max_fg_bits[10]);
    if (flag == 0)
    {
        result = FALCON_ERR_INTERNAL;
    }
    counter += flag;
    flag = trim_i_8_encode(seckey + counter, seckey_size - counter, A, 10, max_FG_bits[10]);
    if (flag == 0)
    {
        result = FALCON_ERR_INTERNAL;
    }
    counter += flag;
    if (counter != seckey_size)
    {
        result = FALCON_ERR_INTERNAL;
    }

    if (public_key_view.data() != NULL)
    {
        h = (uint16_t *)align_u_16(b + elemNum);
        ause = (uint8_t *)(h + elemNum);
        if (!compute_public(h, a, b, 10, ause))
        {
            result = FALCON_ERR_INTERNAL;
        }
        pk = public_key_view.data();
        pubkey_size = PQC_FALCON_PUBKEY_SIZE(10);
        pk[0] = 0x00 + static_cast<uint8_t>(10);
        flag = modq_encode(pk + 1, pubkey_size - 1, h, 10);
        if (flag != pubkey_size - 1)
        {
            result = FALCON_ERR_INTERNAL;
        }
    }
    if (result)
    {
        throw InternalError();
    }
}


bool FalconContext::verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const
{

    if (signature.size() != PQC_FALCON_SIGNATURE_LEN)
    {
        throw BadLength();
    }

    uint8_t tmp[PQC_FALCON_TMPSIZE_VERIFY(10)];

    int result = 0;
    shake256_context a;
    int rez;

    rez = falcon_verify_start(&a, signature);
    if (rez < 0)
    {
        result = rez;
    }
    else
    {
        shake_256_inject(&a, buffer);
        result = falcon_verify_finish(
            signature, FALCON_SIG_PADDED, public_key(), &a, BufferView(tmp, PQC_FALCON_TMPSIZE_VERIFY(10))
        );
    }
    if (result == 0)
    {
        return true;
    }

    return false;
}


size_t FalconFactory::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_PUBLIC:
        return PQC_FALCON_PUBLIC_KEYLEN;
    case PQC_LENGTH_PRIVATE:
        return PQC_FALCON_PRIVATE_KEYLEN;
    case PQC_LENGTH_SIGNATURE:
        return PQC_FALCON_SIGNATURE_LEN;
    }
    return 0;
}

size_t FalconContext::get_length(uint32_t type) const { return FalconFactory().get_length(type); }


void FalconContext::create_signature(const ConstBufferView & buffer, const BufferView & signature)
{
    if (signature.size() != PQC_FALCON_SIGNATURE_LEN)
    {
        throw BadLength();
    }

    shake256_context c;
    uint8_t nonce[40];
    const BufferView nonce_buf(&nonce, sizeof(nonce));
    get_random_generator().random_bytes(nonce_buf);

    falcon_sign_start(nonce_buf, &c);
    shake_256_inject(&c, buffer);

    uint8_t tmp[PQC_FALCON_TMPSIZE_SIGNDYN(10)];
    int result = falcon_sign_dyn_finish(
        signature, FALCON_SIG_PADDED, private_key(), &c, nonce, ConstBufferView(tmp, PQC_FALCON_TMPSIZE_SIGNDYN(10)),
        &get_random_generator()
    );

    if (result)
    {
        throw PQC_INTERNAL_ERROR;
    }
}
