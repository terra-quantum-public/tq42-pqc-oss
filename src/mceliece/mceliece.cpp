#include "mceliece.h"

#include <array>
#include <cstring>
#include <vector>

#include <pqc/mceliece.h>

#include <buffer.h>
#include <mceliece/controlbits.h>
#include <mceliece/crypto_hash.h>
#include <mceliece/decrypt.h>
#include <mceliece/encrypt.h>
#include <mceliece/params.h>
#include <mceliece/pk_gen.h>
#include <mceliece/sk_gen.h>
#include <rng/rng.h>


uint32_t McElieceFactory::cipher_id() const { return PQC_CIPHER_MCELIECE; }

std::unique_ptr<PQC_Context> McElieceFactory::create_context(const ConstBufferView & private_key) const
{
    if (private_key.size() != PQC_MCELIECE_PRIVATE_KEYLEN)
    {
        throw BadLength();
    }
    return std::make_unique<McElieceContext>(reinterpret_cast<const pqc_mceliece_private_key *>(private_key.const_data()
    ));
}

void McElieceFactory::generate_keypair(const BufferView & public_key, const BufferView & private_key) const
{
    if (private_key.size() != PQC_MCELIECE_PRIVATE_KEYLEN || public_key.size() != PQC_MCELIECE_PUBLIC_KEYLEN)
    {
        throw BadLength();
    }

    constexpr size_t seed_size = 32;
    randombytes(private_key.mid(0, seed_size));

    static_assert(seed_size + 8 + IRR_BYTES + COND_BYTES + (SYS_N >> 3) == PQC_MCELIECE_PRIVATE_KEYLEN);
    static_assert(IRR_BYTES == SYS_T << 1);

    while (true)
    {
        /// private_key: [ 0:seed | seed_size:pivots | seed_size+8:irr | cond | random ]
        /// a: [ random | perm | f ]

        std::array<uint8_t, (SYS_N >> 3) + (1 << (GFBITS + 2)) + (SYS_T << 1)> a;

        /// See known answers test for 256-bit keys generation.
        randombytes(a);
        const auto & a_const_buffer = ConstBufferView(a);
        const auto & a_buffer = BufferView(a);

        uint16_t c[SYS_T];
        auto a_f = a_const_buffer.mid((SYS_N >> 3) + (1 << (GFBITS + 2)), SYS_T << 1);
        for (size_t i = 0; i < SYS_T; ++i)
        {
            c[i] = a_f.load_16_le(i) & GFMASK; // FIXME can apply mask inplace
        }

        uint16_t d[SYS_T];
        if (!mceliece_8192128_f_genpoly_gen(d, c))
        {
            continue;
        }

        private_key.mid(seed_size + 8, SYS_T << 1)
            .store(ConstBufferView(d, SYS_T << 1)); // FIXME probably no need for extra variable?

        auto pivots = private_key.mid(seed_size, 8);
        auto irr = private_key.mid(seed_size + 8, SYS_T << 1);
        auto perm = a_const_buffer.mid(SYS_N >> 3, 1 << (GFBITS + 2));
        std::array<int16_t, 1 << GFBITS> pi;

        if (!mceliece_8192128_f_pk_gen(
                public_key,
                reinterpret_cast<const uint32_t *>(perm.const_data()), // TODO perm.as<uint32_t[N]>()
                irr, pi.data(),
                *reinterpret_cast<uint64_t *>(pivots.data()) // TODO pivots.as<uint64_t>()
            ))
        {
            continue;
        }

        auto cond = private_key.mid(seed_size + 8 + IRR_BYTES, COND_BYTES);
        mceliece_8192128_f_controlbits_perm(cond.data(), pi.data());

        auto random = private_key.mid(seed_size + 8 + IRR_BYTES + COND_BYTES, SYS_N >> 3);
        random.store(a_buffer.mid(0, SYS_N >> 3));
        break;
    }
}

void McElieceFactory::kem_encode_secret(
    const BufferView & message, const ConstBufferView public_key, const BufferView & shared_secret
) const
{
    if (message.size() != PQC_MCELIECE_MESSAGE_LENGTH || shared_secret.size() != PQC_MCELIECE_SHARED_LENGTH ||
        public_key.size() != PQC_MCELIECE_PUBLIC_KEYLEN)
    {
        throw BadLength();
    }

    std::array<uint8_t, (SYS_N >> 3)> k;
    std::array<uint8_t, 1 + (SYS_N >> 3) + SYND_BYTES> ecOne = {1};

    mceliece_8192128_f_encrypt(message.data(), k.data(), public_key.const_data());

    BufferView(ecOne).mid(1, SYS_N >> 3).store(k);
    BufferView(ecOne).mid(1 + (SYS_N >> 3), SYND_BYTES).store(message.mid(0, SYND_BYTES));

    sha_3_hash_256(shared_secret.mid(0, 32), ecOne);
}

size_t McElieceFactory::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_PUBLIC:
        return PQC_MCELIECE_PUBLIC_KEYLEN;
    case PQC_LENGTH_PRIVATE:
        return PQC_MCELIECE_PRIVATE_KEYLEN;
    case PQC_LENGTH_MESSAGE:
        return PQC_MCELIECE_MESSAGE_LENGTH;
    case PQC_LENGTH_SHARED:
        return PQC_MCELIECE_SHARED_LENGTH;
    }
    return 0;
}

void McElieceContext::kem_decode_secret(ConstBufferView message, BufferView shared_secret) const
{
    if (message.size() != PQC_MCELIECE_MESSAGE_LENGTH || shared_secret.size() != PQC_MCELIECE_SHARED_LENGTH)
    {
        throw BadLength();
    }

    std::array<uint8_t, (SYS_N >> 3)> k = {0};
    std::array<uint8_t, 1 + (SYS_N >> 3) + SYND_BYTES> prePic;

    uint16_t l =
        mceliece_8192128_f_decrypt(k.data(), ConstBufferView(private_key_).mid(40, std::nullopt), message.const_data());
    l -= 1;
    l >>= 8;

    uint8_t * x = prePic.data();
    const uint8_t * s = ConstBufferView(private_key_).mid(40 + IRR_BYTES + COND_BYTES, std::nullopt).const_data();
    *x++ = l & 1;

    for (size_t i = 0; i < SYS_N >> 3; i++)
    {
        *x++ = (~l & s[i]) | (l & k[i]);
    }
    for (size_t i = 0; i < SYND_BYTES; i++)
    {
        *x++ = message.const_data()[i];
    }

    sha_3_hash_256(shared_secret, prePic);
}

size_t McElieceContext::get_length(uint32_t type) const { return McElieceFactory().get_length(type); }
