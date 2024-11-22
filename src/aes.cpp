#include "aes.h"
#include "vector128.h"
#include <array>
#include <string.h>

#define Nb 4
#define Nk 8
#define Nr 14

typedef uint8_t state_t[4][4];


static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
    0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
    0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
    0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
    0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
    0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
    0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39,
    0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2,
    0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76,
    0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc,
    0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d,
    0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c,
    0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f,
    0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62,
    0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd,
    0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
    0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
    0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

static const uint8_t Rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};


void rot_word(uint8_t * a)
{
    const uint8_t tmp = a[0];
    unsigned i;
    for (i = 0; i < 4; ++i)
    {
        if (i == 3)
        {
            a[i] = tmp;
            break;
        }
        a[i] = a[i + 1];
    }
}

void sub_word(uint8_t * a)
{
    uint8_t i;
    for (i = 0; i < 4; ++i)
        a[i] = sbox[a[i]];
}

static void key_expansion(uint8_t * RoundKey, const pqc_aes_key * Key)
{
    uint8_t i, j;
    uint8_t temp[4];

    for (i = 0; i < Nk; ++i)
        for (j = 0; j < 4; ++j)
            RoundKey[(i * 4) + j] = Key->key[(i * 4) + j];

    for (i = Nk; i < Nb * (Nr + 1); ++i)
    {
        for (j = 0; j < 4; ++j)
            temp[j] = RoundKey[(i - 1) * 4 + j];

        if (i % Nk == 0)
        {
            rot_word(temp);
            sub_word(temp);
            temp[0] ^= Rcon[i / Nk];
        }

        if (Nk > 6 && i % Nk == 4)
            sub_word(temp);

        for (j = 0; j < 4; ++j)
            RoundKey[i * 4 + j] = RoundKey[(i - Nk) * 4 + j] ^ temp[j];
    }
}

AES::AES(const ConstBufferView & key)
{
    key_expansion(RoundKey_.data(), (const pqc_aes_key *)key.const_data());
    IvSet_ = 0;
}

AES::AES(const ConstBufferView & key, const ConstBufferView & iv)
{
    key_expansion(RoundKey_.data(), (const pqc_aes_key *)key.const_data());
    Iv_.store(iv);
    IvSet_ = 1;
}

void AES::set_iv(const ConstBufferView & iv)
{
    if (iv.size() != PQC_AES_BLOCKLEN)
    {
        throw BadLength();
    }
    Iv_.store(iv);
    IvSet_ = 1;
}

static void add_round_key(uint8_t round, state_t * state, const uint8_t * RoundKey)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
        for (j = 0; j < 4; ++j)
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
}

static void sub_bytes(state_t * state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
        for (j = 0; j < 4; ++j)
            (*state)[j][i] = sbox[((*state)[j][i])];
}


static void inv_sub_bytes(state_t * state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = rsbox[(*state)[j][i]];
        }
    }
}

void sub_shift(state_t * state, uint8_t nr, uint8_t s)
{
    uint8_t temp, i;
    if (s == 2)
    {
        uint8_t temp1, temp2;
        temp1 = (*state)[0][nr];
        temp2 = (*state)[1][nr];

        (*state)[0][nr] = (*state)[2][nr];
        (*state)[1][nr] = (*state)[3][nr];
        (*state)[2][nr] = temp1;
        (*state)[3][nr] = temp2;
    }

    else if (s == 1)
    {
        temp = (*state)[0][nr];
        for (i = 0; i < 4; ++i)
        {
            if (i == 3)
            {
                (*state)[i][nr] = temp;
                break;
            }
            (*state)[i][nr] = (*state)[(i + 1) % 4][nr];
        }
    }

    else
    {
        temp = (*state)[3][nr];
        for (i = 3; i >= 0; --i)
        {
            if (i == 0)
            {
                (*state)[i][nr] = temp;
                break;
            }
            (*state)[i][nr] = (*state)[i - 1][nr];
        }
    }
}

void inv_sub_shift(state_t * state, uint8_t nr, uint8_t s) { sub_shift(state, nr, 4 - s); }

static void shift_rows(state_t * state)
{
    uint8_t i;
    for (i = 1; i < 4; ++i)
        sub_shift(state, i, i);
}

static void inv_shift_rows(state_t * state)
{
    uint8_t i;
    for (i = 1; i < 4; ++i)
        inv_sub_shift(state, i, i);
}

static uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }

static uint8_t multiply(uint8_t x, uint8_t y)
{
    return (
        ((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^
        ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))
    );
}

static void mix_columns(state_t * state)
{
    uint8_t i, j;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        for (j = 0; j < 4; ++j)
        {
            if (j == 3)
            {
                Tm = (*state)[i][j] ^ t;
                Tm = xtime(Tm);
                (*state)[i][j] ^= Tm ^ Tmp;
                break;
            }

            Tm = (*state)[i][j] ^ (*state)[i][j + 1];
            Tm = xtime(Tm);
            (*state)[i][j] ^= Tm ^ Tmp;
        }
    }
}

static void inv_mix_columns(state_t * state)
{
    uint8_t i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i)
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        (*state)[i][1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        (*state)[i][2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        (*state)[i][3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

static void cipher(const BufferView & state, const ConstBufferView & round_key)
{
#ifndef NDEBUG
    if (state.size() != sizeof(state_t) || round_key.size() != PQC_AES_keyExpSize)
    {
        throw std::invalid_argument("Bad buffer size");
    }
#endif
    const uint8_t * const key_ptr = round_key.const_data();
    state_t * const state_ptr = (state_t *)state.data();

    uint8_t round = 0;
    add_round_key(0, state_ptr, key_ptr);

    for (round = 1;; ++round)
    {
        sub_bytes(state_ptr);
        shift_rows(state_ptr);
        if (round == Nr)
        {
            break;
        }
        mix_columns(state_ptr);
        add_round_key(round, state_ptr, key_ptr);
    }
    add_round_key(Nr, state_ptr, key_ptr);
}

static void inv_cipher(const BufferView & state, const ConstBufferView & round_key)
{
#ifndef NDEBUG
    if (state.size() != sizeof(state_t) || round_key.size() != PQC_AES_keyExpSize)
    {
        throw std::invalid_argument("Bad buffer size");
    }
#endif
    const uint8_t * const key_ptr = round_key.const_data();
    state_t * const state_ptr = (state_t *)state.data();

    uint8_t round = 0;
    add_round_key(Nr, state_ptr, key_ptr);

    for (round = (Nr - 1);; --round)
    {
        inv_shift_rows(state_ptr);
        inv_sub_bytes(state_ptr);
        add_round_key(round, state_ptr, key_ptr);
        if (round == 0)
        {
            break;
        }
        inv_mix_columns(state_ptr);
    }
}

void AES::ecb_encrypt(const BufferView & data)
{
    for (BufferView buf : iterate_blocks(data, PQC_AES_BLOCKLEN))
    {
        cipher(buf, RoundKey_);
    }
}

void AES::ecb_decrypt(const BufferView & data)
{
    for (BufferView buf : iterate_blocks(data, PQC_AES_BLOCKLEN))
    {
        inv_cipher(buf, RoundKey_);
    }
}

void AES::cbc_encrypt_buffer(const BufferView & data)
{
    ConstBufferView local_Iv = Iv_;

    for (BufferView buf : iterate_blocks(data, PQC_AES_BLOCKLEN))
    {
        buf ^= local_Iv;
        cipher(buf, RoundKey_);
        local_Iv = buf;
    }
    Iv_.store(local_Iv);
}


void AES::cbc_decrypt_buffer(const BufferView & data)
{
    StackBuffer<PQC_AES_BLOCKLEN> storeNextIv;

    for (BufferView buf : iterate_blocks(data, PQC_AES_BLOCKLEN))
    {
        storeNextIv.store(buf);
        inv_cipher(buf, RoundKey_);
        buf ^= Iv_;
        Iv_.store(storeNextIv);
    }
}

void AES::ofb_xcrypt(BufferView data)
{
    if (IvOffset_ != 0)
    {
        size_t size = std::min((size_t)(PQC_AES_IVLEN - IvOffset_), data.size());
        data.mid(0, size) ^= Iv_.mid(IvOffset_, size);
        if (size == data.size())
        {
            IvOffset_ = (IvOffset_ + (uint32_t)size) % PQC_AES_IVLEN;
            return;
        }
        data = data.mid(size, std::nullopt);
        IvOffset_ = 0;
    }

    auto blocks = iterate_blocks(data, PQC_AES_BLOCKLEN);

    for (BufferView buf : blocks)
    {
        cipher(Iv_, RoundKey_);
        buf ^= Iv_;
    }
    if (blocks.has_extra())
    {
        BufferView buf = blocks.extra();
        cipher(Iv_, RoundKey_);
        buf ^= Iv_.mid(0, buf.size());
        IvOffset_ = (uint32_t)buf.size();
    }
}


void AES::ctr_xcrypt(const BufferView & data)
{
    size_t length = data.size();
    StackBuffer<PQC_AES_BLOCKLEN> local_Iv;

    for (size_t data_offset = 0; data_offset < length;)
    {
        local_Iv.store(Iv_);
        cipher(local_Iv, RoundKey_);

        for (; IvOffset_ < PQC_AES_BLOCKLEN && data_offset < length; ++IvOffset_, ++data_offset)
        {
            data[data_offset] ^= local_Iv[IvOffset_];
        }

        if (IvOffset_ == PQC_AES_BLOCKLEN)
        {
            for (uint8_t carry = 1, j = PQC_AES_BLOCKLEN - 1; j != 0xFF; --j)
            {
                Iv_[j] += carry;
                carry = (carry == 1 && Iv_[j] == 0) ? 1 : 0;
            }
            IvOffset_ = 0;
        }
    }
}

size_t AES::get_length(uint32_t type) const { return AESFactory().get_length(type); }

AESFactory::AESFactory() {}

uint32_t AESFactory::cipher_id() const { return PQC_CIPHER_AES; }

std::unique_ptr<PQC_Context> AESFactory::create_context(const ConstBufferView & private_key) const
{
    if (private_key.size() != PQC_AES_KEYLEN)
        throw BadLength();

    return std::make_unique<AES>(private_key);
}

std::unique_ptr<PQC_Context>
AESFactory::create_context(const ConstBufferView & private_key, const ConstBufferView & iv) const
{
    if (private_key.size() != PQC_AES_KEYLEN)
        throw BadLength();
    if (iv.size() != PQC_AES_IVLEN)
        throw BadLength();

    return std::make_unique<AES>(private_key, iv);
}

size_t AESFactory::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_SYMMETRIC:
        return PQC_AES_KEYLEN;
    case PQC_LENGTH_IV:
        return PQC_AES_IVLEN;
    }
    return 0;
}

void AES::encrypt(uint32_t mode, const BufferView & data)
{
    switch (mode)
    {
    case PQC_AES_M_CBC:
        if (!is_iv_set())
        {
            throw IVNotSet();
        }
        if (data.size() % PQC_AES_BLOCKLEN != 0)
        {
            throw BadLength();
        }
        cbc_encrypt_buffer(data);
        return;

    case PQC_AES_M_ECB:
        if (data.size() != PQC_AES_BLOCKLEN)
        {
            throw BadLength();
        }
        ecb_encrypt(data);
        return;

    case PQC_AES_M_CTR:
        if (!is_iv_set())
        {
            throw IVNotSet();
        }
        if (data.size() == 0)
        {
            throw BadLength();
        }
        ctr_xcrypt(data);
        return;

    case PQC_AES_M_OFB:
        if (!is_iv_set())
        {
            throw IVNotSet();
        }
        ofb_xcrypt(data);
        return;

    default:
        throw BadMode();
    }
}

void AES::decrypt(uint32_t mode, const BufferView & data)
{
    switch (mode)
    {
    case PQC_AES_M_CBC:
        if (!is_iv_set())
        {
            throw IVNotSet();
        }
        if (data.size() % PQC_AES_BLOCKLEN != 0)
        {
            throw BadLength();
        }
        cbc_decrypt_buffer(data);
        return;

    case PQC_AES_M_CTR:
        if (!is_iv_set())
        {
            throw IVNotSet();
        }
        if (data.size() == 0)
        {
            throw BadLength();
        }
        ctr_xcrypt(data);
        return;

    case PQC_AES_M_ECB:
        if (data.size() != PQC_AES_BLOCKLEN)
        {
            throw BadLength();
        }
        ecb_decrypt(data);
        return;

    case PQC_AES_M_OFB:
        if (!is_iv_set())
        {
            throw IVNotSet();
        }
        ofb_xcrypt(data);
        return;

    default:
        throw BadMode();
    }
}

void AES::aead_encrypt(uint32_t mode, const BufferView & data, const ConstBufferView & aad, const BufferView & auth_tag)
{
    if (mode != PQC_AES_M_GCM)
    {
        throw BadMode();
    }

    if (!is_iv_set())
    {
        throw IVNotSet();
    }

    if (auth_tag.size() != PQC_AES_IVLEN)
    {
        throw BadLength();
    }

    HeapBuffer<PQC_AES_BLOCKLEN> iv_copy;
    iv_copy.store(Iv_);
    gcm_xcrypt(data);
    gcm_get_auth_tag(iv_copy, data, aad, auth_tag);
}

void AES::aead_decrypt(
    uint32_t mode, const BufferView & data, const ConstBufferView & aad, const ConstBufferView & auth_tag
)
{
    if (mode != PQC_AES_M_GCM)
    {
        throw BadMode();
    }

    if (!is_iv_set())
    {
        throw IVNotSet();
    }

    if (auth_tag.size() != PQC_AES_IVLEN)
    {
        throw BadLength();
    }

    if (!gcm_check_auth_tag(data, aad, auth_tag))
    {
        throw AEADVerificationError();
    }

    gcm_xcrypt(data);
}

bool AES::aead_check(
    uint32_t mode, const BufferView & data, const ConstBufferView & aad, const ConstBufferView & auth_tag
)
{
    if (mode != PQC_AES_M_GCM)
    {
        throw BadMode();
    }

    if (!is_iv_set())
    {
        throw IVNotSet();
    }

    if (auth_tag.size() != PQC_AES_IVLEN)
    {
        throw BadLength();
    }

    return gcm_check_auth_tag(data, aad, auth_tag);
}

void AES::gcm_xcrypt(const BufferView & data)
{
    StackBuffer<PQC_AES_BLOCKLEN> local_Iv;
    BufferView iv_view = BufferView::from_single(Iv_);

    BufferView fixed_local_iv_part = local_Iv.mid(0, local_Iv.size() - 4);
    fixed_local_iv_part.store(Iv_.mid(0, fixed_local_iv_part.size()));

    uint32_t counter = iv_view.load_32_be(3);
    ++counter;
    local_Iv.store_32_be(3, counter);

    auto data_blocks = iterate_blocks(data, PQC_AES_BLOCKLEN);

    for (BufferView block : data_blocks)
    {
        cipher(local_Iv, RoundKey_); // can be generated before started encryption
        block ^= local_Iv;
        fixed_local_iv_part.store(Iv_.mid(0, fixed_local_iv_part.size()));
        ++counter;
        local_Iv.store_32_be(3, counter);
    }
    if (data_blocks.has_extra())
    {
        BufferView extra_data = data_blocks.extra();
        cipher(local_Iv, RoundKey_); // can be generated before started encryption
        extra_data ^= local_Iv.mid(0, extra_data.size());
    }
    iv_view.store_32_be(3, counter);
}


using MTable = std::array<Vector128, 16>;

static MTable build_M(const ConstBufferView & h)
{
    MTable M;
    Vector128 v;

    v.load_be(h);

    M[8] = v;

    for (int i = 4; i > 0; i >>= 1)
    {
        uint32_t T = (uint32_t)(v.lo64() & 1) * 0xE1000000;
        v.shr<1>();
        v.hi64() ^= ((uint64_t)T << 32);
        M[i] = v;
    }
    for (int i = 2; i < 16; i <<= 1)
    {
        Vector128 * M_i = M.data() + i;
        v = *M_i;
        for (int j = 1; j < i; j++)
        {
            M_i[j] = v;
            M_i[j] ^= M[j];
        }
    }

    return M;
}

static void mod_polynomial_mult_M(BufferView x, const MTable & M)
{
    static const uint16_t R[16] = {0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
                                   0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0};

    uint8_t lo, hi, reminder;
    Vector128 z;

    lo = (uint8_t)(x[15] & 0x0f);
    hi = (uint8_t)(x[15] >> 4);
    z = M[lo];

    reminder = (uint8_t)(z.lo64() & 0x0F);
    z.shr<4>();
    z.hi64() ^= (uint64_t)R[reminder] << 48;
    z ^= M[hi];

    for (int i = 14; i >= 0; i--)
    {
        lo = (uint8_t)(x[i] & 0x0f);
        hi = (uint8_t)(x[i] >> 4);

        reminder = (uint8_t)(z.lo64() & 0x0F);
        z.shr<4>();
        z.hi64() ^= (uint64_t)R[reminder] << 48;
        z ^= M[lo];

        reminder = (uint8_t)(z.lo64() & 0x0F);
        z.shr<4>();
        z.hi64() ^= (uint64_t)R[reminder] << 48;
        z ^= M[hi];
    }

    z.store_be(x);
}

void addBlockIntoAutTeg(ConstBufferView cipherTextBlock, BufferView AutTag, const MTable & M)
{
#ifndef NDEBUG
    if (AutTag.size() != PQC_AES_BLOCKLEN || cipherTextBlock.size() != PQC_AES_BLOCKLEN)
    {
        throw std::invalid_argument("Bad buffer size");
    }
#endif

    AutTag ^= cipherTextBlock;
    mod_polynomial_mult_M(AutTag, M);
}

void getATagBlock(ConstBufferView AutData, const MTable & M, BufferView resultA)
{
    // AutDataLength should be: AutDataLength == PQC_AES_BLOCKLEN*n

#ifndef NDEBUG
    if (resultA.size() != PQC_AES_BLOCKLEN)
    {
        throw std::invalid_argument("Bad buffer size");
    }
#endif

    auto data_blocks = iterate_blocks(AutData, PQC_AES_BLOCKLEN);

    for (ConstBufferView block : data_blocks)
    {
        resultA ^= block;
        mod_polynomial_mult_M(resultA, M);
    }

    if (data_blocks.has_extra())
    {
        StackBuffer<PQC_AES_BLOCKLEN> specialBuffer1;
        ConstBufferView extra_data = data_blocks.extra();

        specialBuffer1.mid(0, extra_data.size()).store(extra_data);

        resultA ^= specialBuffer1;
        mod_polynomial_mult_M(resultA, M);
    }
}

void AES::gcm_get_auth_tag(
    const ConstBufferView & iv_view, const ConstBufferView & data, const ConstBufferView & aad,
    const BufferView & auth_tag
)
{
    StackBuffer<PQC_AES_BLOCKLEN> H;
    cipher(H, RoundKey_);
    MTable M = build_M(H);

    auth_tag.fill(0);

    getATagBlock(aad, M, auth_tag);

    getATagBlock(data, M, auth_tag);

    // Last part with length of Associated Data concatenated with 64 bit representation of length of ciphertext
    StackBuffer<PQC_AES_BLOCKLEN> buffer;

    uint64_t lenBuf = 0ULL;

    lenBuf = aad.size() * 8;
    buffer.store_64_be(0, lenBuf);

    lenBuf = data.size() * 8;
    buffer.store_64_be(1, lenBuf);

    addBlockIntoAutTeg(buffer, auth_tag, M);

    buffer.store(iv_view);
    cipher(buffer, RoundKey_);

    auth_tag ^= buffer;
}


bool AES::gcm_check_auth_tag(
    const ConstBufferView & data, const ConstBufferView & aad, const ConstBufferView & auth_tag
)
{
    StackBuffer<PQC_AES_BLOCKLEN> AutTag;
    gcm_get_auth_tag(Iv_, data, aad, AutTag);

    // check AutTag
    bool result = true;
    for (int i = 0; i < PQC_AES_BLOCKLEN; i++)
        if (auth_tag.const_data()[i] != AutTag[i])
            result = false;

    return result;
}
