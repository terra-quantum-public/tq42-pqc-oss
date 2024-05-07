#include "falcon.h"

#include <cstdint>

#include <buffer.h>


static const uint64_t RC[] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
                              0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                              0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
                              0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
                              0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
                              0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

static void process_block(uint64_t * inp)
{
    uint64_t a0, a1, a2, a3, a4;
    uint64_t a00, a10, a20, a30;
    uint64_t k, l;
    uint64_t b0, b1, b2, b3, b4, bnn;
    int j;

    inp[1] = ~inp[1];
    inp[2] = ~inp[2];
    inp[8] = ~inp[8];
    inp[12] = ~inp[12];
    inp[17] = ~inp[17];
    inp[20] = ~inp[20];


    for (j = 0; j < 24; j += 2)
    {

        a00 = inp[1] ^ inp[6];
        a10 = inp[11] ^ inp[16];
        a00 ^= inp[21] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[4] ^ inp[9];
        a30 = inp[14] ^ inp[19];
        a00 ^= inp[24];
        a20 ^= a30;
        a0 = a00 ^ a20;

        a00 = inp[2] ^ inp[7];
        a10 = inp[12] ^ inp[17];
        a00 ^= inp[22] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[0] ^ inp[5];
        a30 = inp[10] ^ inp[15];
        a00 ^= inp[20];
        a20 ^= a30;
        a1 = a00 ^ a20;

        a00 = inp[3] ^ inp[8];
        a10 = inp[13] ^ inp[18];
        a00 ^= inp[23] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[1] ^ inp[6];
        a30 = inp[11] ^ inp[16];
        a00 ^= inp[21];
        a20 ^= a30;
        a2 = a00 ^ a20;

        a00 = inp[4] ^ inp[9];
        a10 = inp[14] ^ inp[19];
        a00 ^= inp[24] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[2] ^ inp[7];
        a30 = inp[12] ^ inp[17];
        a00 ^= inp[22];
        a20 ^= a30;
        a3 = a00 ^ a20;

        a00 = inp[0] ^ inp[5];
        a10 = inp[10] ^ inp[15];
        a00 ^= inp[20] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[3] ^ inp[8];
        a30 = inp[13] ^ inp[18];
        a00 ^= inp[23];
        a20 ^= a30;
        a4 = a00 ^ a20;

        inp[0] = inp[0] ^ a0;
        inp[5] = inp[5] ^ a0;
        inp[10] = inp[10] ^ a0;
        inp[15] = inp[15] ^ a0;
        inp[20] = inp[20] ^ a0;
        inp[1] = inp[1] ^ a1;
        inp[6] = inp[6] ^ a1;
        inp[11] = inp[11] ^ a1;
        inp[16] = inp[16] ^ a1;
        inp[21] = inp[21] ^ a1;
        inp[2] = inp[2] ^ a2;
        inp[7] = inp[7] ^ a2;
        inp[12] = inp[12] ^ a2;
        inp[17] = inp[17] ^ a2;
        inp[22] = inp[22] ^ a2;
        inp[3] = inp[3] ^ a3;
        inp[8] = inp[8] ^ a3;
        inp[13] = inp[13] ^ a3;
        inp[18] = inp[18] ^ a3;
        inp[23] = inp[23] ^ a3;
        inp[4] = inp[4] ^ a4;
        inp[9] = inp[9] ^ a4;
        inp[14] = inp[14] ^ a4;
        inp[19] = inp[19] ^ a4;
        inp[24] = inp[24] ^ a4;
        inp[5] = (inp[5] << 36) | (inp[5] >> (64 - 36));
        inp[10] = (inp[10] << 3) | (inp[10] >> (64 - 3));
        inp[15] = (inp[15] << 41) | (inp[15] >> (64 - 41));
        inp[20] = (inp[20] << 18) | (inp[20] >> (64 - 18));
        inp[1] = (inp[1] << 1) | (inp[1] >> (64 - 1));
        inp[6] = (inp[6] << 44) | (inp[6] >> (64 - 44));
        inp[11] = (inp[11] << 10) | (inp[11] >> (64 - 10));
        inp[16] = (inp[16] << 45) | (inp[16] >> (64 - 45));
        inp[21] = (inp[21] << 2) | (inp[21] >> (64 - 2));
        inp[2] = (inp[2] << 62) | (inp[2] >> (64 - 62));
        inp[7] = (inp[7] << 6) | (inp[7] >> (64 - 6));
        inp[12] = (inp[12] << 43) | (inp[12] >> (64 - 43));
        inp[17] = (inp[17] << 15) | (inp[17] >> (64 - 15));
        inp[22] = (inp[22] << 61) | (inp[22] >> (64 - 61));
        inp[3] = (inp[3] << 28) | (inp[3] >> (64 - 28));
        inp[8] = (inp[8] << 55) | (inp[8] >> (64 - 55));
        inp[13] = (inp[13] << 25) | (inp[13] >> (64 - 25));
        inp[18] = (inp[18] << 21) | (inp[18] >> (64 - 21));
        inp[23] = (inp[23] << 56) | (inp[23] >> (64 - 56));
        inp[4] = (inp[4] << 27) | (inp[4] >> (64 - 27));
        inp[9] = (inp[9] << 20) | (inp[9] >> (64 - 20));
        inp[14] = (inp[14] << 39) | (inp[14] >> (64 - 39));
        inp[19] = (inp[19] << 8) | (inp[19] >> (64 - 8));
        inp[24] = (inp[24] << 14) | (inp[24] >> (64 - 14));

        bnn = ~inp[12];
        l = inp[6] | inp[12];
        b0 = inp[0] ^ l;
        l = bnn | inp[18];
        b1 = inp[6] ^ l;
        l = inp[18] & inp[24];
        b2 = inp[12] ^ l;
        l = inp[24] | inp[0];
        b3 = inp[18] ^ l;
        l = inp[0] & inp[6];
        b4 = inp[24] ^ l;
        inp[0] = b0;
        inp[6] = b1;
        inp[12] = b2;
        inp[18] = b3;
        inp[24] = b4;
        bnn = ~inp[22];
        l = inp[9] | inp[10];
        b0 = inp[3] ^ l;
        l = inp[10] & inp[16];
        b1 = inp[9] ^ l;
        l = inp[16] | bnn;
        b2 = inp[10] ^ l;
        l = inp[22] | inp[3];
        b3 = inp[16] ^ l;
        l = inp[3] & inp[9];
        b4 = inp[22] ^ l;
        inp[3] = b0;
        inp[9] = b1;
        inp[10] = b2;
        inp[16] = b3;
        inp[22] = b4;
        bnn = ~inp[19];
        l = inp[7] | inp[13];
        b0 = inp[1] ^ l;
        l = inp[13] & inp[19];
        b1 = inp[7] ^ l;
        l = bnn & inp[20];
        b2 = inp[13] ^ l;
        l = inp[20] | inp[1];
        b3 = bnn ^ l;
        l = inp[1] & inp[7];
        b4 = inp[20] ^ l;
        inp[1] = b0;
        inp[7] = b1;
        inp[13] = b2;
        inp[19] = b3;
        inp[20] = b4;
        bnn = ~inp[17];
        l = inp[5] & inp[11];
        b0 = inp[4] ^ l;
        l = inp[11] | inp[17];
        b1 = inp[5] ^ l;
        l = bnn | inp[23];
        b2 = inp[11] ^ l;
        l = inp[23] & inp[4];
        b3 = bnn ^ l;
        l = inp[4] | inp[5];
        b4 = inp[23] ^ l;
        inp[4] = b0;
        inp[5] = b1;
        inp[11] = b2;
        inp[17] = b3;
        inp[23] = b4;
        bnn = ~inp[8];
        l = bnn & inp[14];
        b0 = inp[2] ^ l;
        l = inp[14] | inp[15];
        b1 = bnn ^ l;
        l = inp[15] & inp[21];
        b2 = inp[14] ^ l;
        l = inp[21] | inp[2];
        b3 = inp[15] ^ l;
        l = inp[2] & inp[8];
        b4 = inp[21] ^ l;
        inp[2] = b0;
        inp[8] = b1;
        inp[14] = b2;
        inp[15] = b3;
        inp[21] = b4;
        inp[0] = inp[0] ^ RC[j + 0];

        a00 = inp[6] ^ inp[9];
        a10 = inp[7] ^ inp[5];
        a00 ^= inp[8] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[24] ^ inp[22];
        a30 = inp[20] ^ inp[23];
        a00 ^= inp[21];
        a20 ^= a30;
        a0 = a00 ^ a20;

        a00 = inp[12] ^ inp[10];
        a10 = inp[13] ^ inp[11];
        a00 ^= inp[14] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[0] ^ inp[3];
        a30 = inp[1] ^ inp[4];
        a00 ^= inp[2];
        a20 ^= a30;
        a1 = a00 ^ a20;

        a00 = inp[18] ^ inp[16];
        a10 = inp[19] ^ inp[17];
        a00 ^= inp[15] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[6] ^ inp[9];
        a30 = inp[7] ^ inp[5];
        a00 ^= inp[8];
        a20 ^= a30;
        a2 = a00 ^ a20;

        a00 = inp[24] ^ inp[22];
        a10 = inp[20] ^ inp[23];
        a00 ^= inp[21] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[12] ^ inp[10];
        a30 = inp[13] ^ inp[11];
        a00 ^= inp[14];
        a20 ^= a30;
        a3 = a00 ^ a20;

        a00 = inp[0] ^ inp[3];
        a10 = inp[1] ^ inp[4];
        a00 ^= inp[2] ^ a10;
        a00 = (a00 << 1) | (a00 >> 63);
        a20 = inp[18] ^ inp[16];
        a30 = inp[19] ^ inp[17];
        a00 ^= inp[15];
        a20 ^= a30;
        a4 = a00 ^ a20;

        inp[0] = inp[0] ^ a0;
        inp[3] = inp[3] ^ a0;
        inp[1] = inp[1] ^ a0;
        inp[4] = inp[4] ^ a0;
        inp[2] = inp[2] ^ a0;
        inp[6] = inp[6] ^ a1;
        inp[9] = inp[9] ^ a1;
        inp[7] = inp[7] ^ a1;
        inp[5] = inp[5] ^ a1;
        inp[8] = inp[8] ^ a1;
        inp[12] = inp[12] ^ a2;
        inp[10] = inp[10] ^ a2;
        inp[13] = inp[13] ^ a2;
        inp[11] = inp[11] ^ a2;
        inp[14] = inp[14] ^ a2;
        inp[18] = inp[18] ^ a3;
        inp[16] = inp[16] ^ a3;
        inp[19] = inp[19] ^ a3;
        inp[17] = inp[17] ^ a3;
        inp[15] = inp[15] ^ a3;
        inp[24] = inp[24] ^ a4;
        inp[22] = inp[22] ^ a4;
        inp[20] = inp[20] ^ a4;
        inp[23] = inp[23] ^ a4;
        inp[21] = inp[21] ^ a4;
        inp[3] = (inp[3] << 36) | (inp[3] >> (64 - 36));
        inp[1] = (inp[1] << 3) | (inp[1] >> (64 - 3));
        inp[4] = (inp[4] << 41) | (inp[4] >> (64 - 41));
        inp[2] = (inp[2] << 18) | (inp[2] >> (64 - 18));
        inp[6] = (inp[6] << 1) | (inp[6] >> (64 - 1));
        inp[9] = (inp[9] << 44) | (inp[9] >> (64 - 44));
        inp[7] = (inp[7] << 10) | (inp[7] >> (64 - 10));
        inp[5] = (inp[5] << 45) | (inp[5] >> (64 - 45));
        inp[8] = (inp[8] << 2) | (inp[8] >> (64 - 2));
        inp[12] = (inp[12] << 62) | (inp[12] >> (64 - 62));
        inp[10] = (inp[10] << 6) | (inp[10] >> (64 - 6));
        inp[13] = (inp[13] << 43) | (inp[13] >> (64 - 43));
        inp[11] = (inp[11] << 15) | (inp[11] >> (64 - 15));
        inp[14] = (inp[14] << 61) | (inp[14] >> (64 - 61));
        inp[18] = (inp[18] << 28) | (inp[18] >> (64 - 28));
        inp[16] = (inp[16] << 55) | (inp[16] >> (64 - 55));
        inp[19] = (inp[19] << 25) | (inp[19] >> (64 - 25));
        inp[17] = (inp[17] << 21) | (inp[17] >> (64 - 21));
        inp[15] = (inp[15] << 56) | (inp[15] >> (64 - 56));
        inp[24] = (inp[24] << 27) | (inp[24] >> (64 - 27));
        inp[22] = (inp[22] << 20) | (inp[22] >> (64 - 20));
        inp[20] = (inp[20] << 39) | (inp[20] >> (64 - 39));
        inp[23] = (inp[23] << 8) | (inp[23] >> (64 - 8));
        inp[21] = (inp[21] << 14) | (inp[21] >> (64 - 14));

        bnn = ~inp[13];
        l = inp[9] | inp[13];
        b0 = inp[0] ^ l;
        l = bnn | inp[17];
        b1 = inp[9] ^ l;
        l = inp[17] & inp[21];
        b2 = inp[13] ^ l;
        l = inp[21] | inp[0];
        b3 = inp[17] ^ l;
        l = inp[0] & inp[9];
        b4 = inp[21] ^ l;
        inp[0] = b0;
        inp[9] = b1;
        inp[13] = b2;
        inp[17] = b3;
        inp[21] = b4;
        bnn = ~inp[14];
        l = inp[22] | inp[1];
        b0 = inp[18] ^ l;
        l = inp[1] & inp[5];
        b1 = inp[22] ^ l;
        l = inp[5] | bnn;
        b2 = inp[1] ^ l;
        l = inp[14] | inp[18];
        b3 = inp[5] ^ l;
        l = inp[18] & inp[22];
        b4 = inp[14] ^ l;
        inp[18] = b0;
        inp[22] = b1;
        inp[1] = b2;
        inp[5] = b3;
        inp[14] = b4;
        bnn = ~inp[23];
        l = inp[10] | inp[19];
        b0 = inp[6] ^ l;
        l = inp[19] & inp[23];
        b1 = inp[10] ^ l;
        l = bnn & inp[2];
        b2 = inp[19] ^ l;
        l = inp[2] | inp[6];
        b3 = bnn ^ l;
        l = inp[6] & inp[10];
        b4 = inp[2] ^ l;
        inp[6] = b0;
        inp[10] = b1;
        inp[19] = b2;
        inp[23] = b3;
        inp[2] = b4;
        bnn = ~inp[11];
        l = inp[3] & inp[7];
        b0 = inp[24] ^ l;
        l = inp[7] | inp[11];
        b1 = inp[3] ^ l;
        l = bnn | inp[15];
        b2 = inp[7] ^ l;
        l = inp[15] & inp[24];
        b3 = bnn ^ l;
        l = inp[24] | inp[3];
        b4 = inp[15] ^ l;
        inp[24] = b0;
        inp[3] = b1;
        inp[7] = b2;
        inp[11] = b3;
        inp[15] = b4;
        bnn = ~inp[16];
        l = bnn & inp[20];
        b0 = inp[12] ^ l;
        l = inp[20] | inp[4];
        b1 = bnn ^ l;
        l = inp[4] & inp[8];
        b2 = inp[20] ^ l;
        l = inp[8] | inp[12];
        b3 = inp[4] ^ l;
        l = inp[12] & inp[16];
        b4 = inp[8] ^ l;
        inp[12] = b0;
        inp[16] = b1;
        inp[20] = b2;
        inp[4] = b3;
        inp[8] = b4;
        inp[0] = inp[0] ^ RC[j + 1];
        k = inp[5];
        inp[5] = inp[18];
        inp[18] = inp[11];
        inp[11] = inp[10];
        inp[10] = inp[6];
        inp[6] = inp[22];
        inp[22] = inp[20];
        inp[20] = inp[12];
        inp[12] = inp[19];
        inp[19] = inp[15];
        inp[15] = inp[24];
        inp[24] = inp[8];
        inp[8] = k;
        k = inp[1];
        inp[1] = inp[9];
        inp[9] = inp[14];
        inp[14] = inp[2];
        inp[2] = inp[13];
        inp[13] = inp[23];
        inp[23] = inp[4];
        inp[4] = inp[21];
        inp[21] = inp[16];
        inp[16] = inp[3];
        inp[3] = inp[17];
        inp[17] = inp[7];
        inp[7] = k;
    }


    inp[1] = ~inp[1];
    inp[2] = ~inp[2];
    inp[8] = ~inp[8];
    inp[12] = ~inp[12];
    inp[17] = ~inp[17];
    inp[20] = ~inp[20];
}


void shake_256_extract(shake256_context * context, BufferView rezBufferView)
{
    size_t size = rezBufferView.size();
    size_t dptr;

    size_t rezPtr = 0;

    dptr = (size_t)((inner_shake256_context *)context)->dptr;
    while (size > 0)
    {
        size_t cln;

        if (dptr == 136)
        {
            process_block(((inner_shake256_context *)context)->st.A);
            dptr = 0;
        }
        cln = 136 - dptr;
        if (cln > size)
        {
            cln = size;
        }
        size -= cln;

#ifndef __BIG_ENDIAN__
        memcpy(rezBufferView.data() + rezPtr, ((inner_shake256_context *)context)->st.dbuf + dptr, cln);
        dptr += cln;
        rezPtr += cln;
#else
        for (size_t i = 0; i < cln; ++i)
        {
            *(rezBufferView.data() + rezPtr++) =
                ((inner_shake256_context *)context)->st.A[dptr >> 3] >> ((dptr & 7) << 3);
            ++dptr;
        }
#endif
    }
    ((inner_shake256_context *)context)->dptr = dptr;
}


void shake_256_init(shake256_context * context)
{

    ((inner_shake256_context *)context)->dptr = 0;

    memset(((inner_shake256_context *)context)->st.A, 0, sizeof((inner_shake256_context *)context)->st.A);
}


void shake_256_inject(shake256_context * context, ConstBufferView buffer)
{

    const uint8_t * a = buffer.const_data();
    size_t size = buffer.size();

    size_t dptr;

    dptr = (size_t)((inner_shake256_context *)context)->dptr;
    while (size > 0)
    {
        size_t cln, u;

        cln = 136 - dptr;
        if (cln > size)
        {
            cln = size;
        }
#ifndef __BIG_ENDIAN__
        for (u = 0; u < cln; u++)
        {
            ((inner_shake256_context *)context)->st.dbuf[dptr + u] ^= a[u];
        }
#else
        for (u = 0; u < cln; u++)
        {
            size_t v = u + dptr;
            ((inner_shake256_context *)context)->st.A[v >> 3] ^= (uint64_t)a[u] << ((v & 7) << 3);
        }
#endif
        dptr += cln;
        a += cln;
        size -= cln;
        if (dptr == 136)
        {
            process_block(((inner_shake256_context *)context)->st.A);
            dptr = 0;
        }
    }
    ((inner_shake256_context *)context)->dptr = dptr;
}


void shake_256_flip(shake256_context * context)
{


#ifndef __BIG_ENDIAN__
    ((inner_shake256_context *)context)->st.dbuf[((inner_shake256_context *)context)->dptr] ^= 0x1F;
    ((inner_shake256_context *)context)->st.dbuf[135] ^= 0x80;
#else
    unsigned v;

    v = ((inner_shake256_context *)context)->dptr;
    ((inner_shake256_context *)context)->st.A[v >> 3] ^= (uint64_t)0x1F << ((v & 7) << 3);
    ((inner_shake256_context *)context)->st.A[16] ^= (uint64_t)0x80 << 56;
#endif
    ((inner_shake256_context *)context)->dptr = 136;
}

void shake_256_init_prng_from_seed(shake256_context * context, ConstBufferView buffer)
{
    shake_256_init(context);
    shake_256_inject(context, buffer);
    shake_256_flip(context);
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


void falcon_sign_start(ConstBufferView nonce, shake256_context * hash_data)
{
    shake_256_init(hash_data);
    shake_256_inject(hash_data, nonce);
}

int falcon_sign_dyn_finish(
    ConstBufferView signature, int sign_type, ConstBufferView privkey, shake256_context * hash_data, const void * nonce,
    ConstBufferView useData
)
{
    size_t sign_size = signature.size();

    unsigned degIndex;
    const uint8_t * seckey;
    uint8_t * es;
    int8_t *a, *b, *A, *B;
    uint16_t * hm;
    int16_t * sv;
    uint8_t * ause;
    size_t counter, flag, elemNum, es_size;
    unsigned oldcw;

    if (privkey.size() == 0)
    {
        return FALCON_ERR_FORMAT;
    }
    seckey = privkey.const_data();
    if ((seckey[0] & 0xF0) != 0x50)
    {
        return FALCON_ERR_FORMAT;
    }
    degIndex = seckey[0] & 0x0F;
    if (degIndex < 1 || degIndex > 10)
    {
        return FALCON_ERR_FORMAT;
    }
    if (privkey.size() != PQC_FALCON_PRIVKEY_SIZE(degIndex))
    {
        return FALCON_ERR_FORMAT;
    }
    if (useData.size() < PQC_FALCON_TMPSIZE_SIGNDYN(degIndex))
    {
        return FALCON_ERR_SIZE;
    }
    es_size = sign_size;
    if (es_size < 41)
    {
        return FALCON_ERR_SIZE;
    }
    switch (sign_type)
    {
    case FALCON_SIG_COMPRESSED:
        break;
    case FALCON_SIG_PADDED:
        if (sign_size < PQC_FALCON_SIG_PADDED_SIZE(degIndex))
        {
            return FALCON_ERR_SIZE;
        }
        break;
    case FALCON_SIG_CT:
        if (sign_size < PQC_FALCON_SIG_CT_SIZE(degIndex))
        {
            return FALCON_ERR_SIZE;
        }
        break;
    default:
        return FALCON_ERR_BADARG;
    }
    elemNum = (size_t)1 << degIndex;
    a = (int8_t *)useData.const_data();
    b = a + elemNum;
    A = b + elemNum;
    B = A + elemNum;
    hm = (uint16_t *)(B + elemNum);
    sv = (int16_t *)hm;
    ause = align_u_64(hm + elemNum);
    counter = 1;
    flag = trim_i_8_decode(a, degIndex, max_fg_bits[degIndex], seckey + counter, privkey.size() - counter);
    if (flag == 0)
    {
        return FALCON_ERR_FORMAT;
    }
    counter += flag;
    flag = trim_i_8_decode(b, degIndex, max_fg_bits[degIndex], seckey + counter, privkey.size() - counter);
    if (flag == 0)
    {
        return FALCON_ERR_FORMAT;
    }
    counter += flag;
    flag = trim_i_8_decode(A, degIndex, max_FG_bits[degIndex], seckey + counter, privkey.size() - counter);
    if (flag == 0)
    {
        return FALCON_ERR_FORMAT;
    }
    counter += flag;
    if (counter != privkey.size())
    {
        return FALCON_ERR_FORMAT;
    }
    if (!complete_private(B, a, b, A, degIndex, ause))
    {
        return FALCON_ERR_FORMAT;
    }

    shake_256_flip(hash_data);

    inner_shake256_context sav_hash_data = *(inner_shake256_context *)hash_data;

    for (;;)
    {
        *(inner_shake256_context *)hash_data = sav_hash_data;
        if (sign_type == FALCON_SIG_CT)
        {
            hash_to_point_ct((inner_shake256_context *)hash_data, hm, degIndex, ause);
        }
        else
        {
            hash_to_point_vartime((inner_shake256_context *)hash_data, hm, degIndex);
        }

        oldcw = set_fpu_cw(2);
        sign_dyn(sv, a, b, A, B, hm, degIndex, ause);

        set_fpu_cw(oldcw);
        es = (uint8_t *)signature.const_data();
        es_size = sign_size;
        memcpy(es + 1, nonce, 40);
        counter = 41;
        switch (sign_type)
        {
            size_t tu;

        case FALCON_SIG_COMPRESSED:
            es[0] = 0x30 + static_cast<uint8_t>(degIndex);
            flag = comp_encode(es + counter, es_size - counter, sv, degIndex);
            if (flag == 0)
            {
                return FALCON_ERR_SIZE;
            }
            break;
        case FALCON_SIG_PADDED:
            es[0] = 0x30 + static_cast<uint8_t>(degIndex);
            tu = PQC_FALCON_SIG_PADDED_SIZE(degIndex);
            flag = comp_encode(es + counter, tu - counter, sv, degIndex);
            if (flag == 0)
            {
                continue;
            }
            if (counter + flag < tu)
            {
                memset(es + counter + flag, 0, tu - (counter + flag));
            }
            break;
        case FALCON_SIG_CT:
            es[0] = 0x50 + static_cast<uint8_t>(degIndex);
            flag = trim_i_16_encode(es + counter, es_size - counter, sv, degIndex, max_sig_bits[degIndex]);
            if (flag == 0)
            {
                return FALCON_ERR_SIZE;
            }
            break;
        }
        return 0;
    }
}

int falcon_verify_start(shake256_context * hash_data, ConstBufferView signature)
{
    if (signature.size() < 41)
    {
        return FALCON_ERR_FORMAT;
    }
    shake_256_init(hash_data);
    shake_256_inject(hash_data, ConstBufferView((const uint8_t *)signature.const_data() + 1, 40));
    return 0;
}

int falcon_verify_finish(
    ConstBufferView signature, int sign_type, ConstBufferView public_key, shake256_context * hash_data,
    BufferView useData
)
{
    unsigned degIndex;
    uint8_t * ause;
    const uint8_t *pk, *es;
    size_t counter, flag, elemNum;
    uint16_t *h, *hm;
    int16_t * sv;
    int ct;


    if (signature.size() < 41 || public_key.size() == 0)
    {
        return FALCON_ERR_FORMAT;
    }
    es = (uint8_t *)signature.const_data();
    pk = (uint8_t *)public_key.const_data();
    if ((pk[0] & 0xF0) != 0x00)
    {
        return FALCON_ERR_FORMAT;
    }
    degIndex = pk[0] & 0x0F;
    if (degIndex < 1 || degIndex > 10)
    {
        return FALCON_ERR_FORMAT;
    }
    if (static_cast<unsigned>(es[0] & 0x0F) != degIndex)
    {
        return FALCON_ERR_BADSIG;
    }
    ct = 0;
    switch (sign_type)
    {
    case 0:
        switch (es[0] & 0xF0)
        {
        case 0x30:
            break;
        case 0x50:
            if (signature.size() != PQC_FALCON_SIG_CT_SIZE(degIndex))
            {
                return FALCON_ERR_FORMAT;
            }
            ct = 1;
            break;
        default:
            return FALCON_ERR_BADSIG;
        }
        break;
    case FALCON_SIG_COMPRESSED:
        if ((es[0] & 0xF0) != 0x30)
        {
            return FALCON_ERR_FORMAT;
        }
        break;
    case FALCON_SIG_PADDED:
        if ((es[0] & 0xF0) != 0x30)
        {
            return FALCON_ERR_FORMAT;
        }
        if (signature.size() != PQC_FALCON_SIG_PADDED_SIZE(degIndex))
        {
            return FALCON_ERR_FORMAT;
        }
        break;
    case FALCON_SIG_CT:
        if ((es[0] & 0xF0) != 0x50)
        {
            return FALCON_ERR_FORMAT;
        }
        if (signature.size() != PQC_FALCON_SIG_CT_SIZE(degIndex))
        {
            return FALCON_ERR_FORMAT;
        }
        ct = 1;
        break;
    default:
        return FALCON_ERR_BADARG;
    }
    if (public_key.size() != PQC_FALCON_PUBKEY_SIZE(degIndex))
    {
        return FALCON_ERR_FORMAT;
    }
    if (useData.size() < PQC_FALCON_TMPSIZE_VERIFY(degIndex))
    {
        return FALCON_ERR_SIZE;
    }

    elemNum = (size_t)1 << degIndex;
    h = (uint16_t *)align_u_16(useData.data());
    hm = h + elemNum;
    sv = (int16_t *)(hm + elemNum);
    ause = (uint8_t *)(sv + elemNum);

    if (modq_decode(h, degIndex, pk + 1, public_key.size() - 1) != public_key.size() - 1)
    {
        return FALCON_ERR_FORMAT;
    }

    counter = 41;
    if (ct)
    {
        flag = trim_i_16_decode(sv, degIndex, max_sig_bits[degIndex], es + counter, signature.size() - counter);
    }
    else
    {
        flag = comp_decode(sv, degIndex, es + counter, signature.size() - counter);
    }
    if (flag == 0)
    {
        return FALCON_ERR_FORMAT;
    }
    if ((counter + flag) != signature.size())
    {

        if ((sign_type == 0 && signature.size() == PQC_FALCON_SIG_PADDED_SIZE(degIndex)) ||
            sign_type == FALCON_SIG_PADDED)
        {
            while (counter + flag < signature.size())
            {
                if (es[counter + flag] != 0)
                {
                    return FALCON_ERR_FORMAT;
                }
                flag++;
            }
        }
        else
        {
            return FALCON_ERR_FORMAT;
        }
    }


    shake_256_flip(hash_data);
    if (ct)
    {
        hash_to_point_ct((inner_shake256_context *)hash_data, hm, degIndex, ause);
    }
    else
    {
        hash_to_point_vartime((inner_shake256_context *)hash_data, hm, degIndex);
    }

    to_ntt_monty(h, degIndex);
    if (!verify_raw(hm, sv, h, degIndex, ause))
    {
        return FALCON_ERR_BADSIG;
    }
    return 0;
}
