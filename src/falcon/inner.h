#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <buffer.h>
#include <core.h>
#include <falcon/fpr.h>
#include <rng/random_generator.h>

#if defined _MSC_VER && _MSC_VER
#pragma warning(disable : 4146)
#endif

#ifndef FALCON_AVX2
#define FALCON_AVX2 0
#endif
#ifndef FALCON_FMA
#define FALCON_FMA 0
#endif

#if defined __GNUC__ && defined __i386__
static inline unsigned set_fpu_cw(unsigned a)
{
    unsigned short k;
    unsigned use;

    __asm__ __volatile__("fstcw %0" : "=m"(k) : :);
    use = (k & 0x0300u) >> 8;
    k = (unsigned short)((k & ~0x0300u) | (a << 8));
    __asm__ __volatile__("fldcw %0" : : "m"(k) :);
    return use;
}
#elif defined _M_IX86
static inline unsigned set_fpu_cw(unsigned a)
{
    unsigned short k;
    unsigned use;

    __asm { fstcw k }
    use = (k & 0x0300u) >> 8;
    k = (unsigned short)((k & ~0x0300u) | (a << 8));
    __asm { fldcw k }
    return use;
}
#else
static inline unsigned set_fpu_cw(unsigned a) { return a; }
#endif

typedef struct
{
    union
    {
        uint64_t A[25];
        uint8_t dbuf[200];
    } st;
    uint64_t dptr;
} inner_shake256_context;

size_t modq_encode(void * rez, size_t maxRexSize, const uint16_t * a, unsigned degIndex);
size_t trim_i_16_encode(void * rez, size_t maxRexSize, const int16_t * a, unsigned degIndex, unsigned bits);
size_t trim_i_8_encode(void * rez, size_t maxRexSize, const int8_t * a, unsigned degIndex, unsigned bits);
size_t comp_encode(void * rez, size_t maxRexSize, const int16_t * a, unsigned degIndex);

size_t modq_decode(uint16_t * a, unsigned degIndex, const void * inp, size_t maxInpSize);
size_t trim_i_16_decode(int16_t * a, unsigned degIndex, unsigned bits, const void * inp, size_t maxInpSize);
size_t trim_i_8_decode(int8_t * a, unsigned degIndex, unsigned bits, const void * inp, size_t maxInpSize);
size_t comp_decode(int16_t * a, unsigned degIndex, const void * inp, size_t maxInpSize);

extern const uint8_t max_fg_bits[];
extern const uint8_t max_FG_bits[];
extern const uint8_t max_sig_bits[];

void hash_to_point_vartime(inner_shake256_context * context, uint16_t * a, unsigned degIndex);

void hash_to_point_ct(inner_shake256_context * context, uint16_t * a, unsigned degIndex, uint8_t * tmp);

int is_short(const int16_t * a1, const int16_t * a2, unsigned degIndex);

int is_short_half(uint32_t satSquareNorm, const int16_t * a2, unsigned degIndex);

void to_ntt_monty(uint16_t * a, unsigned degIndex);

int verify_raw(const uint16_t * l, const int16_t * a2, const uint16_t * k, unsigned degIndex, uint8_t * tmp);

int compute_public(uint16_t * h, const int8_t * a, const int8_t * b, unsigned degIndx, uint8_t * temp);

int complete_private(
    int8_t * B, const int8_t * a, const int8_t * b, const int8_t * A, unsigned degIndex, uint8_t * temp
);

typedef struct
{
    union
    {
        uint8_t d[512];
        uint64_t dummy_u64;
    } buf;
    size_t ptr;
    union
    {
        uint8_t d[256];
        uint64_t dummy_u64;
    } state;
    int type;
} prng;

static inline uint64_t prng_get_u_64(prng * a, IRandomGenerator * rng)
{
    size_t use;

    use = a->ptr;
    if (use >= (sizeof a->buf.d) - 9)
    {
        rng->random_bytes(BufferView(a->buf.d, sizeof a->buf.d));
        rng->random_bytes(BufferView(a->state.d, sizeof a->state.d));
        a->ptr = 0;
        use = 0;
    }
    a->ptr = use + 8;

#if !defined(__BIG_ENDIAN__)
    return *(uint64_t *)(a->buf.d + use);
#else
    return (uint64_t)a->buf.d[use + 0] | ((uint64_t)a->buf.d[use + 1] << 8) | ((uint64_t)a->buf.d[use + 2] << 16) |
           ((uint64_t)a->buf.d[use + 3] << 24) | ((uint64_t)a->buf.d[use + 4] << 32) |
           ((uint64_t)a->buf.d[use + 5] << 40) | ((uint64_t)a->buf.d[use + 6] << 48) |
           ((uint64_t)a->buf.d[use + 7] << 56);
#endif
}

static inline unsigned prng_get_u_8(prng * a, IRandomGenerator * rng)
{
    unsigned rez;

    rez = a->buf.d[a->ptr++];
    if (a->ptr == sizeof a->buf.d)
    {
        rng->random_bytes(BufferView(a->buf.d, sizeof a->buf.d));
        rng->random_bytes(BufferView(a->state.d, sizeof a->state.d));
        a->ptr = 0;
    }
    return rez;
}

void fft(fpr * a, unsigned degIndex);

void i_fft(fpr * a, unsigned degIndex);

void poly_add(fpr * a, const fpr * b, unsigned degIndex);

void poly_sub(fpr * a, const fpr * b, unsigned degIndex);

void poly_neg(fpr * a, unsigned degIndex);

void poly_adj_fft(fpr * a, unsigned degIndex);

void poly_mul_fft(fpr * a, const fpr * b, unsigned degIndex);

void poly_muladj_fft(fpr * a, const fpr * b, unsigned degIndex);

void poly_mulselfadj_fft(fpr * a, unsigned degIndex);

void poly_mulconst(fpr * a, fpr b, unsigned degIndex);

void poly_invnorm_2_fft(fpr * d, const fpr * a, const fpr * b, unsigned degIndex);

void poly_add_muladj_fft(fpr * k, const fpr * A, const fpr * B, const fpr * a, const fpr * b, unsigned degIndex);

void poly_mul_autoadj_fft(fpr * a, const fpr * b, unsigned degIndex);

void poly_div_autoadj_fft(fpr * a, const fpr * b, unsigned degIndex);

void poly_ldl_fft(const fpr * b00, fpr * b01, fpr * b11, unsigned degIndex);

void poly_split_fft(fpr * a0, fpr * a1, const fpr * a, unsigned degIndex);

void poly_merge_fft(fpr * a, const fpr * a0, const fpr * a1, unsigned degIndex);

#define FALCON_KEYGEN_TEMP_1 136
#define FALCON_KEYGEN_TEMP_2 272
#define FALCON_KEYGEN_TEMP_3 224
#define FALCON_KEYGEN_TEMP_4 448
#define FALCON_KEYGEN_TEMP_5 896
#define FALCON_KEYGEN_TEMP_6 1792
#define FALCON_KEYGEN_TEMP_7 3584
#define FALCON_KEYGEN_TEMP_8 7168
#define FALCON_KEYGEN_TEMP_9 14336
#define FALCON_KEYGEN_TEMP_10 28672

void keygen(
    inner_shake256_context * context, int8_t * a, int8_t * b, int8_t * A, int8_t * B, uint16_t * c, unsigned degIndex,
    uint8_t * temp
);

void sign_dyn(
    int16_t * sign, const int8_t * a, const int8_t * b, const int8_t * A, const int8_t * B, const uint16_t * c,
    unsigned degIndex, uint8_t * temp, IRandomGenerator * rng
);

typedef struct
{
    prng p;
    fpr sigma_min;
} sampler_context;


int sampler(void * a, fpr b, fpr i_sigma, IRandomGenerator * rng);

int gaussian_0_sampler(prng * a, IRandomGenerator * rng);
