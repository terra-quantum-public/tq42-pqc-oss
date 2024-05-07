#pragma once

#include <cmath>
#include <cstdint>

#if !FALCON_AVX2
#if defined(__GNUC__) && defined(__SSE2_MATH__)
#include <immintrin.h>
#endif
#endif

#if defined __clang__
#pragma STDC FP_CONTRACT OFF
#elif defined __GNUC__
#pragma GCC optimize("fp-contract=off")
#endif


struct fpr
{
    double v;
};

static inline fpr fpr_fpr(double v)
{
    fpr a;
    a.v = v;
    return a;
}

static inline fpr fpr_of(int64_t a) { return fpr_fpr((double)a); }

static const fpr fpr_q = {12289.0};
static const fpr fpr_inverse_of_q = {1.0 / 12289.0};
static const fpr fpr_inv_2sqrsigma0 = {.150865048875372721532312163019};
static const fpr fpr_inv_sigma[] = {
    {0.0},
    {0.0069054793295940891952143765991630516},
    {0.0068102267767177975961393730687908629},
    {0.0067188101910722710707826117910434131},
    {0.0065883354370073665545865037227681924},
    {0.0064651781207602900738053897763485516},
    {0.0063486788828078995327741182928037856},
    {0.0062382586529084374473367528433697537},
    {0.0061334065020930261548984001431770281},
    {0.0060336696681577241031668062510953022},
    {0.0059386453095331159950250124336477482}};
static const fpr fpr_sigma_min[] = {
    {0.0},
    {1.1165085072329102588881898380334015},
    {1.1321247692325272405718031785357108},
    {1.1475285353733668684571123112513188},
    {1.1702540788534828939713084716509250},
    {1.1925466358390344011122170489094133},
    {1.2144300507766139921088487776957699},
    {1.2359260567719808790104525941706723},
    {1.2570545284063214162779743112075080},
    {1.2778336969128335860256340575729042},
    {1.2982803343442918539708792538826807}};
static const fpr fpr_log2 = {0.69314718055994530941723212146};
static const fpr fpr_inv_log2 = {1.4426950408889634073599246810};
static const fpr fpr_bnorm_max = {16822.4121};
static const fpr fpr_zero = {0.0};
static const fpr fpr_one = {1.0};
static const fpr fpr_two = {2.0};
static const fpr fpr_onehalf = {0.5};
static const fpr fpr_invsqrt2 = {0.707106781186547524400844362105};
static const fpr fpr_invsqrt8 = {0.353553390593273762200422181052};
static const fpr fpr_ptwo31 = {2147483648.0};
static const fpr fpr_ptwo31m1 = {2147483647.0};
static const fpr fpr_mtwo31m1 = {-2147483647.0};
static const fpr fpr_ptwo63m1 = {9223372036854775807.0};
static const fpr fpr_mtwo63m1 = {-9223372036854775807.0};
static const fpr fpr_ptwo63 = {9223372036854775808.0};


static inline int64_t fpr_rint(fpr a)
{

    int64_t b, c, d, e, m;
    uint32_t l;

    b = (int64_t)(a.v - 1.0);
    c = (int64_t)a.v;
    d = (int64_t)(a.v + 4503599627370496.0) - 4503599627370496;
    e = (int64_t)(a.v - 4503599627370496.0) + 4503599627370496;

    m = b >> 63;
    e &= m;
    d &= ~m;


    l = (uint32_t)((uint64_t)c >> 52);
    m = -(int64_t)((((l + 1) & 0xFFF) - 2) >> 31);
    d &= m;
    e &= m;
    c &= ~m;


    return c | e | d;
}

static inline int64_t fpr_floor(fpr a)
{
    int64_t use;


    use = (int64_t)a.v;
    return use - (a.v < (double)use);
}

static inline int64_t fpr_trunc(fpr a) { return (int64_t)a.v; }

static inline fpr fpr_add(fpr a, fpr b) { return fpr_fpr(a.v + b.v); }

static inline fpr fpr_sub(fpr a, fpr b) { return fpr_fpr(a.v - b.v); }

static inline fpr fpr_neg(fpr a) { return fpr_fpr(-a.v); }

static inline fpr fpr_half(fpr a) { return fpr_fpr(a.v * 0.5); }

static inline fpr fpr_double(fpr a) { return fpr_fpr(a.v + a.v); }

static inline fpr fpr_mul(fpr a, fpr b) { return fpr_fpr(a.v * b.v); }

static inline fpr fpr_sqr(fpr a) { return fpr_fpr(a.v * a.v); }

static inline fpr fpr_inv(fpr a) { return fpr_fpr(1.0 / a.v); }

static inline fpr fpr_div(fpr a, fpr b) { return fpr_fpr(a.v / b.v); }


static inline fpr fpr_sqrt(fpr a)
{
#if defined __GNUC__ && defined __SSE2_MATH__
    return fpr_fpr(_mm_cvtsd_f64(_mm_sqrt_pd(_mm_set1_pd(a.v))));
#elif defined __GNUC__ && defined __i386__
    __asm__ __volatile__("fldl   %0\n\t"
                         "fsqrt\n\t"
                         "fstpl  %0\n\t"
                         : "+m"(a.v)
                         :
                         :);
    return a;
#elif defined _M_IX86
    __asm {
		fld a.v
		fsqrt
		fstp a.v
    }
    return a;
#elif defined __PPC__ && defined __GNUC__
    fpr b;

#if defined __clang__

    __asm__("fsqrt  %0, %1" : "=f"(b.v) : "f"(a.v) :);
#else
    __asm__("fsqrt  %0, %1" : "=d"(b.v) : "d"(a.v) :);
#endif
    return b;
#elif (defined __ARM_FP && ((__ARM_FP & 0x08) == 0x08)) || (!defined __ARM_FP && defined __ARM_VFPV2__)

#if defined __aarch64__ && __aarch64__
    __asm__("fsqrt   %d0, %d0" : "+w"(a.v) : :);
#else
    __asm__("fsqrtd  %P0, %P0" : "+w"(a.v) : :);
#endif
    return a;
#else
    return fpr_fpr(sqrt(a.v));
#endif
}

static inline int fpr_lt(fpr a, fpr b) { return a.v < b.v; }

static inline uint64_t fpr_expm_p_63(fpr a, fpr ccs)
{
    double k, b;

    k = a.v;
    b = 0.000000002073772366009083061987;
    b = 0.000000025299506379442070029551 - b * k;
    b = 0.000000275607356160477811864927 - b * k;
    b = 0.000002755586350219122514855659 - b * k;
    b = 0.000024801566833585381209939524 - b * k;

    b = 0.000198412739277311890541063977 - b * k;
    b = 0.001388888894063186997887560103 - b * k;
    b = 0.008333333327800835146903501993 - b * k;
    b = 0.041666666666110491190622155955 - b * k;
    b = 0.166666666666984014666397229121 - b * k;
    b = 0.500000000000019206858326015208 - b * k;
    b = 0.999999999999994892974086724280 - b * k;
    b = 1.000000000000000000000000000000 - b * k;
    b *= ccs.v;
    return (uint64_t)(b * fpr_ptwo63.v);
}

extern const fpr fpr_gm_tab[];
extern const fpr fpr_p2_tab[];
