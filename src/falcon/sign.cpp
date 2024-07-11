#include "inner.h"

#define MKN(degIndx) ((size_t)1 << (degIndx))

static void smallints_to_fpr(fpr * a, const int8_t * b, unsigned degIndx)
{
    size_t elemNum, counter;

    elemNum = MKN(degIndx);
    for (counter = 0; counter < elemNum; counter++)
    {
        a[counter] = fpr_of(b[counter]);
    }
}

typedef int (*samplerZ)(void * ctx, fpr mu, fpr sigma);

static void ff_sampling_fft_dyntree(
    samplerZ samp, void * sampCtx, fpr * t0, fpr * t1, fpr * c0, fpr * c1, fpr * c2, unsigned origDegIndx,
    unsigned degIndx, fpr * temp
)
{
    size_t elemNum, use;
    fpr *z0, *z1;


    if (degIndx == 0)
    {
        fpr leaf;

        leaf = c0[0];
        leaf = fpr_mul(fpr_sqrt(leaf), fpr_inv_sigma[origDegIndx]);
        t0[0] = fpr_of(samp(sampCtx, t0[0], leaf));
        t1[0] = fpr_of(samp(sampCtx, t1[0], leaf));
        return;
    }

    elemNum = (size_t)1 << degIndx;
    use = elemNum >> 1;

    poly_ldl_fft(c0, c1, c2, degIndx);

    poly_split_fft(temp, temp + use, c0, degIndx);
    memcpy(c0, temp, elemNum * sizeof *temp);
    poly_split_fft(temp, temp + use, c2, degIndx);
    memcpy(c2, temp, elemNum * sizeof *temp);
    memcpy(temp, c1, elemNum * sizeof *c1);
    memcpy(c1, c0, use * sizeof *c0);
    memcpy(c1 + use, c2, use * sizeof *c0);

    z1 = temp + elemNum;
    poly_split_fft(z1, z1 + use, t1, degIndx);
    ff_sampling_fft_dyntree(
        samp, sampCtx, z1, z1 + use, c2, c2 + use, c1 + use, origDegIndx, degIndx - 1, z1 + elemNum
    );
    poly_merge_fft(temp + (elemNum << 1), z1, z1 + use, degIndx);

    memcpy(z1, t1, elemNum * sizeof *t1);
    poly_sub(z1, temp + (elemNum << 1), degIndx);
    memcpy(t1, temp + (elemNum << 1), elemNum * sizeof *temp);
    poly_mul_fft(temp, z1, degIndx);
    poly_add(t0, temp, degIndx);

    z0 = temp;
    poly_split_fft(z0, z0 + use, t0, degIndx);
    ff_sampling_fft_dyntree(samp, sampCtx, z0, z0 + use, c0, c0 + use, c1, origDegIndx, degIndx - 1, z0 + elemNum);
    poly_merge_fft(t0, z0, z0 + use, degIndx);
}

static int do_sign_dyn(
    samplerZ samp, void * sampCtx, int16_t * s2, const int8_t * a, const int8_t * b, const int8_t * A, const int8_t * B,
    const uint16_t * h, unsigned degIndx, fpr * temp
)
{
    size_t elemNum, counter;
    fpr *t0, *t1, *tx, *ty;
    fpr *b00, *b01, *b10, *b11, *c0, *c1, *c2;
    fpr ni;
    uint32_t sqn, ng;
    int16_t *s1tmp, *s2tmp;

    elemNum = MKN(degIndx);

    b00 = temp;
    b01 = b00 + elemNum;
    b10 = b01 + elemNum;
    b11 = b10 + elemNum;
    smallints_to_fpr(b01, a, degIndx);
    smallints_to_fpr(b00, b, degIndx);
    smallints_to_fpr(b11, A, degIndx);
    smallints_to_fpr(b10, B, degIndx);
    fft(b01, degIndx);
    fft(b00, degIndx);
    fft(b11, degIndx);
    fft(b10, degIndx);
    poly_neg(b01, degIndx);
    poly_neg(b11, degIndx);

    t0 = b11 + elemNum;
    t1 = t0 + elemNum;

    memcpy(t0, b01, elemNum * sizeof *b01);
    poly_mulselfadj_fft(t0, degIndx);

    memcpy(t1, b00, elemNum * sizeof *b00);
    poly_muladj_fft(t1, b10, degIndx);
    poly_mulselfadj_fft(b00, degIndx);
    poly_add(b00, t0, degIndx);
    memcpy(t0, b01, elemNum * sizeof *b01);
    poly_muladj_fft(b01, b11, degIndx);
    poly_add(b01, t1, degIndx);
    poly_mulselfadj_fft(b10, degIndx);
    memcpy(t1, b11, elemNum * sizeof *b11);
    poly_mulselfadj_fft(t1, degIndx);
    poly_add(b10, t1, degIndx);

    c0 = b00;
    c1 = b01;
    c2 = b10;
    b01 = t0;
    t0 = b01 + elemNum;
    t1 = t0 + elemNum;

    for (counter = 0; counter < elemNum; counter++)
    {
        t0[counter] = fpr_of(h[counter]);
    }

    fft(t0, degIndx);
    ni = fpr_inverse_of_q;
    memcpy(t1, t0, elemNum * sizeof *t0);
    poly_mul_fft(t1, b01, degIndx);
    poly_mulconst(t1, fpr_neg(ni), degIndx);
    poly_mul_fft(t0, b11, degIndx);
    poly_mulconst(t0, ni, degIndx);

    memcpy(b11, t0, elemNum * 2 * sizeof *t0);
    t0 = c2 + elemNum;
    t1 = t0 + elemNum;

    ff_sampling_fft_dyntree(samp, sampCtx, t0, t1, c0, c1, c2, degIndx, degIndx, t1 + elemNum);

    b00 = temp;
    b01 = b00 + elemNum;
    b10 = b01 + elemNum;
    b11 = b10 + elemNum;
    memmove(b11 + elemNum, t0, elemNum * 2 * sizeof *t0);
    t0 = b11 + elemNum;
    t1 = t0 + elemNum;
    smallints_to_fpr(b01, a, degIndx);
    smallints_to_fpr(b00, b, degIndx);
    smallints_to_fpr(b11, A, degIndx);
    smallints_to_fpr(b10, B, degIndx);
    fft(b01, degIndx);
    fft(b00, degIndx);
    fft(b11, degIndx);
    fft(b10, degIndx);
    poly_neg(b01, degIndx);
    poly_neg(b11, degIndx);
    tx = t1 + elemNum;
    ty = tx + elemNum;

    memcpy(tx, t0, elemNum * sizeof *t0);
    memcpy(ty, t1, elemNum * sizeof *t1);
    poly_mul_fft(tx, b00, degIndx);
    poly_mul_fft(ty, b10, degIndx);
    poly_add(tx, ty, degIndx);
    memcpy(ty, t0, elemNum * sizeof *t0);
    poly_mul_fft(ty, b01, degIndx);

    memcpy(t0, tx, elemNum * sizeof *tx);
    poly_mul_fft(t1, b11, degIndx);
    poly_add(t1, ty, degIndx);
    i_fft(t0, degIndx);
    i_fft(t1, degIndx);

    s1tmp = (int16_t *)tx;
    sqn = 0;
    ng = 0;
    for (counter = 0; counter < elemNum; counter++)
    {
        int32_t z;

        z = (int32_t)h[counter] - (int32_t)fpr_rint(t0[counter]);
        sqn += (uint32_t)(z * z);
        ng |= sqn;
        s1tmp[counter] = (int16_t)z;
    }
    sqn |= -(ng >> 31);

    s2tmp = (int16_t *)temp;
    for (counter = 0; counter < elemNum; counter++)
    {
        s2tmp[counter] = (int16_t)-fpr_rint(t1[counter]);
    }
    if (is_short_half(sqn, s2tmp, degIndx))
    {
        memcpy(s2, s2tmp, elemNum * sizeof *s2);
        memcpy(temp, s1tmp, elemNum * sizeof *s1tmp);
        return 1;
    }
    return 0;
}

int gaussian_0_sampler(prng * inp)
{

    static const uint32_t dst[] = {10745844u, 3068844u,  3741698u, 5559083u,  1580863u,  8248194u, 2260429u,  13669192u,
                                   2736639u,  708981u,   4421575u, 10046180u, 169348u,   7122675u, 4136815u,  30538u,
                                   13063405u, 7650655u,  4132u,    14505003u, 7826148u,  417u,     16768101u, 11363290u,
                                   31u,       8444042u,  8086568u, 1u,        12844466u, 265321u,  0u,        1232676u,
                                   13644283u, 0u,        38047u,   9111839u,  0u,        870u,     6138264u,  0u,
                                   14u,       12545723u, 0u,       0u,        3104126u,  0u,       0u,        28824u,
                                   0u,        0u,        198u,     0u,        0u,        1u};

    uint32_t u0, u1, u2, h;
    uint64_t l;
    size_t counter;
    int rez;

    l = prng_get_u_64(inp);
    h = prng_get_u_8(inp);
    u0 = (uint32_t)l & 0xFFFFFF;
    u1 = (uint32_t)(l >> 24) & 0xFFFFFF;
    u2 = (uint32_t)(l >> 48) | (h << 16);

    rez = 0;
    for (counter = 0; counter < (sizeof dst) / sizeof(dst[0]); counter += 3)
    {
        uint32_t l0, l1, l2, k0;

        l0 = dst[counter + 2];
        l1 = dst[counter + 1];
        l2 = dst[counter + 0];
        k0 = (u0 - l0) >> 31;
        k0 = (u1 - l1 - k0) >> 31;
        k0 = (u2 - l2 - k0) >> 31;
        rez += (int)k0;
    }
    return rez;
}


static int ber_exp(prng * inp, fpr a, fpr b)
{
    int s;
    fpr k;
    uint32_t c, d;
    uint64_t e;

    s = (int)fpr_trunc(fpr_mul(a, fpr_inv_log2));
    k = fpr_sub(a, fpr_mul(fpr_of(s), fpr_log2));

    c = (uint32_t)s;
    c ^= (c ^ 63) & -((63 - c) >> 31);
    s = (int)c;

    e = ((fpr_expm_p_63(k, b) << 1) - 1) >> s;

    int i = 64;
    do
    {
        i -= 8;
        d = prng_get_u_8(inp) - ((uint32_t)(e >> i) & 0xFF);
    } while (!d && i > 0);
    return (int)(d >> 31);
}


int sampler(void * k, fpr l, fpr sigma)
{
    sampler_context * use;
    int s;
    fpr r, d, c;

    use = (sampler_context *)k;

    s = (int)fpr_floor(l);
    r = fpr_sub(l, fpr_of(s));

    d = fpr_half(fpr_sqr(sigma));

    c = fpr_mul(sigma, use->sigma_min);

    for (;;)
    {
        int z0, z, b;
        fpr x;

        z0 = gaussian_0_sampler(&use->p);
        b = (int)prng_get_u_8(&use->p) & 1;
        z = b + ((b << 1) - 1) * z0;

        x = fpr_mul(fpr_sqr(fpr_sub(fpr_of(z), r)), d);
        x = fpr_sub(x, fpr_mul(fpr_of(z0 * z0), fpr_inv_2sqrsigma0));
        if (ber_exp(&use->p, x, c))
        {
            return s + z;
        }
    }
}

void sign_dyn(
    int16_t * sig, const int8_t * a, const int8_t * b, const int8_t * A, const int8_t * B, const uint16_t * h,
    unsigned degIndx, uint8_t * temp
)
{
    fpr * ftmp;

    ftmp = (fpr *)temp;
    for (;;)
    {
        sampler_context spc;
        samplerZ samp;
        void * sampCtx;

        spc.sigma_min = fpr_sigma_min[degIndx];

        randombytes(BufferView((&spc.p)->buf.d, sizeof(&spc.p)->buf.d));
        randombytes(BufferView((&spc.p)->state.d, sizeof(&spc.p)->state.d));
        (&spc.p)->ptr = 0;

        samp = sampler;
        sampCtx = &spc;

        if (do_sign_dyn(samp, sampCtx, sig, a, b, A, B, h, degIndx, ftmp))
        {
            break;
        }
    }
}
