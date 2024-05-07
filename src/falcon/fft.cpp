#include <falcon/fpr.h>
#include <falcon/inner.h>


#define FPC_ADD(rezRe, rezIm, xRe, xIm, yRe, yIm)                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        fpr fpctRe, fpctIm;                                                                                            \
        fpctRe = fpr_add(xRe, yRe);                                                                                    \
        fpctIm = fpr_add(xIm, yIm);                                                                                    \
        (rezRe) = fpctRe;                                                                                              \
        (rezIm) = fpctIm;                                                                                              \
    } while (0)

#define FPC_SUB(rezRe, rezIm, xRe, xIm, yRe, yIm)                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        fpr fpctRe, fpctIm;                                                                                            \
        fpctRe = fpr_sub(xRe, yRe);                                                                                    \
        fpctIm = fpr_sub(xIm, yIm);                                                                                    \
        (rezRe) = fpctRe;                                                                                              \
        (rezIm) = fpctIm;                                                                                              \
    } while (0)

#define FPC_MUL(rezRe, rezIm, xRe, xIm, yRe, yIm)                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        fpr fpctReA, fpctImA;                                                                                          \
        fpr fpctReB, fpctImB;                                                                                          \
        fpr fpctRezRe, fpctRezIm;                                                                                      \
        fpctReA = (xRe);                                                                                               \
        fpctImA = (xIm);                                                                                               \
        fpctReB = (yRe);                                                                                               \
        fpctImB = (yIm);                                                                                               \
        fpctRezRe = fpr_sub(fpr_mul(fpctReA, fpctReB), fpr_mul(fpctImA, fpctImB));                                     \
        fpctRezIm = fpr_add(fpr_mul(fpctReA, fpctImB), fpr_mul(fpctImA, fpctReB));                                     \
        (rezRe) = fpctRezRe;                                                                                           \
        (rezIm) = fpctRezIm;                                                                                           \
    } while (0)

#define FPC_SQR(rezRe, rezIm, xRe, xIm)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        fpr fpctReA, fpctImA;                                                                                          \
        fpr fpctRezRe, fpctRezIm;                                                                                      \
        fpctReA = (xRe);                                                                                               \
        fpctImA = (xIm);                                                                                               \
        fpctRezRe = fpr_sub(fpr_sqr(fpctReA), fpr_sqr(fpctImA));                                                       \
        fpctRezIm = fpr_double(fpr_mul(fpctReA, fpctImA));                                                             \
        (rezRe) = fpctRezRe;                                                                                           \
        (rezIm) = fpctRezIm;                                                                                           \
    } while (0)

#define FPC_INV(rezRe, rezIm, xRe, xIm)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        fpr fpctReA, fpctImA;                                                                                          \
        fpr fpctRezRe, fpctRezIm;                                                                                      \
        fpr fpct_use;                                                                                                  \
        fpctReA = (xRe);                                                                                               \
        fpctImA = (xIm);                                                                                               \
        fpct_use = fpr_add(fpr_sqr(fpctReA), fpr_sqr(fpctImA));                                                        \
        fpct_use = fpr_inv(fpct_use);                                                                                  \
        fpctRezRe = fpr_mul(fpctReA, fpct_use);                                                                        \
        fpctRezIm = fpr_mul(fpr_neg(fpctImA), fpct_use);                                                               \
        (rezRe) = fpctRezRe;                                                                                           \
        (rezIm) = fpctRezIm;                                                                                           \
    } while (0)

#define FPC_DIV(rezRe, rezIm, xRe, xIm, yRe, yIm)                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        fpr fpctReA, fpctImA;                                                                                          \
        fpr fpctReB, fpctImB;                                                                                          \
        fpr fpctRezRe, fpctRezIm;                                                                                      \
        fpr fpct_use;                                                                                                  \
        fpctReA = (xRe);                                                                                               \
        fpctImA = (xIm);                                                                                               \
        fpctReB = (yRe);                                                                                               \
        fpctImB = (yIm);                                                                                               \
        fpct_use = fpr_add(fpr_sqr(fpctReB), fpr_sqr(fpctImB));                                                        \
        fpct_use = fpr_inv(fpct_use);                                                                                  \
        fpctReB = fpr_mul(fpctReB, fpct_use);                                                                          \
        fpctImB = fpr_mul(fpr_neg(fpctImB), fpct_use);                                                                 \
        fpctRezRe = fpr_sub(fpr_mul(fpctReA, fpctReB), fpr_mul(fpctImA, fpctImB));                                     \
        fpctRezIm = fpr_add(fpr_mul(fpctReA, fpctImB), fpr_mul(fpctImA, fpctReB));                                     \
        (rezRe) = fpctRezRe;                                                                                           \
        (rezIm) = fpctRezIm;                                                                                           \
    } while (0)


void fft(fpr * a, unsigned degIndx)
{
    unsigned counter;
    size_t b, elemNum, c, d;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;
    b = c;
    for (counter = 1, d = 2; counter < degIndx; counter++, d <<= 1)
    {
        size_t e, f, i1, j1;

        e = b >> 1;
        f = d >> 1;
        for (i1 = 0, j1 = 0; i1 < f; i1++, j1 += b)
        {
            size_t j, j2;

            j2 = j1 + e;

            fpr sRe, sIm;

            sRe = fpr_gm_tab[((d + i1) << 1) + 0];
            sIm = fpr_gm_tab[((d + i1) << 1) + 1];
            for (j = j1; j < j2; j++)
            {
                fpr xRe, xIm, yRe, yIm;

                xRe = a[j];
                xIm = a[j + c];
                yRe = a[j + e];
                yIm = a[j + e + c];
                FPC_MUL(yRe, yIm, yRe, yIm, sRe, sIm);
                FPC_ADD(a[j], a[j + c], xRe, xIm, yRe, yIm);
                FPC_SUB(a[j + e], a[j + e + c], xRe, xIm, yRe, yIm);
            }
        }
        b = e;
    }
}


void i_fft(fpr * a, unsigned degIndx)
{
    size_t counter, elemNum, b, c, d;

    elemNum = (size_t)1 << degIndx;
    c = 1;
    d = elemNum;
    b = elemNum >> 1;
    for (counter = degIndx; counter > 1; counter--)
    {
        size_t e, f, i1, j1;

        e = d >> 1;
        f = c << 1;
        for (i1 = 0, j1 = 0; j1 < b; i1++, j1 += f)
        {
            size_t j, j2;

            j2 = j1 + c;

            fpr sRe, sIm;

            sRe = fpr_gm_tab[((e + i1) << 1) + 0];
            sIm = fpr_neg(fpr_gm_tab[((e + i1) << 1) + 1]);
            for (j = j1; j < j2; j++)
            {
                fpr xRe, xIm, yRe, yIm;

                xRe = a[j];
                xIm = a[j + b];
                yRe = a[j + c];
                yIm = a[j + c + b];
                FPC_ADD(a[j], a[j + b], xRe, xIm, yRe, yIm);
                FPC_SUB(xRe, xIm, xRe, xIm, yRe, yIm);
                FPC_MUL(a[j + c], a[j + c + b], xRe, xIm, sRe, sIm);
            }
        }
        c = f;
        d = e;
    }

    if (degIndx > 0)
    {
        fpr ni;

        ni = fpr_p2_tab[degIndx];
        for (counter = 0; counter < elemNum; counter++)
        {
            a[counter] = fpr_mul(a[counter], ni);
        }
    }
}

void poly_add(fpr * a, const fpr * b, unsigned degIndx)
{
    size_t elemNum, counter;

    elemNum = (size_t)1 << degIndx;
    for (counter = 0; counter < elemNum; counter++)
    {
        a[counter] = fpr_add(a[counter], b[counter]);
    }
}

void poly_sub(fpr * a, const fpr * b, unsigned degIndx)
{
    size_t elemNum, counter;

    elemNum = (size_t)1 << degIndx;

    for (counter = 0; counter < elemNum; counter++)
    {
        a[counter] = fpr_sub(a[counter], b[counter]);
    }
}

void poly_neg(fpr * a, unsigned degIndx)
{
    size_t elemNum, counter;

    elemNum = (size_t)1 << degIndx;
    for (counter = 0; counter < elemNum; counter++)
    {
        a[counter] = fpr_neg(a[counter]);
    }
}

void poly_adj_fft(fpr * a, unsigned degIndx)
{
    size_t elemNum, counter;

    elemNum = (size_t)1 << degIndx;
    for (counter = (elemNum >> 1); counter < elemNum; counter++)
    {
        a[counter] = fpr_neg(a[counter]);
    }
}

void poly_mul_fft(fpr * a, const fpr * b, unsigned degIndx)
{
    size_t elemNum, c, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;

    for (counter = 0; counter < c; counter++)
    {
        fpr xRe, xIm, yRe, yIm;

        xRe = a[counter];
        xIm = a[counter + c];
        yRe = b[counter];
        yIm = b[counter + c];
        FPC_MUL(a[counter], a[counter + c], xRe, xIm, yRe, yIm);
    }
}

void poly_muladj_fft(fpr * a, const fpr * b, unsigned degIndx)
{
    size_t elemNum, c, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;

    for (counter = 0; counter < c; counter++)
    {
        fpr xRe, xIm, yRe, yIm;

        xRe = a[counter];
        xIm = a[counter + c];
        yRe = b[counter];
        yIm = fpr_neg(b[counter + c]);
        FPC_MUL(a[counter], a[counter + c], xRe, xIm, yRe, yIm);
    }
}


void poly_mulselfadj_fft(fpr * a, unsigned degIndx)
{
    size_t elemNum, c, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;

    for (counter = 0; counter < c; counter++)
    {
        fpr xRe, xIm;

        xRe = a[counter];
        xIm = a[counter + c];
        a[counter] = fpr_add(fpr_sqr(xRe), fpr_sqr(xIm));
        a[counter + c] = fpr_zero;
    }
}


void poly_mulconst(fpr * a, fpr x, unsigned degIndx)
{
    size_t elemNum, counter;

    elemNum = (size_t)1 << degIndx;

    for (counter = 0; counter < elemNum; counter++)
    {
        a[counter] = fpr_mul(a[counter], x);
    }
}


void poly_invnorm_2_fft(fpr * d, const fpr * a, const fpr * b, unsigned degIndx)
{
    size_t elemNum, c, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;

    for (counter = 0; counter < c; counter++)
    {
        fpr xRe, xIm;
        fpr yRe, yIm;

        xRe = a[counter];
        xIm = a[counter + c];
        yRe = b[counter];
        yIm = b[counter + c];
        d[counter] = fpr_inv(fpr_add(fpr_add(fpr_sqr(xRe), fpr_sqr(xIm)), fpr_add(fpr_sqr(yRe), fpr_sqr(yIm))));
    }
}


void poly_add_muladj_fft(fpr * e, const fpr * A, const fpr * B, const fpr * a, const fpr * b, unsigned degIndx)
{
    size_t elemNum, f, counter;

    elemNum = (size_t)1 << degIndx;
    f = elemNum >> 1;

    for (counter = 0; counter < f; counter++)
    {
        fpr ARe, AIm, BRe, BIm;
        fpr aRe, aIm, bRe, bIm;
        fpr xRe, xIm, yRe, yIm;

        ARe = A[counter];
        AIm = A[counter + f];
        BRe = B[counter];
        BIm = B[counter + f];
        aRe = a[counter];
        aIm = a[counter + f];
        bRe = b[counter];
        bIm = b[counter + f];

        FPC_MUL(xRe, xIm, ARe, AIm, aRe, fpr_neg(aIm));
        FPC_MUL(yRe, yIm, BRe, BIm, bRe, fpr_neg(bIm));
        e[counter] = fpr_add(xRe, yRe);
        e[counter + f] = fpr_add(xIm, yIm);
    }
}


void poly_mul_autoadj_fft(fpr * a, const fpr * b, unsigned degIndx)
{
    size_t elemNum, c, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;

    for (counter = 0; counter < c; counter++)
    {
        a[counter] = fpr_mul(a[counter], b[counter]);
        a[counter + c] = fpr_mul(a[counter + c], b[counter]);
    }
}


void poly_div_autoadj_fft(fpr * a, const fpr * b, unsigned degIndx)
{
    size_t elemNum, c, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;

    for (counter = 0; counter < c; counter++)
    {
        fpr ib;

        ib = fpr_inv(b[counter]);
        a[counter] = fpr_mul(a[counter], ib);
        a[counter + c] = fpr_mul(a[counter + c], ib);
    }
}


void poly_ldl_fft(const fpr * b00, fpr * b01, fpr * b11, unsigned degIndx)
{
    size_t elemNum, c, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;

    for (counter = 0; counter < c; counter++)
    {
        fpr b00Re, b00Im, b01Re, b01Im, b11Re, b11Im;
        fpr muRe, muIm;

        b00Re = b00[counter];
        b00Im = b00[counter + c];
        b01Re = b01[counter];
        b01Im = b01[counter + c];
        b11Re = b11[counter];
        b11Im = b11[counter + c];
        FPC_DIV(muRe, muIm, b01Re, b01Im, b00Re, b00Im);
        FPC_MUL(b01Re, b01Im, muRe, muIm, b01Re, fpr_neg(b01Im));
        FPC_SUB(b11[counter], b11[counter + c], b11Re, b11Im, b01Re, b01Im);
        b01[counter] = muRe;
        b01[counter + c] = fpr_neg(muIm);
    }
}

void poly_split_fft(fpr * a0, fpr * a1, const fpr * a, unsigned degIndx)
{

    size_t elemNum, c, qn, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;
    qn = c >> 1;


    a0[0] = a[0];
    a1[0] = a[c];

    for (counter = 0; counter < qn; counter++)
    {
        fpr xRe, xIm, yRe, yIm;
        fpr tRe, tIm;

        xRe = a[(counter << 1) + 0];
        xIm = a[(counter << 1) + 0 + c];
        yRe = a[(counter << 1) + 1];
        yIm = a[(counter << 1) + 1 + c];

        FPC_ADD(tRe, tIm, xRe, xIm, yRe, yIm);
        a0[counter] = fpr_half(tRe);
        a0[counter + qn] = fpr_half(tIm);

        FPC_SUB(tRe, tIm, xRe, xIm, yRe, yIm);
        FPC_MUL(
            tRe, tIm, tRe, tIm, fpr_gm_tab[((counter + c) << 1) + 0], fpr_neg(fpr_gm_tab[((counter + c) << 1) + 1])
        );
        a1[counter] = fpr_half(tRe);
        a1[counter + qn] = fpr_half(tIm);
    }
}


void poly_merge_fft(fpr * a, const fpr * a0, const fpr * a1, unsigned degIndx)
{
    size_t elemNum, c, qn, counter;

    elemNum = (size_t)1 << degIndx;
    c = elemNum >> 1;
    qn = c >> 1;


    a[0] = a0[0];
    a[c] = a1[0];

    for (counter = 0; counter < qn; counter++)
    {
        fpr xRe, xIm, yRe, yIm;
        fpr tRe, tIm;

        xRe = a0[counter];
        xIm = a0[counter + qn];
        FPC_MUL(
            yRe, yIm, a1[counter], a1[counter + qn], fpr_gm_tab[((counter + c) << 1) + 0],
            fpr_gm_tab[((counter + c) << 1) + 1]
        );
        FPC_ADD(tRe, tIm, xRe, xIm, yRe, yIm);
        a[(counter << 1) + 0] = tRe;
        a[(counter << 1) + 0 + c] = tIm;
        FPC_SUB(tRe, tIm, xRe, xIm, yRe, yIm);
        a[(counter << 1) + 1] = tRe;
        a[(counter << 1) + 1 + c] = tIm;
    }
}
