#include "falcon.h"

#include <buffer.h>


void hash_to_point_vartime(inner_shake256_context * cntxt, uint16_t * a, unsigned degIndex)
{
    size_t elemNum;

    elemNum = (size_t)1 << degIndex;
    while (elemNum > 0)
    {
        StackBuffer<2> buffer;
        uint32_t use;

        shake_256_extract(((shake256_context *)cntxt), buffer);
        use = ((unsigned)buffer[0] << 8) | (unsigned)buffer[1];
        if (use < 61445)
        {
            while (use >= 12289)
            {
                use -= 12289;
            }
            *a++ = (uint16_t)use;
            elemNum--;
        }
    }
}

void hash_to_point_ct(inner_shake256_context * cntxt, uint16_t * a, unsigned degIndex, uint8_t * temp)
{
    static const uint16_t overArr[] = {0, 65, 67, 71, 77, 86, 100, 122, 154, 205, 287};

    unsigned use, use2, counter, flag, counter2, over;
    uint16_t *t1, t2[63];

    use = 1U << degIndex;
    use2 = use << 1;
    over = overArr[degIndex];
    flag = use + over;
    t1 = (uint16_t *)temp;
    for (counter = 0; counter < flag; counter++)
    {
        StackBuffer<2> buffer;
        uint32_t w, r;

        shake_256_extract(((shake256_context *)cntxt), buffer);
        w = ((uint32_t)buffer[0] << 8) | (uint32_t)buffer[1];
        r = w - ((uint32_t)24578 & (((w - 24578) >> 31) - 1));
        r = r - ((uint32_t)24578 & (((r - 24578) >> 31) - 1));
        r = r - ((uint32_t)12289 & (((r - 12289) >> 31) - 1));
        r |= ((w - 61445) >> 31) - 1;
        if (counter < use)
        {
            a[counter] = (uint16_t)r;
        }
        else if (counter < use2)
        {
            t1[counter - use] = (uint16_t)r;
        }
        else
        {
            t2[counter - use2] = (uint16_t)r;
        }
    }

    for (counter2 = 1; counter2 <= over; counter2 <<= 1)
    {
        unsigned g;


        g = 0;
        for (counter = 0; counter < flag; counter++)
        {
            uint16_t *h, *c;
            unsigned j, hg, cg, d;

            if (counter < use)
            {
                h = &a[counter];
            }
            else if (counter < use2)
            {
                h = &t1[counter - use];
            }
            else
            {
                h = &t2[counter - use2];
            }
            hg = *h;

            j = counter - g;


            d = (hg >> 15) - 1U;
            g -= d;


            if (counter < counter2)
            {
                continue;
            }

            if ((counter - counter2) < use)
            {
                c = &a[counter - counter2];
            }
            else if ((counter - counter2) < use2)
            {
                c = &t1[(counter - counter2) - use];
            }
            else
            {
                c = &t2[(counter - counter2) - use2];
            }
            cg = *c;

            d &= -(((j & counter2) + 0x1FF) >> 9);

            *h = (uint16_t)(hg ^ (d & (hg ^ cg)));
            *c = (uint16_t)(cg ^ (d & (hg ^ cg)));
        }
    }
}

static const uint32_t l2_bound[] = {0,       101498,  208714,   428865,   892039,  1852696,
                                    3842630, 7959734, 16468416, 34034726, 70265242};

int is_short(const int16_t * a1, const int16_t * a2, unsigned degIndex)
{
    size_t elemNum, counter;
    uint32_t b, c;

    elemNum = (size_t)1 << degIndex;
    b = 0;
    c = 0;
    for (counter = 0; counter < elemNum; counter++)
    {
        int32_t d;

        d = a1[counter];
        b += (uint32_t)(d * d);
        c |= b;
        d = a2[counter];
        b += (uint32_t)(d * d);
        c |= b;
    }
    b |= -(c >> 31);

    return b <= l2_bound[degIndex];
}

int is_short_half(uint32_t satSquareNorm, const int16_t * a, unsigned degIndex)
{
    size_t elemNum, counter;
    uint32_t ng;

    elemNum = (size_t)1 << degIndex;
    ng = -(satSquareNorm >> 31);
    for (counter = 0; counter < elemNum; counter++)
    {
        int32_t use;

        use = a[counter];
        satSquareNorm += (uint32_t)(use * use);
        ng |= satSquareNorm;
    }
    satSquareNorm |= -(ng >> 31);

    return satSquareNorm <= l2_bound[degIndex];
}
