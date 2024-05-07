#include "inner.h"

size_t modq_encode(void * rez, size_t maxRezSize, const uint16_t * a, unsigned degIndex)
{
    size_t elemNum, rezSize, counter;
    uint8_t * buffer;
    uint32_t accum;
    int accum_Size;

    elemNum = (size_t)1 << degIndex;
    for (counter = 0; counter < elemNum; counter++)
    {
        if (a[counter] >= 12289)
        {
            return 0;
        }
    }
    rezSize = ((elemNum * 14) + 7) >> 3;
    if (rez == NULL)
    {
        return rezSize;
    }
    if (rezSize > maxRezSize)
    {
        return 0;
    }
    buffer = (uint8_t *)rez;
    accum = 0;
    accum_Size = 0;
    for (counter = 0; counter < elemNum; counter++)
    {
        accum = (accum << 14) | a[counter];
        accum_Size += 14;
        while (accum_Size >= 8)
        {
            accum_Size -= 8;
            *buffer++ = (uint8_t)(accum >> accum_Size);
        }
    }
    if (accum_Size > 0)
    {
        *buffer = (uint8_t)(accum << (8 - accum_Size));
    }
    return rezSize;
}

size_t modq_decode(uint16_t * a, unsigned degIndex, const void * inp, size_t maxInpSize)
{
    size_t elemNum, inpSize, counter;
    const uint8_t * buffer;
    uint32_t accum;
    int accum_Size;

    elemNum = (size_t)1 << degIndex;
    inpSize = ((elemNum * 14) + 7) >> 3;
    if (inpSize > maxInpSize)
    {
        return 0;
    }
    buffer = (uint8_t *)inp;
    accum = 0;
    accum_Size = 0;
    counter = 0;
    while (counter < elemNum)
    {
        accum = (accum << 8) | (*buffer++);
        accum_Size += 8;
        if (accum_Size >= 14)
        {
            unsigned use;

            accum_Size -= 14;
            use = (accum >> accum_Size) & 0x3FFF;
            if (use >= 12289)
            {
                return 0;
            }
            a[counter++] = (uint16_t)use;
        }
    }
    if ((accum & (((uint32_t)1 << accum_Size) - 1)) != 0)
    {
        return 0;
    }
    return inpSize;
}

size_t trim_i_16_encode(void * rez, size_t maxRezSize, const int16_t * a, unsigned degIndex, unsigned bits)
{
    size_t elemNum, counter, rezSize;
    int useMin, useMax;
    uint8_t * buffer;
    uint32_t accum, mask;
    unsigned accum_Size;

    elemNum = (size_t)1 << degIndex;
    useMax = (1 << (bits - 1)) - 1;
    useMin = -useMax;
    for (counter = 0; counter < elemNum; counter++)
    {
        if (a[counter] < useMin || a[counter] > useMax)
        {
            return 0;
        }
    }
    rezSize = ((elemNum * bits) + 7) >> 3;
    if (rez == NULL)
    {
        return rezSize;
    }
    if (rezSize > maxRezSize)
    {
        return 0;
    }
    buffer = (uint8_t *)rez;
    accum = 0;
    accum_Size = 0;
    mask = ((uint32_t)1 << bits) - 1;
    for (counter = 0; counter < elemNum; counter++)
    {
        accum = (accum << bits) | ((uint16_t)a[counter] & mask);
        accum_Size += bits;
        while (accum_Size >= 8)
        {
            accum_Size -= 8;
            *buffer++ = (uint8_t)(accum >> accum_Size);
        }
    }
    if (accum_Size > 0)
    {
        *buffer++ = (uint8_t)(accum << (8 - accum_Size));
    }
    return rezSize;
}

size_t trim_i_16_decode(int16_t * a, unsigned degIndex, unsigned bits, const void * inp, size_t maxInpSize)
{
    size_t elemNum, inpSize;
    const uint8_t * buffer;
    size_t counter;
    uint32_t accum, mask1, mask2;
    unsigned accum_Size;

    elemNum = (size_t)1 << degIndex;
    inpSize = ((elemNum * bits) + 7) >> 3;
    if (inpSize > maxInpSize)
    {
        return 0;
    }
    buffer = (uint8_t *)inp;
    counter = 0;
    accum = 0;
    accum_Size = 0;
    mask1 = ((uint32_t)1 << bits) - 1;
    mask2 = (uint32_t)1 << (bits - 1);
    while (counter < elemNum)
    {
        accum = (accum << 8) | *buffer++;
        accum_Size += 8;
        while (accum_Size >= bits && counter < elemNum)
        {
            uint32_t use;

            accum_Size -= bits;
            use = (accum >> accum_Size) & mask1;
            use |= -(use & mask2);
            if (use == -mask2)
            {

                return 0;
            }
            use |= -(use & mask2);
            a[counter++] = (int16_t) * (int32_t *)&use;
        }
    }
    if ((accum & (((uint32_t)1 << accum_Size) - 1)) != 0)
    {

        return 0;
    }
    return inpSize;
}

size_t trim_i_8_encode(void * rez, size_t maxRezSize, const int8_t * a, unsigned degIndex, unsigned bits)
{
    size_t elemNum, counter, rezSize;
    int useMin, useMax;
    uint8_t * buffer;
    uint32_t accum, mask;
    unsigned accum_Size;

    elemNum = (size_t)1 << degIndex;
    useMax = (1 << (bits - 1)) - 1;
    useMin = -useMax;
    for (counter = 0; counter < elemNum; counter++)
    {
        if (a[counter] < useMin || a[counter] > useMax)
        {
            return 0;
        }
    }
    rezSize = ((elemNum * bits) + 7) >> 3;
    if (rez == NULL)
    {
        return rezSize;
    }
    if (rezSize > maxRezSize)
    {
        return 0;
    }
    buffer = (uint8_t *)rez;
    accum = 0;
    accum_Size = 0;
    mask = ((uint32_t)1 << bits) - 1;
    for (counter = 0; counter < elemNum; counter++)
    {
        accum = (accum << bits) | ((uint8_t)a[counter] & mask);
        accum_Size += bits;
        while (accum_Size >= 8)
        {
            accum_Size -= 8;
            *buffer++ = (uint8_t)(accum >> accum_Size);
        }
    }
    if (accum_Size > 0)
    {
        *buffer++ = (uint8_t)(accum << (8 - accum_Size));
    }
    return rezSize;
}

size_t trim_i_8_decode(int8_t * a, unsigned degIndex, unsigned bits, const void * inp, size_t maxInpSize)
{
    size_t elemNum, inpSize;
    const uint8_t * buffer;
    size_t counter;
    uint32_t accum, mask1, mask2;
    unsigned accum_Size;

    elemNum = (size_t)1 << degIndex;
    inpSize = ((elemNum * bits) + 7) >> 3;
    if (inpSize > maxInpSize)
    {
        return 0;
    }
    buffer = (uint8_t *)inp;
    counter = 0;
    accum = 0;
    accum_Size = 0;
    mask1 = ((uint32_t)1 << bits) - 1;
    mask2 = (uint32_t)1 << (bits - 1);
    while (counter < elemNum)
    {
        accum = (accum << 8) | *buffer++;
        accum_Size += 8;
        while (accum_Size >= bits && counter < elemNum)
        {
            uint32_t use;

            accum_Size -= bits;
            use = (accum >> accum_Size) & mask1;
            use |= -(use & mask2);
            if (use == -mask2)
            {

                return 0;
            }
            a[counter++] = (int8_t) * (int32_t *)&use;
        }
    }
    if ((accum & (((uint32_t)1 << accum_Size) - 1)) != 0)
    {

        return 0;
    }
    return inpSize;
}


size_t comp_encode(void * rez, size_t maxRezSize, const int16_t * a, unsigned degIndex)
{
    uint8_t * buffer;
    size_t elemNum, counter, flag;
    uint32_t accum;
    unsigned accum_Size;

    elemNum = (size_t)1 << degIndex;
    buffer = (uint8_t *)rez;

    for (counter = 0; counter < elemNum; counter++)
    {
        if (a[counter] < -2047 || a[counter] > +2047)
        {
            return 0;
        }
    }

    accum = 0;
    accum_Size = 0;
    flag = 0;
    for (counter = 0; counter < elemNum; counter++)
    {
        int use1;
        unsigned use2;

        accum <<= 1;
        use1 = a[counter];
        if (use1 < 0)
        {
            use1 = -use1;
            accum |= 1;
        }
        use2 = (unsigned)use1;

        accum <<= 7;

        accum |= use2 & 127u;
        use2 >>= 7;

        accum_Size += 8;

        accum <<= (use2 + 1);
        accum |= 1;
        accum_Size += use2 + 1;

        while (accum_Size >= 8)
        {
            accum_Size -= 8;
            if (buffer != NULL)
            {
                if (flag >= maxRezSize)
                {
                    return 0;
                }
                buffer[flag] = (uint8_t)(accum >> accum_Size);
            }
            flag++;
        }
    }

    if (accum_Size > 0)
    {
        if (buffer != NULL)
        {
            if (flag >= maxRezSize)
            {
                return 0;
            }
            buffer[flag] = (uint8_t)(accum << (8 - accum_Size));
        }
        flag++;
    }

    return flag;
}

size_t comp_decode(int16_t * a, unsigned degIndex, const void * inp, size_t maxInpSize)
{
    const uint8_t * buffer;
    size_t elemNum, counter, flag;
    uint32_t accum;
    unsigned accum_Size;

    elemNum = (size_t)1 << degIndex;
    buffer = (uint8_t *)inp;
    accum = 0;
    accum_Size = 0;
    flag = 0;
    for (counter = 0; counter < elemNum; counter++)
    {
        unsigned use1, use2, use3;

        if (flag >= maxInpSize)
        {
            return 0;
        }
        accum = (accum << 8) | (uint32_t)buffer[flag++];
        use1 = accum >> accum_Size;
        use2 = use1 & 128;
        use3 = use1 & 127;

        for (;;)
        {
            if (accum_Size == 0)
            {
                if (flag >= maxInpSize)
                {
                    return 0;
                }
                accum = (accum << 8) | (uint32_t)buffer[flag++];
                accum_Size = 8;
            }
            accum_Size--;
            if (((accum >> accum_Size) & 1) != 0)
            {
                break;
            }
            use3 += 128;
            if (use3 > 2047)
            {
                return 0;
            }
        }

        if (use2 && use3 == 0)
        {
            return 0;
        }

        a[counter] = (int16_t)(use2 ? -(int)use3 : (int)use3);
    }

    if ((accum & ((1u << accum_Size) - 1u)) != 0)
    {
        return 0;
    }

    return flag;
}

const uint8_t max_fg_bits[] = {0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5};

const uint8_t max_FG_bits[] = {0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};

const uint8_t max_sig_bits[] = {0, 10, 11, 11, 12, 12, 12, 12, 12, 12, 12};
