#include "sort.h"


inline static void uint_64_minmax(uint64_t & a, uint64_t & b)
{
    uint64_t c = b - a;
    c >>= 63;
    c = ~c + 1;
    c &= a ^ b;
    a ^= c;
    b ^= c;
}

inline static void int_32_minmax(int32_t & a, int32_t & b)
{
    int32_t ab = b ^ a;
    int32_t c = b - a;
    c ^= ab & (c ^ b);
    c >>= 31;
    c &= ab;
    a ^= c;
    b ^= c;
}

void uint_64_sort(uint64_t * x, long long n)
{
    long long top, p, q, r, i;

    if (n < 2)
        return;
    top = 1;
    while (top < n - top)
        top += top;

    for (p = top; p > 0; p >>= 1)
    {
        for (i = 0; i < n - p; ++i)
            if (!(i & p))
                uint_64_minmax(x[i], x[i + p]);
        i = 0;
        for (q = top; q > p; q >>= 1)
        {
            for (; i < n - q; ++i)
            {
                if (!(i & p))
                {
                    uint64_t a = x[i + p];
                    for (r = q; r > p; r >>= 1)
                        uint_64_minmax(a, x[i + r]);
                    x[i + p] = a;
                }
            }
        }
    }
}

void int_32_sort(int32_t * x, long long n)
{
    long long top, p, q, r, i;

    if (n < 2)
        return;
    top = 1;
    while (top < n - top)
        top += top;

    for (p = top; p > 0; p >>= 1)
    {
        for (i = 0; i < n - p; ++i)
            if (!(i & p))
                int_32_minmax(x[i], x[i + p]);
        i = 0;
        for (q = top; q > p; q >>= 1)
        {
            for (; i < n - q; ++i)
            {
                if (!(i & p))
                {
                    int32_t a = x[i + p];
                    for (r = q; r > p; r >>= 1)
                        int_32_minmax(a, x[i + r]);
                    x[i + p] = a;
                }
            }
        }
    }
}
