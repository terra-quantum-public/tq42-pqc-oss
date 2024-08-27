#include "buffer.h"

class Vector128
{
public:
    Vector128()
    {
        data_[0] = 0;
        data_[1] = 0;
    }
    Vector128(const Vector128 & other)
    {
        data_[0] = other.data_[0];
        data_[1] = other.data_[1];
    }

    Vector128 & operator^=(const Vector128 & other)
    {
        data_[0] ^= other.data_[0];
        data_[1] ^= other.data_[1];
        return *this;
    }

    template <int n> Vector128 & shr()
    {
        lo64() = (hi64() << (64 - n)) | (lo64() >> n);
        hi64() = (hi64() >> n);
        return *this;
    }

    Vector128 & load_be(const ConstBufferView & memory)
    {
#ifndef NDEBUG
        if (memory.size() != 16)
        {
            throw std::invalid_argument("Bad buffer size");
        }
#endif
        hi64() = memory.load_64_be(0);
        lo64() = memory.load_64_be(1);
        return *this;
    }

    Vector128 & store_be(const BufferView & memory)
    {
#ifndef NDEBUG
        if (memory.size() != 16)
        {
            throw std::invalid_argument("Bad buffer size");
        }
#endif
        memory.store_64_be(0, hi64());
        memory.store_64_be(1, lo64());
        return *this;
    }

    uint64_t & hi64() { return data_[1]; }
    uint64_t & lo64() { return data_[0]; }

private:
    uint64_t data_[2]; // element 0 is Low, element 1 is High
};