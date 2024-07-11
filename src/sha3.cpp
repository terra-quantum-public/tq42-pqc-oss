#include "sha3.h"

#include <cstring>


const unsigned int SHA3::rho_offsets[5][5] = {
    {0, 1, 62, 28, 27}, {36, 44, 6, 55, 20}, {3, 10, 171, 153, 231}, {41, 45, 15, 21, 8}, {18, 2, 61, 56, 14}};

const uint64_t SHA3::sha3_roundConsts[SHA3::NR] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL, 0x000000000000808BULL,
    0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL, 0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

#ifdef __BIG_ENDIAN__
static inline uint16_t endian16(uint16_t x) { return (x >> 8) | (x << 8); }

static inline uint32_t endian32(uint32_t x)
{
    return endian16(x >> 16) | (static_cast<uint32_t>(endian16(static_cast<uint16_t>(x))) << 16);
}
#endif

static inline uint64_t endian_64(uint64_t x)
{
#ifdef __BIG_ENDIAN__
    return endian32(x >> 32) | (static_cast<uint64_t>(endian32(static_cast<uint32_t>(x))) << 32);
#else
    return x;
#endif
}

SHA3::SHA3(int m)
{
    mode = m;
    switch (mode)
    {
    case PQC_SHAKE_128:
        r = 1344 >> 3;
        break;
    case PQC_SHAKE_256:
        r = 1088 >> 3;
        break;
    case PQC_SHA3_224:
        r = 1152 >> 3;
        break;
    case PQC_SHA3_256:
        r = 1088 >> 3;
        break;
    case PQC_SHA3_384:
        r = 832 >> 3;
        break;
    default:
        mode = PQC_SHA3_512;
        r = 576 >> 3;
        break;
    }
    data_buffer_size = 0; // how many bytes in buffer are fulled by data
    for (int i = 0; i < 168; ++i)
    {
        data_buffer[i] = 0;
    }
    c = (1600 >> 3) - r;
    for (int x = 0; x < 5; ++x)
    {
        for (int y = 0; y < 5; ++y)
        {
            State[x][y] = 0LL;
        }
    } // get all as zeros
    hash_size_ = mode >> 3;
    if (mode == PQC_SHAKE_128 || mode == PQC_SHAKE_256)
        hash_size_ = 0;
}

// rotate left and after put around to right
uint64_t SHA3::rot_word(uint64_t word, unsigned int d)
{
    if (d)
        return (word << (d & 0x3f)) | (word >> (64 - (d & 0x3f)));
    else
        return word;
}

void SHA3::theta()
{
    uint64_t C[5];
    uint64_t D[5];
    for (int i = 0; i < 5; ++i)
    {
        C[i] = 0LL;
    }
    for (int x = 0; x < 5; ++x)
    {
        for (int y = 0; y < 5; ++y)
        {
            C[x] ^= State[x][y];
        }
    }
    for (int i = 0; i < 5; ++i)
    {
        D[i] = C[(i + 4) % 5] ^ rot_word(C[(i + 1) % 5], 1);
    }
    for (int y = 0; y < 5; ++y)
    {
        for (int x = 0; x < 5; ++x)
        {
            State[x][y] ^= D[x];
        }
    }
}

void SHA3::rho()
{
    for (int y = 0; y < 5; ++y)
    {
        for (int x = 0; x < 5; ++x)
        {
            State[x][y] = rot_word(State[x][y], rho_offsets[y][x]);
        }
    }
}

void SHA3::pi()
{
    uint64_t new_State[5][5];
    for (int y = 0; y < 5; ++y)
    {
        for (int x = 0; x < 5; ++x)
        {
            new_State[x][y] = State[(x + 3 * y) % 5][x];
        }
    }
    for (int y = 0; y < 5; ++y)
    {
        for (int x = 0; x < 5; ++x)
        {
            State[x][y] = new_State[x][y];
        }
    }
}

void SHA3::chi()
{
    uint64_t new_State[5][5];
    for (int y = 0; y < 5; ++y)
    {
        for (int x = 0; x < 5; ++x)
        {
            new_State[x][y] = (~State[(x + 1) % 5][y]) & State[(x + 2) % 5][y];
        }
    }
    for (int y = 0; y < 5; ++y)
    {
        for (int x = 0; x < 5; ++x)
        {
            State[x][y] ^= new_State[x][y];
        }
    }
}

void SHA3::yota(size_t i) { State[0][0] ^= sha3_roundConsts[i]; }

void SHA3::keccak_1600()
{
    for (size_t i = 0; i < NR; ++i)
    {
        theta();
        rho();
        pi();
        chi();
        yota(i);
    }
}

void SHA3::mix_r_block_of_data_into_state(const void * data, unsigned int r_)
{
    const uint64_t * data64 = (const uint64_t *)data; // const void* data
    unsigned int cursor = 0;
    int x, y;
    while (cursor < (r_ >> 3))
    { // r>>3 - is how many words length 64 bits in on r-block
        x = cursor % 5;
        y = cursor / 5;
        State[x][y] ^= endian_64(data64[cursor]);
        cursor++;
    }
}

// add some bytes to State. data_size is number of bytes to be added
void SHA3::add_data(const ConstBufferView & data)
{
    for (unsigned long long int cursor = 0; cursor < data.size(); ++cursor)
    {
        data_buffer[data_buffer_size] = data.const_data()[cursor]; // saving data to buffer
        data_buffer_size++;
        if (data_buffer_size == r)
        {
            mix_r_block_of_data_into_state(data_buffer, r);
            data_buffer_size = 0;
            keccak_1600();
        }
    }
}

void SHA3::shake_padding(int withCopy)
{
    if (withCopy != 0)
    {
        // Copy of buffer state!
        for (size_t i = 0; i < 168; ++i)
        {
            data_buffer_copy[i] = data_buffer[i];
        }
        data_buffer_size_copy = data_buffer_size;
        for (size_t y = 0; y < 5; ++y)
        {
            for (size_t x = 0; x < 5; ++x)
            {
                State_copy[x][y] = State[x][y];
            }
        }
    }

    size_t bytes_to_pad = r - data_buffer_size;
    for (size_t i = 0; i < bytes_to_pad; ++i)
    { // add zeros
        data_buffer[data_buffer_size] = 0;
        data_buffer_size++;
    }
    // add first byte
    data_buffer[r - bytes_to_pad] |= 0x1F;
    // add last byte
    data_buffer[data_buffer_size - 1] |= 0x80;
    data_buffer_size = 0;
    add_data(ConstBufferView(data_buffer, r));
}


void SHA3::padding(int withCopy)
{
    if (withCopy != 0)
    {
        // Copy of buffer state!
        for (size_t i = 0; i < 168; ++i)
        {
            data_buffer_copy[i] = data_buffer[i];
        }
        data_buffer_size_copy = data_buffer_size;
        for (size_t y = 0; y < 5; ++y)
        {
            for (size_t x = 0; x < 5; ++x)
            {
                State_copy[x][y] = State[x][y];
            }
        }
    }

    size_t bytes_to_pad = r - data_buffer_size;
    for (size_t i = 0; i < bytes_to_pad; ++i)
    { // add zeros
        data_buffer[data_buffer_size] = 0;
        data_buffer_size++;
    }
    // add first byte
    data_buffer[r - bytes_to_pad] |= 0x06; // 0x1F
    // add last byte
    data_buffer[data_buffer_size - 1] |= 0x80;
    data_buffer_size = 0;
    add_data(ConstBufferView(data_buffer, r));
}


void SHA3::shake_squeezing(const BufferView & HASH, int withCopy) // uint64_t hashShakeSize, uint8_t* ShakeHash, int
                                                                  // withCopy)
{
    uint8_t message[200]; // 200 because there  is the state size
    uint64_t gamma = 0xffLL;

    uint64_t Counter = 0;

    while (Counter < HASH.size())
    {
        for (int y = 0; y < 5; ++y)
        {
            for (int x = 0; x < 5; ++x)
            {
                for (int i = 0; i < 8; ++i)
                {
                    gamma = 0xffLL;
                    gamma <<= (i * 8);
                    message[(y * 5 + x) * 8 + i] = (uint8_t)((State[x][y] & gamma) >> (i * 8));
                }
            }
        }
        for (unsigned int i = 0; i < r; ++i)
        {
            if (HASH.size() > Counter)
            {
                HASH.data()[Counter] = message[i];
            }
            Counter++;
        }
        if (HASH.size() >= Counter)
        {
            keccak_1600();
        }
    }
    if (withCopy != 0)
    {
        // Get buffer state back!
        for (int i = 0; i < 168; ++i)
        {
            data_buffer[i] = data_buffer_copy[i];
        }
        data_buffer_size = data_buffer_size_copy;
        for (int y = 0; y < 5; ++y)
        {
            for (int x = 0; x < 5; ++x)
            {
                State[x][y] = State_copy[x][y];
            }
        }
    }
}


void SHA3::squeezing(int withCopy)
{
    uint8_t message[80]; // 40 because there are no hash legth more than 64 byte
    uint64_t gamma = 0xffLL;

    for (int y = 0; y < 2; ++y)
    {
        for (int x = 0; x < 5; ++x)
        {
            for (int i = 0; i < 8; ++i)
            {
                gamma = 0xffLL;
                gamma <<= (i * 8);
                message[(y * 5 + x) * 8 + i] = (uint8_t)((State[x][y] & gamma) >> (i * 8));
            }
        }
    }
    for (unsigned int i = 0; i < hash_size_; ++i)
    {
        hash[i] = message[i];
    }

    if (withCopy != 0)
    {
        // Get buffer state back!
        for (int i = 0; i < 168; ++i)
        {
            data_buffer[i] = data_buffer_copy[i];
        }
        data_buffer_size = data_buffer_size_copy;
        for (int y = 0; y < 5; ++y)
        {
            for (int x = 0; x < 5; ++x)
            {
                State[x][y] = State_copy[x][y];
            }
        }
    }
}

uint8_t * SHA3::get_hash()
{
    padding(1);
    squeezing(1);
    return hash;
}

void SHA3::get_shake_hash(const BufferView & hash_)
{
    shake_padding(1);
    shake_squeezing(hash_, 1);
}


void SHA3::do_force_padding(int withCopy)
{
    if ((mode == PQC_SHAKE_128) || (mode == PQC_SHAKE_256))
        shake_padding(withCopy);
    else
        padding(1);
}

// Only 224/256/384/512 hashShakeSizes for sha3-224/sha3-256/sha3-384/sha3-512
void SHA3::do_force_squeeze(const BufferView & HASH)
{
    if ((mode == PQC_SHAKE_128) || (mode == PQC_SHAKE_256))
        shake_squeezing(HASH, 0);
    else
    {
        squeezing(0);
        for (size_t i = 0; i < HASH.size(); ++i)
            HASH.data()[i] = hash[i];
    }
}

void SHA3::get_hash(const BufferView & hash_)
{
    if (hash_.size() != hash_size())
    {
        if (get_mode() != PQC_SHAKE_128)
            if (get_mode() != PQC_SHAKE_256)
                throw BadLength();
        if (hash_.size() == 0)
            throw BadLength();
    }
    if (get_mode() != PQC_SHAKE_128)
        if (get_mode() != PQC_SHAKE_256)
            memcpy(hash_.data(), get_hash(), hash_.size());
    if (get_mode() == PQC_SHAKE_128 || get_mode() == PQC_SHAKE_256)
        get_shake_hash(hash_);
}

std::unique_ptr<PQC_Context> SHA3Factory::create_context_hash(uint32_t mode) const
{
    return std::make_unique<SHA3>(mode);
}
