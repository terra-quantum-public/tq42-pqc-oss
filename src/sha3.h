#pragma once

#include <cstdint>

#include <pqc/sha3.h>

#include <buffer.h>
#include <core.h>


class SHA3 : public HashContext
{
    /*
        The values of constants SHA3_224, SHA3_256, SHA3_384, SHA3_512 are stored in bits. The rest are stored in bytes
        by default. When referring to constants, both constants and variables are meant, primarily those from the
        algorithm standard. For example, r and c.
    */

public:
    SHA3(int mode);

    // add some bytes to State. data_size is number of bytes to be added
    virtual void add_data(const ConstBufferView & data) override;
    virtual void get_hash(const BufferView & hash) override;


    uint8_t * get_hash();
    void get_shake_hash(const BufferView & hash);
    virtual size_t hash_size() const override { return hash_size_; }
    unsigned int get_mode() { return mode; }

    void do_force_padding(int withCopy);
    void do_force_squeeze(const BufferView & HASH);

private:
    // rotate left and after put around to right
    uint64_t rot_word(uint64_t word, unsigned int d);

    void theta();
    void pi();
    void chi();
    void yota(size_t i);
    void rho();
    void keccak_1600();

    void mix_r_block_of_data_into_state(const void * data, unsigned int r);


    void padding(int withCopy);
    void shake_padding(int withCopy);
    void shake_squeezing(const BufferView & HASH, int withCopy);
    void squeezing(int withCopy);

private:
    int mode;
    unsigned int r;
    int c;
    uint64_t State[5][5] = {{0}};   // Current State
    uint8_t data_buffer[168] = {0}; // 168 is the max r butes number (case SHAKE_128)
    size_t data_buffer_size = 0;    // how many bytes in buffer are fulled by data

    uint8_t hash[64] = {0};
    size_t hash_size_ = 0;

    // Copy to get middle hashes
    uint8_t data_buffer_copy[168] = {0};
    size_t data_buffer_size_copy = 0;
    uint64_t State_copy[5][5] = {{0}};

    static const unsigned int rho_offsets[5][5];
    static constexpr size_t L = 6;
    static constexpr size_t NR = 12 + 2 * L;
    static constexpr size_t B = 25 << L;
    static const uint64_t sha3_roundConsts[NR];
};

class SHA3Factory : public AlgorithmFactory
{
public:
    virtual std::unique_ptr<PQC_Context> create_context_hash(uint32_t mode) const override;

    virtual uint32_t cipher_id() const override { return PQC_CIPHER_SHA3; }

    virtual size_t get_length(uint32_t) const override { throw UnsupportedOperation(); }
};
