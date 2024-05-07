#include "pq17.h"
#include "sha3.h"
#include <chrono>
#include <cstring>

PQ17prng_engine::PQ17prng_engine(const pqc_aes_key * key, const pqc_aes_iv * iv) : aes(key, iv) {}

uint64_t PQ17prng_engine::generate()
{
    if (next == 0)
    {
        step();
    }
    next = 1 - next;
    return r[next];
}

void PQ17prng_engine::random_bytes(uint8_t * buf, size_t size)
{
    const size_t type_size = sizeof(uint64_t);
    size_t num_to_gen = size / type_size;
    size_t remainder = size % type_size;

    uint64_t * pos = reinterpret_cast<uint64_t *>(buf);
    for (size_t i = 0; i < num_to_gen; ++i)
        pos[i] = generate();

    uint64_t last_val = generate();
    const size_t index = num_to_gen * type_size;
    memcpy(buf + index, &last_val, remainder);
}

std::unique_ptr<IRandomGenerator> PQ17prng_engine::default_generator()
{
    uint8_t default_key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
                                          '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
                                          '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};

    uint8_t default_iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    return std::make_unique<PQ17prng_engine>((const pqc_aes_key *)default_key, (const pqc_aes_iv *)default_iv);
}

void PQ17prng_engine::step()
{
    std::chrono::system_clock::time_point current_time = std::chrono::system_clock::now();

    uint64_t dt[2] = {0};

    memcpy(dt, &current_time, std::min(sizeof(uint64_t) * 2, sizeof(current_time)));

    SHA3 sha3(PQC_SHA3_256);
    sha3.add_data(ConstBufferView::from_single(dt[0]));
    memcpy(dt, sha3.get_hash() + 8, sizeof(uint64_t) * 2);

    BufferView dataDT = BufferView(reinterpret_cast<uint8_t *>(dt), 1);
    aes.ofb_xcrypt(dataDT);

    r[0] = dt[0] ^ v[0];
    r[1] = dt[1] ^ v[1];
    BufferView dataR = BufferView(reinterpret_cast<uint8_t *>(&r), 1);
    aes.ofb_xcrypt(dataR);

    v[0] = r[0] ^ dt[0];
    v[1] = r[1] ^ dt[1];

    BufferView dataV = BufferView(reinterpret_cast<uint8_t *>(&v), 1);
    aes.ofb_xcrypt(dataV);
}
