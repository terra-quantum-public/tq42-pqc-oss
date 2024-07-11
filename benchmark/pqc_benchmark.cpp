#include <benchmark/benchmark.h>
#include <iostream>

#include <pqc/aes.h>

template <uint32_t mode> void aes_encrypt(benchmark::State & state)
{
    CIPHER_HANDLE context;

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                   'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int64_t data_len = state.range(0);
    uint8_t * data = new uint8_t[data_len];

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    size_t res = 0;
    for (auto _ : state)
    {
        res = PQC_encrypt(context, mode, data, data_len);
    }

    if (res != PQC_OK)
    {
        std::cerr << "PQC_encrypt failed" << std::endl;
        abort();
    }

    benchmark::DoNotOptimize(data);
    state.SetBytesProcessed(state.iterations() * data_len);

    delete[] data;
}


template <uint32_t mode> void aes_decrypt(benchmark::State & state)
{
    CIPHER_HANDLE context;

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                   'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int64_t data_len = state.range(0);
    uint8_t * data = new uint8_t[data_len];

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    size_t res = 0;
    for (auto _ : state)
    {
        res = PQC_decrypt(context, mode, data, data_len);
    }

    if (res != PQC_OK)
    {
        std::cerr << "PQC_decrypt failed" << std::endl;
        abort();
    }

    benchmark::DoNotOptimize(data);
    state.SetBytesProcessed(state.iterations() * data_len);

    delete[] data;
}


BENCHMARK(aes_encrypt<PQC_AES_M_ECB>)->Arg(PQC_AES_BLOCKLEN);
BENCHMARK(aes_decrypt<PQC_AES_M_ECB>)->Arg(PQC_AES_BLOCKLEN);

BENCHMARK(aes_encrypt<PQC_AES_M_CTR>)->Arg(PQC_AES_BLOCKLEN * 100);
BENCHMARK(aes_decrypt<PQC_AES_M_CTR>)->Arg(PQC_AES_BLOCKLEN * 100);

BENCHMARK(aes_encrypt<PQC_AES_M_CBC>)->Arg(PQC_AES_BLOCKLEN * 100);
BENCHMARK(aes_decrypt<PQC_AES_M_CBC>)->Arg(PQC_AES_BLOCKLEN * 100);

BENCHMARK(aes_encrypt<PQC_AES_M_OFB>)->Arg(PQC_AES_BLOCKLEN * 100);
BENCHMARK(aes_decrypt<PQC_AES_M_OFB>)->Arg(PQC_AES_BLOCKLEN * 100);

BENCHMARK_MAIN();
