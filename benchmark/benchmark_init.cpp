#include <benchmark/benchmark.h>
#include <iostream>
#include <pqc/aes.h>
#include <thread>
#include <vector>

template <uint32_t cipher> void init(benchmark::State & state)
{
    std::vector<CIPHER_HANDLE> contexts;
    contexts.reserve(state.max_iterations);

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                   'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    for (auto _ : state)
    {
        contexts.push_back(PQC_context_init_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN));
    }

    for (CIPHER_HANDLE h : contexts)
    {
        PQC_context_close(h);
    }

    state.SetItemsProcessed(contexts.size());
}


template <uint32_t cipher> void remove(benchmark::State & state)
{
    std::vector<CIPHER_HANDLE> contexts;
    contexts.reserve(state.max_iterations);

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                   'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    for (int i = 0; i < state.max_iterations; ++i)
    {
        contexts.push_back(PQC_context_init_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN));
    }

    int i = 0;
    for (auto _ : state)
    {
        PQC_context_close(contexts[i++]);
    }

    state.SetItemsProcessed(contexts.size());
}

template <int open_context_count> void multi_context_operation(benchmark::State & state)
{
    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                   'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int64_t data_len = PQC_AES_BLOCKLEN * 5;
    std::vector<uint8_t> data(data_len, 0);

    size_t res = 0;
    for (auto _ : state)
    {
        CIPHER_HANDLE contexts[open_context_count];
        for (int i = 0; i < open_context_count; ++i)
        {
            contexts[i] = PQC_context_init_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
            res = PQC_symmetric_encrypt(contexts[i], PQC_AES_M_OFB, data.data(), data.size());
            if (res != PQC_OK)
            {
                std::cerr << "PQC_encrypt failed: " << res << std::endl;
                abort();
            }
        }

        for (CIPHER_HANDLE context : contexts)
        {
            PQC_context_close(context);
        }
    }

    benchmark::DoNotOptimize(data);
    state.SetBytesProcessed(state.iterations() * data_len);
    state.SetItemsProcessed(state.iterations() * open_context_count);
}

void single_context_operation(benchmark::State & state)
{
    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'A', 'B', 'C', 'D', 'E', 'F',
                                   'G', 'H', 'I', 'J', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'K', 'L'};

    const int64_t data_len = PQC_AES_BLOCKLEN * 5;
    std::vector<uint8_t> data(data_len, 0);

    size_t res = 0;
    for (auto _ : state)
    {
        CIPHER_HANDLE context;
        context = PQC_context_init_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);
        res = PQC_symmetric_encrypt(context, PQC_AES_M_OFB, data.data(), data.size());
        if (res != PQC_OK)
        {
            std::cerr << "PQC_encrypt failed: " << res << std::endl;
            abort();
        }
        PQC_context_close(context);
    }

    benchmark::DoNotOptimize(data);
    state.SetBytesProcessed(state.iterations() * data_len);
    state.SetItemsProcessed(state.iterations());
}


BENCHMARK(init<PQC_CIPHER_AES>)->Arg(10000);
BENCHMARK(remove<PQC_CIPHER_AES>)->Arg(10000);
BENCHMARK(init<PQC_CIPHER_AES>)->Arg(1000000);
BENCHMARK(remove<PQC_CIPHER_AES>)->Arg(1000000);


BENCHMARK(init<PQC_CIPHER_AES>)->Arg(10000)->Threads(std::thread::hardware_concurrency());
BENCHMARK(remove<PQC_CIPHER_AES>)->Arg(10000)->Threads(std::thread::hardware_concurrency());

BENCHMARK(init<PQC_CIPHER_AES>)->Arg(1000000)->Threads(std::thread::hardware_concurrency());
BENCHMARK(remove<PQC_CIPHER_AES>)->Arg(1000000)->Threads(std::thread::hardware_concurrency());

BENCHMARK(single_context_operation)->Arg(1000000)->Threads(std::thread::hardware_concurrency())->MinTime(300);
BENCHMARK(multi_context_operation<20>)->Arg(1000000)->Threads(std::thread::hardware_concurrency())->MinTime(300);

BENCHMARK_MAIN();
