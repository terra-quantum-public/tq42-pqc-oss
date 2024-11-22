#include <chrono>
#include <iostream>
#include <random>

#include <pqc/aes.h>
#include <pqc/random.h>

void test_prng(CIPHER_HANDLE context)
{
    std::cout << "individual random values: " << std::endl;

    uint64_t val;
    PQC_context_random_get_bytes(context, &val, sizeof(val));

    for (int i = 0; i < 8; ++i)
    {
        std::cout << val % 0xFF << " ";
        val /= 0xFF;
    }

    std::cout << std::endl << std::endl;

    const int max_num = 19;

    int counts[max_num + 1] = {0};

    double mean = 0;

    const int count = (max_num + 1) * 10000;

    std::cout << "generating " << count << " values in range [0.." << max_num << "]" << std::endl;

    const auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < count; ++i)
    {
        uint16_t random_val;
        PQC_context_random_get_bytes(context, &random_val, sizeof(random_val));
        random_val %= (max_num + 1);

        ++counts[random_val];

        mean += random_val;
    }

    const auto end = std::chrono::high_resolution_clock::now();

    mean /= count;

    std::chrono::duration<double> diff = end - start;
    std::cout << "generation time " << diff.count() << " s" << std::endl;
    std::cout << std::endl;

    std::cout << "mean value: " << mean << std::endl;
    std::cout << "true mean: " << max_num / 2.0 << " error: " << mean - (max_num / 2.0) << std::endl;
    std::cout << std::endl;
    std::cout << "counts of individual values :" << std::endl;

    for (int c : counts)
    {
        std::cout << c << " ";
    }

    std::cout << std::endl;

    const int expected_count = count / (max_num + 1);
    std::cout << "expected count: " << expected_count << std::endl;

    std::cout << "errors of counts:" << std::endl;

    for (int c : counts)
    {
        std::cout << c - expected_count << " ";
    }

    std::cout << std::endl;
}

int main(void)
{
    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
                                   '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};
    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    CIPHER_HANDLE context = PQC_context_init_randomsource();
    if (context == PQC_BAD_CIPHER)
    {
        std::cout << "Unable to create context";
    }


    if (PQC_context_random_set_pq_17(context, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN) == PQC_OK)
    {
        test_prng(context);
    }
    else
    {
        std::cout << "random generator initialization error\n";
        PQC_context_close(context);
        return 1;
    }

    PQC_context_close(context);

    return 0;
}
