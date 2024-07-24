#include <algorithm>
#include <bitset>
#include <ciso646>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <vector>

#include "pbkdf2.h"
#include "sha3.h"

std::unique_ptr<int[]> bin_converter(uint8_t a)
{
    std::unique_ptr<int[]> binary = std::make_unique<int[]>(8);
    for (int i = 0; i < 8; i++)
        binary[7 - i] = (a >> i) & 1;
    return binary;
}

void u_filler(size_t symbols_setLength, uint8_t * symbols_set, size_t num, uint8_t * U)
{
    for (size_t i = 0; i < symbols_setLength; i++)
        U[i] = symbols_set[i];

    size_t num_1 = num;
    for (int j = 0; j < 4; j++)
    {
        U[symbols_setLength + 4 - j - 1] = (uint8_t)num_1;
        num_1 >>= 8;
    }
}

std::unique_ptr<uint8_t[]> hmac(
    const uint8_t * charset, size_t hash_length, size_t password_length, uint8_t * U, size_t b, size_t l, size_t U_size
)
{
    auto acceptable_input = std::make_unique<uint8_t[]>(b);

    if (password_length > b)
    {
        SHA3 sha3_variables_1(static_cast<int>(hash_length));
        sha3_variables_1.add_data(ConstBufferView(charset, password_length));

        for (size_t i = 0; i < l; i++)
            acceptable_input[i] = sha3_variables_1.get_hash()[i];

        for (size_t i = l; i < b; i++)
            acceptable_input[i] = 0;
    }

    else if (password_length < b)
    {
        for (size_t i = 0; i < password_length; i++)
            acceptable_input[i] = charset[i];
        for (size_t i = password_length; i < b; i++)
            acceptable_input[i] = 0;
    }

    else
    {
        for (size_t i = 0; i < b; i++)
            acceptable_input[i] = charset[i];
    }


    auto ipad_xor = std::make_unique<uint8_t[]>(b); // beat XOR from ipad
    for (size_t i = 0; i < b; i++)
        ipad_xor[i] = acceptable_input[i] ^ 0x36;


    SHA3 sha3_variables_2(static_cast<int>(hash_length));
    sha3_variables_2.add_data(ConstBufferView(ipad_xor.get(), b));
    sha3_variables_2.add_data(ConstBufferView(U, U_size));
    auto hash_result = std::make_unique<uint8_t[]>(l);
    for (size_t i = 0; i < l; i++)
        hash_result.get()[i] = sha3_variables_2.get_hash()[i];

    auto opad_xor = std::make_unique<uint8_t[]>(b); // bitwise XOR c opad
    for (size_t i = 0; i < b; i++)
        opad_xor.get()[i] = acceptable_input[i] ^ 0x5c;

    SHA3 sha3_variables_3(static_cast<int>(hash_length));
    sha3_variables_3.add_data(ConstBufferView(opad_xor.get(), b));
    sha3_variables_3.add_data(ConstBufferView(hash_result.get(), l));
    auto final_output = std::make_unique<uint8_t[]>(l);
    for (size_t i = 0; i < l; i++)
        final_output[i] = sha3_variables_3.get_hash()[i];

    return final_output;
}

size_t pbkdf_2(
    int mode, size_t hash_length, size_t password_length, const uint8_t * password, size_t key_length,
    uint8_t * derived_key, size_t derived_key_length, uint8_t * salt, size_t salt_length, size_t iterations
)
{
    if (key_length > (pow(2, 32) - 1) * hash_length)
    {
        std::cout << "Password or key length is too long." << std::endl;
        return PQC_BAD_LEN;
    }

    if (derived_key_length < key_length / 8)
    {
        std::cout << "Derived key buffer is too short." << std::endl;
        return PQC_BAD_LEN;
    }

    size_t num_blocks = (key_length + hash_length - 1) / hash_length;
    std::unique_ptr<uint8_t[]> T = std::make_unique<uint8_t[]>(hash_length / 8);

    for (size_t i = 0; i < num_blocks; ++i)
    {
        memset(T.get(), 0, hash_length / 8);
        size_t U_size = salt_length + 4;
        std::unique_ptr<uint8_t[]> U = std::make_unique<uint8_t[]>(U_size);
        u_filler(salt_length, salt, i + 1, U.get());

        for (size_t j = 0; j < iterations; ++j)
        {
            U = hmac(
                password, hash_length, password_length, U.get(), (1600 - 2 * hash_length) >> 3, hash_length / 8, U_size
            );
            U_size = hash_length / 8;
            for (size_t n = 0; n < hash_length / 8; ++n)
            {
                T[n] ^= U[n];
            }
        }

        size_t copy_length = std::min(hash_length / 8, derived_key_length - i * hash_length / 8);
        memcpy(derived_key + i * hash_length / 8, T.get(), copy_length);
    }

    return PQC_OK;
}
