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

std::unique_ptr<uint8_t[]>
hmac(const uint8_t * charset, size_t password_len, uint8_t * U, size_t b, size_t l, size_t U_size)
{
    auto acceptable_input = std::make_unique<uint8_t[]>(b);

    if (password_len > b)
    {
        SHA3 sha3_variables_1(PQC_SHA3_256);
        sha3_variables_1.add_data(ConstBufferView(charset, password_len));

        for (size_t i = 0; i < l; i++)
            acceptable_input[i] = sha3_variables_1.get_hash()[i];

        for (size_t i = l; i < b; i++)
            acceptable_input[i] = 0;
    }

    else if (password_len < b)
    {
        for (size_t i = 0; i < password_len; i++)
            acceptable_input[i] = charset[i];
        for (size_t i = password_len; i < b; i++)
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


    SHA3 sha3_variables_2(PQC_SHA3_256);
    sha3_variables_2.add_data(ConstBufferView(ipad_xor.get(), b));
    sha3_variables_2.add_data(ConstBufferView(U, U_size));
    auto hash_result = std::make_unique<uint8_t[]>(l);
    for (size_t i = 0; i < l; i++)
        hash_result.get()[i] = sha3_variables_2.get_hash()[i];

    auto opad_xor = std::make_unique<uint8_t[]>(b); // bitwise XOR c opad
    for (size_t i = 0; i < b; i++)
        opad_xor.get()[i] = acceptable_input[i] ^ 0x5c;

    SHA3 sha3_variables_3(PQC_SHA3_256);
    sha3_variables_3.add_data(ConstBufferView(opad_xor.get(), b));
    sha3_variables_3.add_data(ConstBufferView(hash_result.get(), l));
    auto final_output = std::make_unique<uint8_t[]>(l);
    for (size_t i = 0; i < l; i++)
        final_output[i] = sha3_variables_3.get_hash()[i];

    return final_output;
}

int * pbkdf_2(
    size_t password_len, const uint8_t * charset, size_t kLen, int * master_key, uint8_t * symbols_set,
    size_t symbols_setLength
)
{
    if (kLen > (pow(2, 32) - 1) * PQC_PBKDF2_hLen)
        std::cout << "password is too long";

    size_t len = kLen / PQC_PBKDF2_hLen;
    if (kLen % PQC_PBKDF2_hLen)
        len++;

    size_t r = kLen - (len - 1) * PQC_PBKDF2_hLen;

    size_t counter = 0;
    std::unique_ptr<uint8_t[]> T = std::make_unique<uint8_t[]>(PQC_PBKDF2_L_SHA3);

    for (size_t i = 1; i < len + 1; i++)
    {
        for (size_t k = 0; k < PQC_PBKDF2_L_SHA3; k++)
            T[k] = 0;

        size_t U_size = symbols_setLength + 4;
        std::unique_ptr<uint8_t[]> U = std::make_unique<uint8_t[]>(U_size);
        u_filler(symbols_setLength, symbols_set, i, U.get());

        for (size_t j = 0; j < PQC_PBKDF2_ITERATIONS_NUMBER; j++)
        {
            U = hmac(charset, password_len, U.get(), PQC_PBKDF2_B_SHA3, PQC_PBKDF2_L_SHA3, U_size);
            U_size = PQC_PBKDF2_L_SHA3;

            for (int n = 0; n < PQC_PBKDF2_L_SHA3; n++)
                T[n] ^= U[n];
        }

        std::unique_ptr<int[]> binary_T = std::make_unique<int[]>(PQC_PBKDF2_L_SHA3 * 8);
        for (size_t k = 0; k < PQC_PBKDF2_L_SHA3; k++)
        {
            auto converted = bin_converter(T[k]);
            for (int j = 0; j < 8; j++)
                binary_T[k * 8 + j] = converted[j];
        }

        if (i < len)
        {
            for (size_t n = counter; n < counter + PQC_PBKDF2_hLen; n++)
            {
                if (counter != 0)
                    master_key[n] = binary_T[n % counter];
                else
                    master_key[n] = binary_T[n];
            }
        }

        else
        {
            for (size_t n = counter; n < counter + r; n++)
            {
                if (counter != 0)
                    master_key[n] = binary_T[n % counter];
                else
                    master_key[n] = binary_T[n];
            }
        }

        counter += PQC_PBKDF2_hLen;
    }

    return master_key;
}
