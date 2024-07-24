#include "pqc/kdf.h"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>


/*
In this example, we will derive a key using the PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA3.
We will convert the password and salt into a derived key and print it in hexadecimal format.
*/


/*
Converts a hexadecimal string to a vector of bytes.
This function is used to convert the hexadecimal representation of the salt
into a byte array that can be used with the PBKDF2 function.
 */
std::vector<uint8_t> hex_to_bytes(const std::string & hex)
{
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        std::istringstream iss(hex.substr(i, 2));
        int val;
        iss >> std::hex >> val;
        bytes.push_back(static_cast<uint8_t>(val));
    }
    return bytes;
}

int main()
{
    // Define the password in plain text
    const uint8_t password[] = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
    // Calculate the length of the password
    const size_t password_length = sizeof(password) / sizeof(password[0]);
    // Define the length of the master key to be derived
    const size_t master_key_length = 32 * 8; // 32 bytes * 8 bits per byte
    // Prepare a buffer to store the derived key
    uint8_t master_key[master_key_length / 8] = {0}; // Actual byte array

    std::string salt_hex = "a5dcea8d0bba2f1fcfa5824085bf06e65fa1255484dafd499984323672b71fee";
    std::vector<uint8_t> salt = hex_to_bytes(salt_hex);
    const size_t salt_length = salt.size();
    // Set the hash length and number of iterations for PBKDF2
    size_t hash_length = 256;
    size_t iterations = 10000;
    // Call the PBKDF2 function to derive the key
    size_t result = PQC_pbkdf_2(
        PQC_PBKDF2_HMAC_SHA3, hash_length, password_length, password, master_key_length, master_key, sizeof(master_key),
        salt.data(), salt_length, iterations
    );
    // Check if the key derivation was successful
    if (result == PQC_OK)
    {
        std::cout << "Derived key in hex: ";
        for (size_t i = 0; i < sizeof(master_key); i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(master_key[i]);
        }
        std::cout << std::endl;
    }
    else
    {
        std::cout << "Error occurred during key derivation: " << result << std::endl;
    }

    return 0;
}
