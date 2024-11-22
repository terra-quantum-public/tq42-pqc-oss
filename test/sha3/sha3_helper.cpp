#include "sha3_helper.h"

#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include <pqc/sha3.h>


std::vector<uint8_t> hex_string_to_bytes(const std::string & hex)
{
    if (hex.empty())
        return {};
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        std::string byteStr = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::pair<int, int> verify_sha_3(const std::string & filename)
{
    std::ifstream file(filename);
    std::vector<TestVector> vectors;
    std::string line;
    int L = 0, verifiedCount = 0, totalCount = 0;

    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file");
    }

    while (getline(file, line) && line.find("[L =") == std::string::npos)
        ;

    if (!line.empty())
    {
        std::istringstream iss(line);
        iss.ignore(std::numeric_limits<std::streamsize>::max(), '=');
        if (!(iss >> L))
        {
            throw std::runtime_error("Failed to parse the length L from the file.");
        }
    }

    while (getline(file, line))
    {
        std::istringstream iss(line);
        std::string key, equals;
        TestVector vector;

        if (line.find("Len =") != std::string::npos)
        {
            iss >> key >> equals >> vector.len;
            getline(file, line);
            iss.str(line);
            iss.clear();
            iss >> key >> equals >> vector.msg;
            if (vector.len == 0)
            {
                vector.msg = "";
            }
            getline(file, line);
            iss.str(line);
            iss.clear();
            iss >> key >> equals >> vector.expected_hash;

            vectors.push_back(vector);
            totalCount++;
        }
    }

    file.close();

    for (auto & test : vectors)
    {
        std::vector<uint8_t> message = hex_string_to_bytes(test.msg);
        std::vector<uint8_t> expected = hex_string_to_bytes(test.expected_hash);

        CIPHER_HANDLE sha3 = PQC_context_init_hash(PQC_CIPHER_SHA3, L);
        PQC_hash_update(sha3, message.data(), message.size());
        std::vector<uint8_t> hash(PQC_hash_size(sha3));
        PQC_hash_retrieve(sha3, hash.data(), hash.size());

        if (hash == expected)
        {
            verifiedCount++;
        }

        PQC_context_close(sha3);
    }

    return {verifiedCount, totalCount};
}


std::pair<int, int> verify_shake(const std::string & filename)
{
    std::ifstream file(filename);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file.");
    }

    std::vector<TestVector> vectors;
    std::string line;
    int output_len = 0;

    while (std::getline(file, line) && line.find("[Outputlen =") == std::string::npos)
        ;

    if (!line.empty())
    {
        std::istringstream iss(line);
        iss.ignore(std::numeric_limits<std::streamsize>::max(), '=');
        if (!(iss >> output_len))
        {
            throw std::runtime_error("Failed to parse Outputlen.");
        }
    }

    int verified_count = 0, total_count = 0;

    while (std::getline(file, line))
    {
        if (line.find("Len =") != std::string::npos)
        {
            TestVector vector;
            std::istringstream iss(line);
            std::string key, equals;

            iss >> key >> equals >> vector.len;

            std::getline(file, line);
            iss.str(line);
            iss.clear();
            iss >> key >> equals >> vector.msg;

            if (vector.len == 0)
            {
                vector.msg = "";
            }

            std::getline(file, line);
            iss.str(line);
            iss.clear();
            iss >> key >> equals >> vector.expected_hash;

            if (vector.expected_hash.size() % 2 != 0)
            {
                throw std::runtime_error("Expected hash has incorrect size.");
            }

            vectors.push_back(vector);
            total_count++;
        }
    }

    file.close();

    int hash_size = output_len / 8;
    int hash_mode = (output_len == 128) ? PQC_SHAKE_128 : PQC_SHAKE_256;

    for (const auto & test : vectors)
    {
        std::vector<uint8_t> message = hex_string_to_bytes(test.msg);
        std::vector<uint8_t> expected = hex_string_to_bytes(test.expected_hash);

        CIPHER_HANDLE sha3 = PQC_context_init_hash(PQC_CIPHER_SHA3, hash_mode);

        PQC_hash_update(sha3, message.data(), message.size());

        std::vector<uint8_t> computed_hash(hash_size);
        PQC_hash_retrieve(sha3, computed_hash.data(), hash_size);

        if (computed_hash == expected)
        {
            verified_count++;
        }

        PQC_context_close(sha3);
    }

    return {verified_count, total_count};
}
