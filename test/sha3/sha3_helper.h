#pragma once

#include <string>
#include <utility>
#include <vector>
#include <cstddef>
#include <cstdint>

using std::size_t;
using std::uint8_t;

struct TestVector
{
    int len;
    std::string msg;
    std::string expected_hash;
};

std::vector<uint8_t> hex_string_to_bytes(const std::string & hex);

std::pair<int, int> verify_sha_3(const std::string & filename);

std::pair<int, int> verify_shake(const std::string & filename);
