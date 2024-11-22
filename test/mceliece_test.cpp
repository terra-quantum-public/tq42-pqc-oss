#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include <pqc/aes.h>
#include <pqc/mceliece.h>
#include <pqc/random.h>
#include <pqc/sha3.h>


#define MCELIECE_PRIVATE(x) std::vector<uint8_t> x(sizeof(pqc_mceliece_private_key))
#define MCELIECE_PUBLIC(x) std::vector<uint8_t> x(sizeof(pqc_mceliece_public_key))

TEST(MCELIECE, MCELIECE_KNOWN_ANSWERS)
{
    constexpr size_t max_answers_size = 10;
#ifndef NDEBUG
    size_t answers_size = 1;
#else
    size_t answers_size = max_answers_size;
#endif
    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mceliece";
    static const auto entropy_path = base_path / "kat_kem.ent";
    static const auto shake_entropy_path = base_path / "kat_kem.shake";
    static const auto responses_path = base_path / "kat_kem.rsp";

    static uint8_t keygen_seed[33] = {0x40};

    struct ShakeEntropyGenerator
    {
        static void get_entropy(uint8_t * buf, size_t size)
        {
            std::vector<uint8_t> entropy(size + sizeof keygen_seed - 1);

            CIPHER_HANDLE shake = PQC_context_init_hash(PQC_CIPHER_SHA3, PQC_SHAKE_256);
            PQC_hash_update(shake, keygen_seed, sizeof keygen_seed);
            PQC_hash_retrieve(shake, entropy.data(), entropy.size());

            std::copy(entropy.begin(), std::next(entropy.begin(), size), buf);

            /// Next seed (in case keygen failed):
            std::copy(std::next(entropy.begin(), size), entropy.end(), keygen_seed + 1);
        }
    };

    static bool isFromFile = true;
    struct ShakeEntropyReader
    {
        static size_t get_entropy(uint8_t * buf, size_t size)
        {
            if (isFromFile)
            {
                static std::ifstream f(shake_entropy_path, std::ios_base::in | std::ios_base::binary);
                f.exceptions(std::ios_base::badbit | std::ios_base::eofbit);
                f.read(reinterpret_cast<char *>(keygen_seed + 1), size);

                std::copy(keygen_seed + 1, keygen_seed + 1 + size, buf);
                isFromFile = false;
            }
            else
            {
                ShakeEntropyGenerator::get_entropy(buf, size);
            }

            return PQC_OK;
        }
    };

    struct EntropyReader
    {
        static size_t get_entropy(uint8_t * buf, size_t size)
        {
            static std::ifstream f(entropy_path, std::ios_base::in | std::ios_base::binary);
            f.exceptions(std::ios_base::badbit | std::ios_base::eofbit);
            f.read(reinterpret_cast<char *>(buf), size);
            return PQC_OK;
        }
    };

    struct Hex
    {
        static std::string to_string(uint8_t * data, size_t size)
        {
            std::ostringstream s;
            s << std::hex << std::uppercase;
            for (size_t i = 0; i < size; ++i)
            {
                s << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(data[i]);
            }
            return s.str();
        }
    };

    CIPHER_HANDLE ctx = PQC_context_init_randomsource();

    PQC_context_random_set_external(ctx, EntropyReader::get_entropy);

    std::array<std::array<uint8_t, 48>, max_answers_size> seeds;
    for (size_t i = 0; i < max_answers_size; ++i)
    {
        PQC_context_random_get_bytes(ctx, seeds[i].data(), seeds[i].size());
    }

    PQC_context_close(ctx);

    std::ifstream responses(responses_path);
    std::string expected;

    std::getline(responses, expected);
    EXPECT_TRUE(expected == "# kem/mceliece8192128f");

    for (size_t i = 0; i < answers_size; ++i)
    {
        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("seed = " + Hex::to_string(seeds[i].data(), seeds[i].size())));

        MCELIECE_PRIVATE(private_key);
        MCELIECE_PUBLIC(public_key);

        CIPHER_HANDLE alice = PQC_context_init_asymmetric(PQC_CIPHER_MCELIECE, nullptr, 0, nullptr, 0);

        isFromFile = true;
        PQC_context_random_set_external(alice, ShakeEntropyReader::get_entropy);
        EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "key generation should succeed";

        EXPECT_EQ(
            PQC_context_get_keypair(
                alice, public_key.data(), public_key.size(), private_key.data(), private_key.size()
            ),
            PQC_OK
        ) << "PQC_context_get_keypair should return OK";

        CIPHER_HANDLE bob =
            PQC_context_init_asymmetric(PQC_CIPHER_MCELIECE, public_key.data(), public_key.size(), nullptr, 0);

        PQC_context_random_set_external(bob, EntropyReader::get_entropy);

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("pk = " + Hex::to_string(public_key.data(), public_key.size())));

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("sk = " + Hex::to_string(private_key.data(), private_key.size())));

        std::vector<uint8_t> message(sizeof(pqc_mceliece_message));
        std::vector<uint8_t> secret(sizeof(pqc_mceliece_shared_secret));
        EXPECT_EQ(
            PQC_kem_encapsulate_secret(bob, message.data(), message.size(), secret.data(), secret.size()), PQC_OK
        );

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("ct = " + Hex::to_string(message.data(), message.size())));

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("ss = " + Hex::to_string(secret.data(), secret.size())));

        std::vector<uint8_t> decoded_secret(sizeof(pqc_mceliece_shared_secret));
        EXPECT_EQ(
            PQC_kem_decapsulate_secret(
                alice, message.data(), message.size(), decoded_secret.data(), decoded_secret.size()
            ),
            PQC_OK
        );
        EXPECT_TRUE(secret == decoded_secret);
    }
}
