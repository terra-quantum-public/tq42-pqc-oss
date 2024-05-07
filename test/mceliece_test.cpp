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

TEST(MCELIECE, MCELIECE_CREATE_SECRET_CHECK_SIZES)
{
    MCELIECE_PRIVATE(priv_alice);
    MCELIECE_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_MCELIECE, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size() - 1
        ),
        PQC_BAD_LEN
    ) << "should check private key size";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_MCELIECE, pub_alice.data(), pub_alice.size() - 1, priv_alice.data(), priv_alice.size()
        ),
        PQC_BAD_LEN
    ) << "should check public key size";
}

TEST(MCELIECE, INIT_CHECK_KEYLEN)
{
    MCELIECE_PRIVATE(priv_alice);

    EXPECT_EQ(PQC_init_context(PQC_CIPHER_MCELIECE, priv_alice.data(), priv_alice.size() - 1), PQC_BAD_CIPHER)
        << "Initialization should fail due to bad key length";
}

TEST(MCELIECE, MCELIECE_CREATE_SECRET)
{
    MCELIECE_PRIVATE(priv_bob);
    MCELIECE_PUBLIC(pub_bob);
    std::vector<uint8_t> shared_alice(sizeof(pqc_mceliece_shared_secret)), shared_bob(sizeof(pqc_mceliece_shared_secret));

    std::vector<uint8_t> message(sizeof(pqc_mceliece_message));

    EXPECT_EQ(
        PQC_generate_key_pair(PQC_CIPHER_MCELIECE, pub_bob.data(), pub_bob.size(), priv_bob.data(), priv_bob.size()),
        PQC_OK
    );
    CIPHER_HANDLE bob = PQC_init_context(PQC_CIPHER_MCELIECE, priv_bob.data(), priv_bob.size());
    EXPECT_NE(bob, PQC_BAD_CIPHER);

    EXPECT_EQ(
        PQC_kem_encode_secret(
            PQC_CIPHER_MCELIECE, message.data(), message.size(), pub_bob.data(), pub_bob.size(), shared_alice.data(),
            shared_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(PQC_kem_decode_secret(bob, message.data(), message.size(), shared_bob.data(), shared_alice.size()), PQC_OK);

    EXPECT_EQ(memcmp(shared_alice.data(), shared_bob.data(), sizeof(pqc_mceliece_shared_secret)), 0);
}

TEST(MCELIECE, MCELIECE_DERIVE)
{
    MCELIECE_PRIVATE(priv_bob);
    MCELIECE_PUBLIC(pub_bob);
    uint8_t shared_alice[PQC_AES_KEYLEN], shared_bob[PQC_AES_KEYLEN];

    pqc_mceliece_message message;

    const size_t info_size = 10;
    uint8_t party_a_info[info_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    EXPECT_EQ(
        PQC_generate_key_pair(PQC_CIPHER_MCELIECE, pub_bob.data(), pub_bob.size(), priv_bob.data(), priv_bob.size()),
        PQC_OK
    );
    CIPHER_HANDLE bob = PQC_init_context(PQC_CIPHER_MCELIECE, priv_bob.data(), priv_bob.size());
    EXPECT_NE(bob, PQC_BAD_CIPHER);

    EXPECT_EQ(
        PQC_kem_encode(
            PQC_CIPHER_MCELIECE, (uint8_t *)&message, sizeof(message), party_a_info, info_size, pub_bob.data(),
            pub_bob.size(), (uint8_t *)&shared_alice, sizeof(shared_alice)
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_kem_decode(
            bob, (uint8_t *)&message, sizeof(message), party_a_info, info_size, (uint8_t *)&shared_bob,
            sizeof(shared_alice)
        ),
        PQC_OK
    );

    EXPECT_EQ(memcmp(&shared_alice, &shared_bob, PQC_AES_KEYLEN), 0);
}

TEST(MCELIECE, MCELIECE_KNOWN_ANSWERS)
{
    constexpr size_t max_answers_size = 10;
#ifndef NDEBUG
    size_t answers_size = 2;
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

            CIPHER_HANDLE shake = PQC_init_context_hash(PQC_CIPHER_SHA3, PQC_SHAKE_256);
            PQC_add_data(shake, keygen_seed, sizeof keygen_seed);
            PQC_get_hash(shake, entropy.data(), entropy.size());

            std::copy(entropy.begin(), std::next(entropy.begin(), size), buf);

            /// Next seed (in case keygen failed):
            std::copy(std::next(entropy.begin(), size), entropy.end(), keygen_seed + 1);
        }
    };

    struct ShakeEntropyReader
    {
        static void get_entropy(uint8_t * buf, size_t size)
        {
            static std::ifstream f(shake_entropy_path, std::ios_base::in | std::ios_base::binary);
            f.exceptions(std::ios_base::badbit | std::ios_base::eofbit);
            f.read(reinterpret_cast<char *>(keygen_seed + 1), size);

            std::copy(keygen_seed + 1, keygen_seed + 1 + size, buf);
            PQC_random_from_external(ShakeEntropyGenerator::get_entropy);
        }
    };

    struct EntropyReader
    {
        static void get_entropy(uint8_t * buf, size_t size)
        {
            static std::ifstream f(entropy_path, std::ios_base::in | std::ios_base::binary);
            f.exceptions(std::ios_base::badbit | std::ios_base::eofbit);
            f.read(reinterpret_cast<char *>(buf), size);
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

    PQC_random_from_external(EntropyReader::get_entropy);

    std::array<std::array<uint8_t, 48>, max_answers_size> seeds;
    for (size_t i = 0; i < max_answers_size; ++i)
    {
        PQC_random_bytes(seeds[i].data(), seeds[i].size());
    }

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

        PQC_random_from_external(ShakeEntropyReader::get_entropy);
        EXPECT_EQ(
            PQC_generate_key_pair(
                PQC_CIPHER_MCELIECE, public_key.data(), public_key.size(), private_key.data(), private_key.size()
            ),
            PQC_OK
        );
        PQC_random_from_external(EntropyReader::get_entropy);

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("pk = " + Hex::to_string(public_key.data(), public_key.size())));

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("sk = " + Hex::to_string(private_key.data(), private_key.size())));

        std::vector<uint8_t> message(sizeof(pqc_mceliece_message));
        std::vector<uint8_t> secret(sizeof(pqc_mceliece_shared_secret));
        EXPECT_EQ(
            PQC_kem_encode_secret(
                PQC_CIPHER_MCELIECE, message.data(), message.size(), public_key.data(), public_key.size(), secret.data(),
                secret.size()
            ),
            PQC_OK
        );

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("ct = " + Hex::to_string(message.data(), message.size())));

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("ss = " + Hex::to_string(secret.data(), secret.size())));

        CIPHER_HANDLE context = PQC_init_context(PQC_CIPHER_MCELIECE, private_key.data(), private_key.size());
        EXPECT_NE(context, PQC_BAD_CIPHER);

        std::vector<uint8_t> decoded_secret(sizeof(pqc_mceliece_shared_secret));
        EXPECT_EQ(
            PQC_kem_decode_secret(context, message.data(), message.size(), decoded_secret.data(), decoded_secret.size()),
            PQC_OK
        );
        EXPECT_TRUE(secret == decoded_secret);
    }
}
