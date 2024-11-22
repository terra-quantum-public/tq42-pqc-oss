#include <filesystem>
#include <fstream>
#include <stdio.h>
#include <vector>

#include <gtest/gtest.h>

#include <pqc/dilithium.h>
#include <pqc/random.h>
#include <pqc/sha3.h>

#define DILITHIUM_PRIVATE_KEY(x) std::vector<uint8_t> x(sizeof(pqc_dilithium_private_key))
#define DILITHIUM_PUBLIC_KEY(x) std::vector<uint8_t> x(sizeof(pqc_dilithium_public_key))
#define DILITHIUM_SIGNATURE(x) std::vector<uint8_t> x(sizeof(pqc_dilithium_signature))

TEST(DILITHIUM, KAT_4880_Round3)
{
    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mldsa";
    static const auto responses_path = base_path / "dilithium-KAT-4880.rsp";
    static const auto entropy_path = base_path / "dilithium-KAT-4880.ent";

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

        static void to_uint_8_t(std::string line, const std::string & label, uint8_t * data, size_t size)
        {
            auto values = line.substr(label.length());
            std::istringstream s(values);
            std::string ss;
            for (size_t i = 0; i < size; ++i)
            {
                s >> std::hex >> std::uppercase >> std::setw(2) >> ss;
                data[i] = static_cast<uint8_t>(std::stoi(ss, nullptr, 16));
            }
        }

        static unsigned long long to_ull(std::string line, const std::string & label)
        {
            auto values = line.substr(label.length());
            return std::stoull(values);
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


    std::ifstream responses(responses_path);
    std::string expected;

    std::getline(responses, expected);
    EXPECT_TRUE(expected == "# Dilithium5-R");

    DILITHIUM_PRIVATE_KEY(sk);
    DILITHIUM_PUBLIC_KEY(pk);
    DILITHIUM_PRIVATE_KEY(kat_sk);
    DILITHIUM_PUBLIC_KEY(kat_pk);
    DILITHIUM_SIGNATURE(sig);
    DILITHIUM_SIGNATURE(kat_sig);

    for (size_t i = 0; i < 100; ++i)
    {
        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected); // seed line skip

        std::getline(responses, expected);
        unsigned long long mlen = Hex::to_ull(expected, "mlen = ");
        EXPECT_EQ(mlen, 33 * (i + 1));

        std::vector<uint8_t> msg(mlen);
        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "msg = ", msg.data(), msg.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        std::getline(responses, expected);
        unsigned long long smlen = Hex::to_ull(expected, "smlen = ");
        EXPECT_EQ(smlen, sig.size() + 33 * (i + 1)) << "smlen equal to siglen+mlen";

        std::vector<uint8_t> sm(smlen);
        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "sm = ", kat_sig.data(), kat_sig.size()); // extract signature only

        CIPHER_HANDLE alice = PQC_context_init_asymmetric(PQC_CIPHER_DILITHIUM, nullptr, 0, nullptr, 0);
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

        PQC_context_random_set_external(alice, EntropyReader::get_entropy);

        EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "keys made";

        EXPECT_EQ(PQC_context_get_keypair(alice, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK)
            << "keys extracted";

        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";

        EXPECT_EQ(PQC_signature_create(alice, msg.data(), mlen, sig.data(), sig.size()), PQC_OK)
            << "signing should succeed";
        EXPECT_TRUE(sig == kat_sig) << "signature equal";

        CIPHER_HANDLE bob = PQC_context_init_asymmetric(PQC_CIPHER_DILITHIUM, pk.data(), pk.size(), nullptr, 0);
        EXPECT_NE(bob, PQC_BAD_CIPHER) << "context initialization should pass";

        EXPECT_EQ(PQC_signature_verify(bob, msg.data(), mlen, sig.data(), sig.size()), PQC_OK)
            << "signature should match";
    }
}
