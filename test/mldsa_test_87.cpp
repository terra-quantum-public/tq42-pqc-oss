#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include <pqc/ml-dsa.h>
#include <pqc/random.h>
#include <pqc/sha3.h>

#define ML_DSA_PRIVATE_KEY(x) std::vector<uint8_t> x(sizeof(pqc_ml_dsa_private_key_87))
#define ML_DSA_PUBLIC_KEY(x) std::vector<uint8_t> x(sizeof(pqc_ml_dsa_public_key_87))
#define ML_DSA_SIGNATURE(x) std::vector<uint8_t> x(sizeof(pqc_ml_dsa_signature_87))


TEST(ML_DSA_87, ACVP_KAT_FROM_JSON)
{
    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mldsa";
    static const auto keygen_responses_path = base_path / "ml-dsa-87-keygen.rsp";
    static const auto siggen_responses_path = base_path / "ml-dsa-87-siggen-hedged.rsp";
    static const auto sigver_responses_path = base_path / "ml-dsa-87-sigver.rsp";

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

    static std::vector<uint8_t> entropy(64);
    static size_t offset = 0;
    struct EntropyEmulator
    {
        static size_t get_entropy(uint8_t * buf, size_t size)
        {
            std::copy_n(entropy.begin() + offset, size, buf);
            offset += size;
            return PQC_OK;
        }
    };

    ML_DSA_PRIVATE_KEY(sk);
    ML_DSA_PUBLIC_KEY(pk);
    ML_DSA_PRIVATE_KEY(kat_sk);
    ML_DSA_PUBLIC_KEY(kat_pk);
    ML_DSA_SIGNATURE(sig);
    ML_DSA_SIGNATURE(kat_sig);

    std::string expected;

    std::ifstream keygen_responses(keygen_responses_path);

    std::getline(keygen_responses, expected);
    EXPECT_TRUE(expected == "# ML-DSA-87-FROM-JSON");

    for (size_t i = 0; i < 25; ++i)
    {
        offset = 0;

        std::getline(keygen_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(keygen_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "seed = ", entropy.data(), 32);

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        CIPHER_HANDLE alice =
            PQC_context_init_asymmetric(PQC_CIPHER_ML_DSA_87, nullptr, 0, kat_sk.data(), kat_sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        PQC_context_random_set_external(alice, EntropyEmulator::get_entropy);

        EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "keys made";

        EXPECT_EQ(PQC_context_get_keypair(alice, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK) << "keys get";
        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";

        PQC_context_close(alice);
    }

    std::ifstream siggen_responses(siggen_responses_path);

    std::getline(siggen_responses, expected);
    EXPECT_TRUE(expected == "# ML-DSA-87-FROM-JSON");

    for (size_t i = 0; i < 10; ++i)
    {
        offset = 0;

        std::getline(siggen_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(siggen_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(siggen_responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        std::getline(siggen_responses, expected);
        std::vector<uint8_t> msg((expected.substr(std::string("message = ").length()).length()) / 2);
        Hex::to_uint_8_t(expected, "message = ", msg.data(), msg.size());

        std::getline(siggen_responses, expected);
        Hex::to_uint_8_t(expected, "rnd = ", entropy.data(), 32);

        std::getline(siggen_responses, expected);
        Hex::to_uint_8_t(expected, "signature = ", kat_sig.data(), kat_sig.size());

        CIPHER_HANDLE alice =
            PQC_context_init_asymmetric(PQC_CIPHER_ML_DSA_87, nullptr, 0, kat_sk.data(), kat_sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        PQC_context_random_set_external(alice, EntropyEmulator::get_entropy);

        EXPECT_EQ(PQC_signature_create(alice, msg.data(), msg.size(), sig.data(), sig.size()), PQC_OK)
            << "signing should succeed";

        EXPECT_TRUE(sig == kat_sig) << "signature equal";

        PQC_context_close(alice);
    }

    std::ifstream sigver_responses(sigver_responses_path);

    std::getline(sigver_responses, expected);
    EXPECT_TRUE(expected == "# ML-DSA-87-FROM-JSON");

    std::getline(sigver_responses, expected);
    EXPECT_TRUE(expected == "");

    std::getline(sigver_responses, expected);
    Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

    std::getline(sigver_responses, expected);
    Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

    for (size_t i = 0; i < 15; ++i)
    {
        std::getline(sigver_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(sigver_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(sigver_responses, expected);
        unsigned long long passed = Hex::to_ull(expected, "testPassed = ");

        std::getline(sigver_responses, expected);
        std::vector<uint8_t> msg((expected.substr(std::string("message = ").length()).length()) / 2);
        Hex::to_uint_8_t(expected, "message = ", msg.data(), msg.size());

        std::getline(sigver_responses, expected);
        Hex::to_uint_8_t(expected, "signature = ", kat_sig.data(), kat_sig.size());

        CIPHER_HANDLE context =
            PQC_context_init_asymmetric(PQC_CIPHER_ML_DSA_87, kat_pk.data(), kat_pk.size(), nullptr, 0);
        EXPECT_NE(context, PQC_BAD_CIPHER);

        if (passed)
        {
            EXPECT_EQ(PQC_signature_verify(context, msg.data(), msg.size(), kat_sig.data(), kat_sig.size()), PQC_OK)
                << "signature should match";
        }
        else
        {
            EXPECT_NE(PQC_signature_verify(context, msg.data(), msg.size(), kat_sig.data(), kat_sig.size()), PQC_OK)
                << "signature shouldn't match";
        }
        PQC_context_close(context);
    }
}

TEST(ML_DSA_87, ACVP_KAT_FROM_JSON_ATSEC)
{
    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mldsa";
    static const auto keygen_responses_path = base_path / "ml-dsa-87-keygen-2.rsp";
    static const auto siggen_responses_path = base_path / "ml-dsa87-siggen-hedged-2.rsp";
    static const auto sigver_responses_path = base_path / "ml-dsa87-sigver-2.rsp";

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

    static std::vector<uint8_t> entropy(64);
    static size_t offset = 0;
    struct EntropyEmulator
    {
        static size_t get_entropy(uint8_t * buf, size_t size)
        {
            std::copy_n(entropy.begin() + offset, size, buf);
            offset += size;
            return PQC_OK;
        }
    };

    ML_DSA_PRIVATE_KEY(sk);
    ML_DSA_PUBLIC_KEY(pk);
    ML_DSA_PRIVATE_KEY(kat_sk);
    ML_DSA_PUBLIC_KEY(kat_pk);
    ML_DSA_SIGNATURE(sig);
    ML_DSA_SIGNATURE(kat_sig);

    std::string expected;

    std::ifstream keygen_responses(keygen_responses_path);

    std::getline(keygen_responses, expected);
    EXPECT_TRUE(expected == "# ML-DSA-87-FROM-ATSEC");

    for (size_t i = 0; i < 25; ++i)
    {
        offset = 0;

        std::getline(keygen_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(keygen_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "seed = ", entropy.data(), 32);

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        CIPHER_HANDLE alice =
            PQC_context_init_asymmetric(PQC_CIPHER_ML_DSA_87, nullptr, 0, kat_sk.data(), kat_sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        PQC_context_random_set_external(alice, EntropyEmulator::get_entropy);

        EXPECT_EQ(PQC_context_keypair_generate(alice), PQC_OK) << "keys made";

        EXPECT_EQ(PQC_context_get_keypair(alice, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK) << "keys get";
        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";

        PQC_context_close(alice);
    }

    std::ifstream siggen_responses(siggen_responses_path);

    std::getline(siggen_responses, expected);
    EXPECT_TRUE(expected == "# ML-DSA-87-FROM-ATSEC");

    for (size_t i = 0; i < 10; ++i)
    {
        offset = 0;

        std::getline(siggen_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(siggen_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(siggen_responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        std::getline(siggen_responses, expected);
        std::vector<uint8_t> msg((expected.substr(std::string("message = ").length()).length()) / 2);
        Hex::to_uint_8_t(expected, "message = ", msg.data(), msg.size());

        std::getline(siggen_responses, expected);
        Hex::to_uint_8_t(expected, "rnd = ", entropy.data(), 32);

        std::getline(siggen_responses, expected);
        Hex::to_uint_8_t(expected, "signature = ", kat_sig.data(), kat_sig.size());

        CIPHER_HANDLE alice =
            PQC_context_init_asymmetric(PQC_CIPHER_ML_DSA_87, nullptr, 0, kat_sk.data(), kat_sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        PQC_context_random_set_external(alice, EntropyEmulator::get_entropy);

        EXPECT_EQ(PQC_signature_create(alice, msg.data(), msg.size(), sig.data(), sig.size()), PQC_OK)
            << "signing should succeed";

        EXPECT_TRUE(sig == kat_sig) << "signature equal";

        PQC_context_close(alice);
    }

    std::ifstream sigver_responses(sigver_responses_path);

    std::getline(sigver_responses, expected);
    EXPECT_TRUE(expected == "# ML-DSA-87-FROM-ATSEC");

    std::getline(sigver_responses, expected);
    EXPECT_TRUE(expected == "");

    std::getline(sigver_responses, expected);
    Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

    for (size_t i = 0; i < 15; ++i)
    {
        std::getline(sigver_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(sigver_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(sigver_responses, expected);
        unsigned long long passed = Hex::to_ull(expected, "testPassed = ");

        std::getline(sigver_responses, expected);
        std::vector<uint8_t> msg((expected.substr(std::string("message = ").length()).length()) / 2);
        Hex::to_uint_8_t(expected, "message = ", msg.data(), msg.size());

        std::getline(sigver_responses, expected);
        Hex::to_uint_8_t(expected, "signature = ", kat_sig.data(), kat_sig.size());
        CIPHER_HANDLE context =
            PQC_context_init_asymmetric(PQC_CIPHER_ML_DSA_87, kat_pk.data(), kat_pk.size(), nullptr, 0);
        EXPECT_NE(context, PQC_BAD_CIPHER);

        if (passed)
        {
            EXPECT_EQ(PQC_signature_verify(context, msg.data(), msg.size(), kat_sig.data(), kat_sig.size()), PQC_OK)
                << "signature should match";
        }
        else
        {
            EXPECT_NE(PQC_signature_verify(context, msg.data(), msg.size(), kat_sig.data(), kat_sig.size()), PQC_OK)
                << "signature shouldn't match";
        }
        PQC_context_close(context);
    }
}
