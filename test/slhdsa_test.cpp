#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

#include <gtest/gtest.h>

#include <pqc/random.h>
#include <pqc/sha3.h>
#include <pqc/slh-dsa.h>

#define SLH_DSA_PRIVATE_KEY(x) std::vector<uint8_t> x(sizeof(pqc_slh_dsa_private_key))
#define SLH_DSA_PUBLIC_KEY(x) std::vector<uint8_t> x(sizeof(pqc_slh_dsa_public_key))
#define SLH_DSA_SIGNATURE(x) std::vector<uint8_t> x(sizeof(pqc_slh_dsa_signature))

TEST(SLH_DSA, CREATE_SECRET_CHECK_SIZES)
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "should check both key sizes";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size() - 1, priv_alice.data(), priv_alice.size()
        ),
        PQC_BAD_LEN
    ) << "should check public key size";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size() - 1
        ),
        PQC_BAD_LEN
    ) << "should check private key size";
}

TEST(SLH_DSA, INIT_CHECK_SIZE)
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size() - 1);
    EXPECT_EQ(alice, PQC_BAD_CIPHER) << "context initialization should fail due to wrong key size";
}


TEST(SLH_DSA, SIGN_CHECK_SIGNATURE_SIZE)
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);
    SLH_DSA_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog.";

    EXPECT_EQ(
        PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size() - 1), PQC_BAD_LEN
    ) << "signing should fail due to bad signature size";
}


TEST(SLH_DSA, VERIFY_CHECK_SIGNATURE_SIZE)
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);
    SLH_DSA_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            signature.data(), signature.size() - 1
        ),
        PQC_BAD_LEN
    ) << "should fail due to bad signature size";
}


TEST(SLH_DSA, VERIFY_CHECK_KEY_SIZE)
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);
    SLH_DSA_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";


    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size() - 1, (uint8_t *)message,
            strlen(message) + 1, signature.data(), signature.size()
        ),
        PQC_BAD_LEN
    ) << "should fail due to bad public key size";
}


TEST(SLH_DSA, CHECK_SIGNATURE)
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);
    SLH_DSA_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            signature.data(), signature.size()
        ),
        PQC_OK
    ) << "signature should match";
}


TEST(SLH_DSA, BAD_SIGNATURE)
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);
    SLH_DSA_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";


    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            signature.data(), signature.size()
        ),
        PQC_OK
    ) << "signature should match";

    for (size_t byte = 0; byte < signature.size(); byte += 1024)
    {
        signature[byte] = ~signature[byte];

        EXPECT_EQ(
            PQC_verify(
                PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), (uint8_t *)message,
                strlen(message) + 1, signature.data(), signature.size()
            ),
            PQC_BAD_SIGNATURE
        ) << "changed signature should NOT match";

        signature[byte] = ~signature[byte];
    }
}


TEST(SLH_DSA, BAD_MESSAGE)
{
    SLH_DSA_PRIVATE_KEY(priv_alice);
    SLH_DSA_PUBLIC_KEY(pub_alice);
    SLH_DSA_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    size_t message_len = strlen(message) + 1;

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, message_len, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), (uint8_t *)message, message_len,
            signature.data(), signature.size()
        ),
        PQC_OK
    ) << "signature should match";

    for (size_t byte = 0; byte < message_len; ++byte)
    {
        message[byte] = ~message[byte];

        EXPECT_EQ(
            PQC_verify(
                PQC_CIPHER_SLH_DSA_SHAKE_256F, pub_alice.data(), pub_alice.size(), (uint8_t *)message, message_len,
                signature.data(), signature.size()
            ),
            PQC_BAD_SIGNATURE
        ) << "changed message should NOT match";

        message[byte] = ~message[byte];
    }
}

TEST(SLH_DSA, ACVP_KAT_FROM_JSON)
{
    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "slhdsa";
    static const auto keygen_responses_path = base_path / "slh-dsa-shake-256f-keygen.rsp";
    static const auto siggen_responses_path = base_path / "slh-dsa-shake-256f-siggen-nondeterministic.rsp";
    static const auto sigver_responses_path = base_path / "slh-dsa-shake-256f-sigver.rsp";

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

    static std::vector<uint8_t> entropy(96);
    static size_t offset = 0;
    struct EntropyEmulator
    {
        static void get_entropy(uint8_t * buf, size_t size)
        {
            std::copy_n(entropy.begin() + offset, size, buf);
            offset += size;
        }
    };
    PQC_random_from_external(EntropyEmulator::get_entropy);

    SLH_DSA_PRIVATE_KEY(sk);
    SLH_DSA_PUBLIC_KEY(pk);
    SLH_DSA_PRIVATE_KEY(kat_sk);
    SLH_DSA_PUBLIC_KEY(kat_pk);
    SLH_DSA_SIGNATURE(sig);
    SLH_DSA_SIGNATURE(kat_sig);

    std::string expected;

    std::ifstream keygen_responses(keygen_responses_path);

    std::getline(keygen_responses, expected);
    EXPECT_TRUE(expected == "# SLH-DSA-SHAKE-256f-FROM-JSON");

    for (size_t i = 0; i < 10; ++i)
    {
        offset = 0;

        std::getline(keygen_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(keygen_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "skSeed = ", entropy.data(), 32);

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "skPrf = ", entropy.data() + 32, 32);

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "pkSeed = ", entropy.data() + 64, 32);

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        EXPECT_EQ(
            PQC_generate_key_pair(PQC_CIPHER_SLH_DSA_SHAKE_256F, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK
        ) << "keys made";
        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";
    }

    std::ifstream siggen_responses(siggen_responses_path);

    std::getline(siggen_responses, expected);
    EXPECT_TRUE(expected == "# SLH-DSA-SHAKE-256f-FROM-JSON");

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
        Hex::to_uint_8_t(expected, "seed = ", entropy.data(), 32);

        std::getline(siggen_responses, expected);
        unsigned long long smlen = Hex::to_ull(expected, "msglen = ");

        std::getline(siggen_responses, expected);
        std::vector<uint8_t> msg(smlen / 8);
        Hex::to_uint_8_t(expected, "msg = ", msg.data(), msg.size());

        std::getline(siggen_responses, expected);
        Hex::to_uint_8_t(expected, "signature = ", kat_sig.data(), kat_sig.size());

        CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, kat_sk.data(), kat_sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        EXPECT_EQ(PQC_sign(alice, msg.data(), msg.size(), sig.data(), sig.size()), PQC_OK) << "signing should succeed";
        EXPECT_TRUE(sig == kat_sig) << "signature equal";
    }

    std::ifstream sigver_responses(sigver_responses_path);

    std::getline(sigver_responses, expected);
    EXPECT_TRUE(expected == "# SLH-DSA-SHAKE-256f-FROM-JSON");

    CIPHER_HANDLE context = PQC_init_context(PQC_CIPHER_SLH_DSA_SHAKE_256F, kat_sk.data(), kat_sk.size());
    EXPECT_NE(context, PQC_BAD_CIPHER);

    for (size_t i = 0; i < 7; ++i)
    {
        std::getline(sigver_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(sigver_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(sigver_responses, expected);
        unsigned long long passed = Hex::to_ull(expected, "testPassed = ");

        std::getline(sigver_responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        std::getline(sigver_responses, expected);
        unsigned long long mlen = Hex::to_ull(expected, "msglen = ");

        std::getline(sigver_responses, expected);
        std::vector<uint8_t> msg(mlen / 8);
        Hex::to_uint_8_t(expected, "message = ", msg.data(), msg.size());

        std::getline(sigver_responses, expected);
        Hex::to_uint_8_t(expected, "signature = ", kat_sig.data(), kat_sig.size());

        if (passed)
        {
            EXPECT_EQ(
                PQC_verify(
                    PQC_CIPHER_SLH_DSA_SHAKE_256F, kat_pk.data(), kat_pk.size(), msg.data(), msg.size(), kat_sig.data(),
                    kat_sig.size()
                ),
                PQC_OK
            ) << "signature should match";
        }
        else
        {
            EXPECT_NE(
                PQC_verify(
                    PQC_CIPHER_SLH_DSA_SHAKE_256F, kat_pk.data(), kat_pk.size(), msg.data(), msg.size(), kat_sig.data(),
                    kat_sig.size()
                ),
                PQC_OK
            ) << "signature shouldn't match";
        }
    }
}