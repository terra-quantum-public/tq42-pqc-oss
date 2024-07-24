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

TEST(DILITHIUM, CREATE_SECRET_CHECK_SIZES)
{
    DILITHIUM_PRIVATE_KEY(priv_alice);
    DILITHIUM_PUBLIC_KEY(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "should check both key sizes";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size() - 1, priv_alice.data(), priv_alice.size()
        ),
        PQC_BAD_LEN
    ) << "should check public key size";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size() - 1
        ),
        PQC_BAD_LEN
    ) << "should check private key size";
}

TEST(DILITHIUM, INIT_CHECK_SIZE)
{
    DILITHIUM_PRIVATE_KEY(priv_alice);
    DILITHIUM_PUBLIC_KEY(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_DILITHIUM, priv_alice.data(), priv_alice.size() - 1);
    EXPECT_EQ(alice, PQC_BAD_CIPHER) << "context initialization should fail due to wrong key size";
}


TEST(DILITHIUM, SIGN_CHECK_SIGNATURE_SIZE)
{
    DILITHIUM_PRIVATE_KEY(priv_alice);
    DILITHIUM_PUBLIC_KEY(pub_alice);
    DILITHIUM_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_DILITHIUM, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog.";

    EXPECT_EQ(
        PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size() - 1), PQC_BAD_LEN
    ) << "signing should fail due to bad signature size";
}


TEST(DILITHIUM, VERIFY_CHECK_SIGNATURE_SIZE)
{
    DILITHIUM_PRIVATE_KEY(priv_alice);
    DILITHIUM_PUBLIC_KEY(pub_alice);
    DILITHIUM_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_DILITHIUM, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            signature.data(), signature.size() - 1
        ),
        PQC_BAD_LEN
    ) << "should fail due to bad signature size";
}


TEST(DILITHIUM, VERIFY_CHECK_KEY_SIZE)
{
    DILITHIUM_PRIVATE_KEY(priv_alice);
    DILITHIUM_PUBLIC_KEY(pub_alice);
    DILITHIUM_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_DILITHIUM, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";


    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_DILITHIUM, priv_alice.data(), priv_alice.size() - 1, (uint8_t *)message, strlen(message) + 1,
            signature.data(), signature.size()
        ),
        PQC_BAD_LEN
    ) << "should fail due to bad public key size";
}


TEST(DILITHIUM, CHECK_SIGNATURE)
{
    DILITHIUM_PRIVATE_KEY(priv_alice);
    DILITHIUM_PUBLIC_KEY(pub_alice);
    DILITHIUM_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_DILITHIUM, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            signature.data(), signature.size()
        ),
        PQC_OK
    ) << "signature should match";
}


TEST(DILITHIUM, BAD_SIGNATURE)
{
    DILITHIUM_PRIVATE_KEY(priv_alice);
    DILITHIUM_PUBLIC_KEY(pub_alice);
    DILITHIUM_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_DILITHIUM, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";


    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, signature.data(), signature.size()), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            signature.data(), signature.size()
        ),
        PQC_OK
    ) << "signature should match";

    for (unsigned long long byte = 0; byte < signature.size(); ++byte)
    {
        for (int bit = 0; bit < 8; ++bit)
        {
            signature[byte] ^= (1 << bit);

            EXPECT_EQ(
                PQC_verify(
                    PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
                    signature.data(), signature.size()
                ),
                PQC_BAD_SIGNATURE
            ) << "changed signature should NOT match";

            signature[byte] ^= (1 << bit);
        }
    }
}


TEST(DILITHIUM, BAD_MESSAGE)
{
    DILITHIUM_PRIVATE_KEY(priv_alice);
    DILITHIUM_PUBLIC_KEY(pub_alice);
    DILITHIUM_SIGNATURE(signature);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_DILITHIUM, priv_alice.data(), priv_alice.size());
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
            PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), (uint8_t *)message, message_len, signature.data(),
            signature.size()
        ),
        PQC_OK
    ) << "signature should match";

    for (size_t byte = 0; byte < message_len; ++byte)
    {
        for (int bit = 0; bit < 8; ++bit)
        {
            message[byte] ^= (1 << bit);


            EXPECT_EQ(
                PQC_verify(
                    PQC_CIPHER_DILITHIUM, pub_alice.data(), pub_alice.size(), (uint8_t *)message, message_len,
                    signature.data(), signature.size()
                ),
                PQC_BAD_SIGNATURE
            ) << "changed message should NOT match";

            message[byte] ^= (1 << bit);
        }
    }
}

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
        static void get_entropy(uint8_t * buf, size_t size)
        {
            static std::ifstream f(entropy_path, std::ios_base::in | std::ios_base::binary);
            f.exceptions(std::ios_base::badbit | std::ios_base::eofbit);
            f.read(reinterpret_cast<char *>(buf), size);
        }
    };

    PQC_random_from_external(EntropyReader::get_entropy);

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

        EXPECT_EQ(PQC_generate_key_pair(PQC_CIPHER_DILITHIUM, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK)
            << "keys made";
        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";

        CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_DILITHIUM, sk.data(), sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        EXPECT_EQ(PQC_sign(alice, msg.data(), mlen, sig.data(), sig.size()), PQC_OK) << "signing should succeed";
        EXPECT_TRUE(sig == kat_sig) << "signature equal";

        EXPECT_EQ(
            PQC_verify(PQC_CIPHER_DILITHIUM, pk.data(), pk.size(), msg.data(), mlen, sig.data(), sig.size()), PQC_OK
        ) << "signature should match";
    }
}
