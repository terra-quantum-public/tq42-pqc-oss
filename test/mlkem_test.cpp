#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include <pqc/aes.h>
#include <pqc/common.h>
#include <pqc/ml-kem.h>
#include <pqc/random.h>


#define ML_KEM_PRIVATE_KEY(x) std::vector<uint8_t> x(sizeof(pqc_ml_kem_private_key))
#define ML_KEM_PUBLIC_KEY(x) std::vector<uint8_t> x(sizeof(pqc_ml_kem_public_key))
#define ML_KEM_MESSAGE(x) std::vector<uint8_t> x(sizeof(pqc_ml_kem_message))
#define ML_KEM_SHARED_SECRET(x) std::vector<uint8_t> x(sizeof(pqc_ml_kem_shared_secret))

TEST(ML_KEM, CREATE_SECRET_CHECK_SIZES)
{
    ML_KEM_PRIVATE_KEY(priv_alice);
    ML_KEM_PUBLIC_KEY(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_ML_KEM, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size() - 1
        ),
        PQC_BAD_LEN
    ) << "should check private key size";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_ML_KEM, pub_alice.data(), pub_alice.size() - 1, priv_alice.data(), priv_alice.size()
        ),
        PQC_BAD_LEN
    ) << "should check public key size";
}

TEST(ML_KEM, INIT_CHECK_KEYLEN)
{
    ML_KEM_PRIVATE_KEY(priv_alice);

    EXPECT_EQ(PQC_init_context(PQC_CIPHER_ML_KEM, priv_alice.data(), priv_alice.size() - 1), PQC_BAD_CIPHER)
        << "Initialization should fail due to bad key length";
}

TEST(ML_KEM, CREATE_SECRET)
{
    ML_KEM_PRIVATE_KEY(priv_bob);
    ML_KEM_PUBLIC_KEY(pub_bob);
    ML_KEM_SHARED_SECRET(shared_alice);
    ML_KEM_SHARED_SECRET(shared_bob);
    ML_KEM_MESSAGE(message);

    EXPECT_EQ(
        PQC_generate_key_pair(PQC_CIPHER_ML_KEM, pub_bob.data(), pub_bob.size(), priv_bob.data(), priv_bob.size()),
        PQC_OK
    );
    CIPHER_HANDLE bob = PQC_init_context(PQC_CIPHER_ML_KEM, priv_bob.data(), priv_bob.size());
    EXPECT_NE(bob, PQC_BAD_CIPHER);

    EXPECT_EQ(
        PQC_kem_encode_secret(
            PQC_CIPHER_ML_KEM, message.data(), message.size(), pub_bob.data(), pub_bob.size(), shared_alice.data(),
            shared_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_kem_decode_secret(bob, message.data(), message.size(), shared_bob.data(), shared_alice.size()), PQC_OK
    );

    EXPECT_TRUE(shared_alice == shared_bob);
}

TEST(ML_KEM, DERIVE)
{
    ML_KEM_PRIVATE_KEY(priv_bob);
    ML_KEM_PUBLIC_KEY(pub_bob);
    ML_KEM_MESSAGE(message);
    std::vector<uint8_t> shared_alice(PQC_AES_KEYLEN);
    std::vector<uint8_t> shared_bob(PQC_AES_KEYLEN);

    const size_t info_size = 10;
    uint8_t party_a_info[info_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    EXPECT_EQ(
        PQC_generate_key_pair(PQC_CIPHER_ML_KEM, pub_bob.data(), pub_bob.size(), priv_bob.data(), priv_bob.size()),
        PQC_OK
    );
    CIPHER_HANDLE bob = PQC_init_context(PQC_CIPHER_ML_KEM, priv_bob.data(), priv_bob.size());
    EXPECT_NE(bob, PQC_BAD_CIPHER);

    EXPECT_EQ(
        PQC_kem_encode(
            PQC_CIPHER_ML_KEM, message.data(), message.size(), party_a_info, info_size, pub_bob.data(), pub_bob.size(),
            shared_alice.data(), shared_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_kem_decode(
            bob, message.data(), message.size(), party_a_info, info_size, shared_bob.data(), shared_bob.size()
        ),
        PQC_OK
    );

    EXPECT_TRUE(shared_alice == shared_bob);
}


TEST(ML_KEM, ACVP_KAT_FROM_JSON)
{
    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mlkem";
    static const auto keygen_responses_path = base_path / "ml-kem-1024-keygen.rsp";
    static const auto encap_responses_path = base_path / "ml-kem-1024-encap.rsp";
    static const auto decap_responses_path = base_path / "ml-kem-1024-decap.rsp";

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
        static void get_entropy(uint8_t * buf, size_t size)
        {
            std::copy_n(entropy.begin() + offset, size, buf);
            offset += size;
        }
    };
    PQC_random_from_external(EntropyEmulator::get_entropy);

    ML_KEM_PRIVATE_KEY(sk);
    ML_KEM_PUBLIC_KEY(pk);
    ML_KEM_MESSAGE(ct);
    ML_KEM_SHARED_SECRET(ss);
    ML_KEM_PRIVATE_KEY(kat_sk);
    ML_KEM_PUBLIC_KEY(kat_pk);
    ML_KEM_MESSAGE(kat_ct);
    ML_KEM_SHARED_SECRET(kat_ss);

    std::string expected;

    std::ifstream keygen_responses(keygen_responses_path);

    std::getline(keygen_responses, expected);
    EXPECT_TRUE(expected == "# ML-KEM-1024-FROM-JSON");

    for (size_t i = 0; i < 25; ++i)
    {
        offset = 0;

        std::getline(keygen_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(keygen_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "d = ", entropy.data(), 32);

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "z = ", entropy.data() + 32, 32);

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "ek = ", kat_pk.data(), kat_pk.size());

        std::getline(keygen_responses, expected);
        Hex::to_uint_8_t(expected, "dk = ", kat_sk.data(), kat_sk.size());

        EXPECT_EQ(PQC_generate_key_pair(PQC_CIPHER_ML_KEM, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK);
        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";
    }

    std::ifstream encap_responses(encap_responses_path);

    std::getline(encap_responses, expected);
    EXPECT_TRUE(expected == "# ML-KEM-1024-FROM-JSON");

    for (size_t i = 0; i < 25; ++i)
    {
        offset = 0;

        std::getline(encap_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(encap_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(encap_responses, expected);
        Hex::to_uint_8_t(expected, "ek = ", kat_pk.data(), kat_pk.size());

        std::getline(encap_responses, expected);
        Hex::to_uint_8_t(expected, "dk = ", kat_sk.data(), kat_sk.size());

        std::getline(encap_responses, expected);
        Hex::to_uint_8_t(expected, "c = ", kat_ct.data(), kat_ct.size());

        std::getline(encap_responses, expected);
        Hex::to_uint_8_t(expected, "k = ", kat_ss.data(), kat_ss.size());

        std::getline(encap_responses, expected);
        Hex::to_uint_8_t(expected, "m = ", entropy.data(), 32);

        EXPECT_EQ(
            PQC_kem_encode_secret(
                PQC_CIPHER_ML_KEM, ct.data(), ct.size(), kat_pk.data(), kat_pk.size(), ss.data(), ss.size()
            ),
            PQC_OK
        );

        EXPECT_TRUE(ct == kat_ct) << "cipher text equal";
        EXPECT_TRUE(ss == kat_ss) << "shared secret equal";
    }

    std::ifstream decap_responses(decap_responses_path);

    std::getline(decap_responses, expected);
    EXPECT_TRUE(expected == "# ML-KEM-1024-FROM-JSON");

    std::getline(decap_responses, expected);
    EXPECT_TRUE(expected == "");

    std::getline(decap_responses, expected);
    Hex::to_uint_8_t(expected, "ek = ", kat_pk.data(), kat_pk.size());

    std::getline(decap_responses, expected);
    Hex::to_uint_8_t(expected, "dk = ", kat_sk.data(), kat_sk.size());

    CIPHER_HANDLE context = PQC_init_context(PQC_CIPHER_ML_KEM, kat_sk.data(), kat_sk.size());
    EXPECT_NE(context, PQC_BAD_CIPHER);

    for (size_t i = 0; i < 10; ++i)
    {
        std::getline(decap_responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(decap_responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(decap_responses, expected);
        Hex::to_uint_8_t(expected, "c = ", kat_ct.data(), kat_ct.size());

        std::getline(decap_responses, expected);
        Hex::to_uint_8_t(expected, "k = ", kat_ss.data(), kat_ss.size());

        EXPECT_EQ(PQC_kem_decode_secret(context, kat_ct.data(), kat_ct.size(), ss.data(), ss.size()), PQC_OK);

        EXPECT_TRUE(ss == kat_ss) << "shared secret equal";
    }
}
