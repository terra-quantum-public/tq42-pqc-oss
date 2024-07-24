#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

#include <gtest/gtest.h>

#include <pqc/aes.h>
#include <pqc/common.h>
#include <pqc/kyber.h>
#include <pqc/random.h>


#define KYBER_PRIVATE_KEY(x) std::vector<uint8_t> x(sizeof(pqc_kyber_private_key))
#define KYBER_PUBLIC_KEY(x) std::vector<uint8_t> x(sizeof(pqc_kyber_public_key))
#define KYBER_MESSAGE(x) std::vector<uint8_t> x(sizeof(pqc_kyber_message))
#define KYBER_SHARED_SECRET(x) std::vector<uint8_t> x(sizeof(pqc_kyber_shared_secret))

TEST(KYBER, CREATE_SECRET_CHECK_SIZES)
{
    KYBER_PRIVATE_KEY(priv_alice);
    KYBER_PUBLIC_KEY(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_KYBER, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size() - 1
        ),
        PQC_BAD_LEN
    ) << "should check private key size";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_KYBER, pub_alice.data(), pub_alice.size() - 1, priv_alice.data(), priv_alice.size()
        ),
        PQC_BAD_LEN
    ) << "should check public key size";
}

TEST(KYBER, INIT_CHECK_KEYLEN)
{
    KYBER_PRIVATE_KEY(priv_alice);

    EXPECT_EQ(PQC_init_context(PQC_CIPHER_KYBER, priv_alice.data(), priv_alice.size() - 1), PQC_BAD_CIPHER)
        << "Initialization should fail due to bad key length";
}

TEST(KYBER, CREATE_SECRET)
{
    KYBER_PRIVATE_KEY(priv_bob);
    KYBER_PUBLIC_KEY(pub_bob);
    KYBER_SHARED_SECRET(shared_alice);
    KYBER_SHARED_SECRET(shared_bob);
    KYBER_MESSAGE(message);

    EXPECT_EQ(
        PQC_generate_key_pair(PQC_CIPHER_KYBER, pub_bob.data(), pub_bob.size(), priv_bob.data(), priv_bob.size()),
        PQC_OK
    );
    CIPHER_HANDLE bob = PQC_init_context(PQC_CIPHER_KYBER, priv_bob.data(), priv_bob.size());
    EXPECT_NE(bob, PQC_BAD_CIPHER);

    EXPECT_EQ(
        PQC_kem_encode_secret(
            PQC_CIPHER_KYBER, message.data(), message.size(), pub_bob.data(), pub_bob.size(), shared_alice.data(),
            shared_alice.size()
        ),
        PQC_OK
    );

    EXPECT_EQ(
        PQC_kem_decode_secret(bob, message.data(), message.size(), shared_bob.data(), shared_alice.size()), PQC_OK
    );

    EXPECT_TRUE(shared_alice == shared_bob);
}

TEST(KYBER, DERIVE)
{
    KYBER_PRIVATE_KEY(priv_bob);
    KYBER_PUBLIC_KEY(pub_bob);
    KYBER_MESSAGE(message);
    std::vector<uint8_t> shared_alice(PQC_AES_KEYLEN);
    std::vector<uint8_t> shared_bob(PQC_AES_KEYLEN);

    const size_t info_size = 10;
    uint8_t party_a_info[info_size] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

    EXPECT_EQ(
        PQC_generate_key_pair(PQC_CIPHER_KYBER, pub_bob.data(), pub_bob.size(), priv_bob.data(), priv_bob.size()),
        PQC_OK
    );
    CIPHER_HANDLE bob = PQC_init_context(PQC_CIPHER_KYBER, priv_bob.data(), priv_bob.size());
    EXPECT_NE(bob, PQC_BAD_CIPHER);

    EXPECT_EQ(
        PQC_kem_encode(
            PQC_CIPHER_KYBER, message.data(), message.size(), party_a_info, info_size, pub_bob.data(), pub_bob.size(),
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


TEST(KYBER, KAT1024_Round3)
{
    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "mlkem";
    static const auto responses_path = base_path / "kyber1024-KAT.rsp";
    static const auto entropy_path = base_path / "kyber1024-KAT.ent";

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

    std::ifstream responses(responses_path);
    std::string expected;

    std::getline(responses, expected);
    EXPECT_TRUE(expected == "# Kyber1024");

    const int KATNUM = 100;
    KYBER_PRIVATE_KEY(sk);
    KYBER_PUBLIC_KEY(pk);
    KYBER_MESSAGE(ct);
    KYBER_SHARED_SECRET(ss);
    KYBER_PRIVATE_KEY(kat_sk);
    KYBER_PUBLIC_KEY(kat_pk);
    KYBER_MESSAGE(kat_ct);
    KYBER_SHARED_SECRET(kat_ss);

    PQC_random_from_external(EntropyReader::get_entropy);
    for (size_t i = 0; i < KATNUM; ++i)
    {
        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected); // seed line

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "pk = ", kat_pk.data(), kat_pk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "sk = ", kat_sk.data(), kat_sk.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "ct = ", kat_ct.data(), kat_ct.size());

        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "ss = ", kat_ss.data(), kat_ss.size());

        EXPECT_EQ(PQC_generate_key_pair(PQC_CIPHER_KYBER, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK);
        EXPECT_TRUE(pk == kat_pk) << "public key equal";
        EXPECT_TRUE(sk == kat_sk) << "secure key equal";

        EXPECT_EQ(
            PQC_kem_encode_secret(PQC_CIPHER_KYBER, ct.data(), ct.size(), pk.data(), pk.size(), ss.data(), ss.size()),
            PQC_OK
        );
        EXPECT_TRUE(ct == kat_ct) << "cipher text equal";
        EXPECT_TRUE(ss == kat_ss) << "shared secret equal";

        CIPHER_HANDLE context = PQC_init_context(PQC_CIPHER_KYBER, sk.data(), sk.size());
        EXPECT_NE(context, PQC_BAD_CIPHER);

        EXPECT_EQ(PQC_kem_decode_secret(context, ct.data(), ct.size(), ss.data(), ss.size()), PQC_OK);
        EXPECT_TRUE(ss == kat_ss) << "decode correct";
    }
}
