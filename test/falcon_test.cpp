#include <filesystem>
#include <fstream>
#include <stdio.h>
#include <vector>

#include <gtest/gtest.h>

#include <pqc/falcon.h>
#include <pqc/random.h>
#include <pqc/sha3.h>

#define FALCON_PRIVATE(x) std::vector<uint8_t> x(sizeof(pqc_falcon_private_key))
#define FALCON_PUBLIC(x) std::vector<uint8_t> x(sizeof(pqc_falcon_public_key))


TEST(FALCON, CREATE_SECRET_CHECK_SIZES)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "should check both key sizes";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size() - 1, priv_alice.data(), priv_alice.size()
        ),
        PQC_BAD_LEN
    ) << "should check public key size";

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size() - 1
        ),
        PQC_BAD_LEN
    ) << "should check private key size";
}

TEST(FALCON, INIT_CHECK_SIZE)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size() - 1);
    EXPECT_EQ(alice, PQC_BAD_CIPHER) << "context initialization should fail due to wrong key size";
}


TEST(FALCON, SIGN_CHECK_SIGNATURE_SIZE)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog.";

    pqc_falcon_signature signature;

    EXPECT_EQ(
        PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, (uint8_t *)&signature, sizeof(signature) - 1),
        PQC_BAD_LEN
    ) << "signing should fail due to bad signature size";
}


TEST(FALCON, VERIFY_CHECK_SIGNATURE_SIZE)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    pqc_falcon_signature signature;

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, (uint8_t *)&signature, sizeof(signature)), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            (uint8_t *)&signature, sizeof(signature) - 1
        ),
        PQC_BAD_LEN
    ) << "should fail due to bad signature size";
}


TEST(FALCON, VERIFY_CHECK_KEY_SIZE)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";

    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    pqc_falcon_signature signature;


    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, (uint8_t *)&signature, sizeof(signature)), PQC_OK)
        << "signing should succeed";


    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size() - 1, (uint8_t *)message, strlen(message) + 1,
            (uint8_t *)&signature, sizeof(signature)
        ),
        PQC_BAD_LEN
    ) << "should fail due to bad public key size";
}


TEST(FALCON, CHECK_SIGNATURE)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    pqc_falcon_signature signature;

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, (uint8_t *)&signature, sizeof(signature)), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            (uint8_t *)&signature, sizeof(signature)
        ),
        PQC_OK
    ) << "signature should match";
}


TEST(FALCON, BAD_SIGNATURE)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";


    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    pqc_falcon_signature signature;

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, strlen(message) + 1, (uint8_t *)&signature, sizeof(signature)), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
            (uint8_t *)&signature, sizeof(signature)
        ),
        PQC_OK
    ) << "signature should match";

    for (unsigned long long byte = 0; byte < sizeof(signature.signature); ++byte)
    {
        for (int bit = 0; bit < 8; ++bit)
        {
            signature.signature[byte] ^= (1 << bit);

            EXPECT_EQ(
                PQC_verify(
                    PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), (uint8_t *)message, strlen(message) + 1,
                    (uint8_t *)&signature, sizeof(signature)
                ),
                PQC_BAD_SIGNATURE
            ) << "changed signature should NOT match";

            signature.signature[byte] ^= (1 << bit);
        }
    }
}


TEST(FALCON, BAD_MESSAGE)
{
    FALCON_PRIVATE(priv_alice);
    FALCON_PUBLIC(pub_alice);

    EXPECT_EQ(
        PQC_generate_key_pair(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), priv_alice.data(), priv_alice.size()
        ),
        PQC_OK
    ) << "key generation should succeed";


    CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, priv_alice.data(), priv_alice.size());
    EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";

    char message[] = "The quick brown fox jumps over the lazy dog."
                     "The quick brown fox jumps over the lazy dog?"
                     "The quick brown fox jumps over the lazy dog!"
                     "The quick brown fox jumps over the lazy dog...";

    size_t message_len = strlen(message) + 1;

    pqc_falcon_signature signature;

    EXPECT_EQ(PQC_sign(alice, (uint8_t *)message, message_len, (uint8_t *)&signature, sizeof(signature)), PQC_OK)
        << "signing should succeed";

    EXPECT_EQ(
        PQC_verify(
            PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), (uint8_t *)message, message_len,
            (uint8_t *)&signature, sizeof(signature)
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
                    PQC_CIPHER_FALCON, pub_alice.data(), pub_alice.size(), (uint8_t *)message, message_len,
                    (uint8_t *)&signature, sizeof(signature)
                ),
                PQC_BAD_SIGNATURE
            ) << "changed message should NOT match";

            message[byte] ^= (1 << bit);
        }
    }
}

TEST(FALCON, KAT1024_Round3)
{
    static const std::filesystem::path current(__FILE__);
    static const auto base_path = current.parent_path() / "falcon";
    static const auto responses_path = base_path / "falcon1024-KAT.rsp";
    static const auto entropy_path = base_path / "falcon1024-KAT.ent";

    struct prng
    {
        uint8_t buf[512];
        size_t ptr;
        uint8_t state[256];
        int type;
    };

    static CIPHER_HANDLE sha3;

    static prng pp;
    static size_t bytes_used;
    static size_t shake_used;
    static bool shakeInitialised;
    static const size_t seed_size = 48;
    static const size_t nonce_size = 40;

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

    std::ifstream responses(responses_path);
    std::string expected;

    std::getline(responses, expected);
    EXPECT_TRUE(expected == "# Falcon-1024");

    const int KATNUM = 100;
    FALCON_PRIVATE(sk);
    FALCON_PUBLIC(pk);
    FALCON_PRIVATE(kat_sk);
    FALCON_PUBLIC(kat_pk);
    pqc_falcon_signature signature;

    struct RNG_Emulator
    {
        void init()
        {
            bytes_used = 0;
            shake_used = 0;
            shakeInitialised = false;
        }

        static void generate(uint8_t * buf, size_t size)
        {
            static std::ifstream ff(entropy_path, std::ios_base::in | std::ios_base::binary);
            if (bytes_used < seed_size + nonce_size)
            {
                ff.read(reinterpret_cast<char *>(buf), size);
                bytes_used += size;
                shake_used = 0;
            }
            else
            {
                if (!shakeInitialised)
                {
                    uint8_t shake_seed[48];
                    ff.read(reinterpret_cast<char *>(shake_seed), 48);

                    sha3 = PQC_init_context_hash(PQC_CIPHER_SHA3, PQC_SHAKE_256);
                    PQC_add_data(sha3, shake_seed, 48);

                    prng_init(&pp);
                    prng_refill(&pp);
                    shake_used = 0;
                    shakeInitialised = true;
                }

                if (shake_used == (sizeof(pp.buf) + sizeof(pp.state)))
                {
                    prng_refill(&pp);
                    shake_used = 0;
                }

                if (shake_used < sizeof(pp.buf))
                {
                    for (size_t i = 0; i < size; ++i)
                    {
                        buf[i] = pp.buf[i];
                    }
                    shake_used += size;
                }
                else if (shake_used < sizeof(pp.buf) + sizeof(pp.state))
                {
                    for (size_t i = 0; i < size; ++i)
                    {
                        buf[i] = pp.state[i];
                    }
                    shake_used += size;
                }
            }
        }

        static void prng_init(prng * p)
        {
            uint8_t tmp[56];

            PQC_get_hash(sha3, tmp, 56);

            for (int i = 0; i < 14; ++i)
            {
                const uint32_t w = (uint32_t)tmp[(i << 2) + 0] | ((uint32_t)tmp[(i << 2) + 1] << 8) |
                                   ((uint32_t)tmp[(i << 2) + 2] << 16) | ((uint32_t)tmp[(i << 2) + 3] << 24);
                *(uint32_t *)(p->state + (i << 2)) = w;
            }
            const uint64_t tl = *(uint32_t *)(p->state + 48);
            const uint64_t th = *(uint32_t *)(p->state + 52);
            *(uint64_t *)(p->state + 48) = tl + (th << 32);
        }

        static void prng_refill(prng * p)
        {
            static const uint32_t CW[] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

            uint64_t cc = *(uint64_t *)(p->state + 48);
            for (size_t u = 0; u < 8; ++u)
            {
                uint32_t state[16];
                size_t v;
                int i;

                memcpy(&state[0], CW, sizeof CW);
                memcpy(&state[4], p->state, 48);
                state[14] ^= (uint32_t)cc;
                state[15] ^= (uint32_t)(cc >> 32);
                for (i = 0; i < 10; i++)
                {

#define QROUND(a, b, c, d)                                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        state[a] += state[b];                                                                                          \
        state[d] ^= state[a];                                                                                          \
        state[d] = (state[d] << 16) | (state[d] >> 16);                                                                \
        state[c] += state[d];                                                                                          \
        state[b] ^= state[c];                                                                                          \
        state[b] = (state[b] << 12) | (state[b] >> 20);                                                                \
        state[a] += state[b];                                                                                          \
        state[d] ^= state[a];                                                                                          \
        state[d] = (state[d] << 8) | (state[d] >> 24);                                                                 \
        state[c] += state[d];                                                                                          \
        state[b] ^= state[c];                                                                                          \
        state[b] = (state[b] << 7) | (state[b] >> 25);                                                                 \
    } while (0)

                    QROUND(0, 4, 8, 12);
                    QROUND(1, 5, 9, 13);
                    QROUND(2, 6, 10, 14);
                    QROUND(3, 7, 11, 15);
                    QROUND(0, 5, 10, 15);
                    QROUND(1, 6, 11, 12);
                    QROUND(2, 7, 8, 13);
                    QROUND(3, 4, 9, 14);

#undef QROUND
                }

                for (v = 0; v < 4; v++)
                {
                    state[v] += CW[v];
                }
                for (v = 4; v < 14; v++)
                {
                    state[v] += ((uint32_t *)p->state)[v - 4];
                }
                state[14] += ((uint32_t *)p->state)[10] ^ (uint32_t)cc;
                state[15] += ((uint32_t *)p->state)[11] ^ (uint32_t)(cc >> 32);
                ++cc;

                /*
                 * We mimic the interleaving that is used in the AVX2
                 * implementation.
                 */
                for (v = 0; v < 16; ++v)
                {
                    p->buf[(u << 2) + (v << 5) + 0] = (uint8_t)state[v];
                    p->buf[(u << 2) + (v << 5) + 1] = (uint8_t)(state[v] >> 8);
                    p->buf[(u << 2) + (v << 5) + 2] = (uint8_t)(state[v] >> 16);
                    p->buf[(u << 2) + (v << 5) + 3] = (uint8_t)(state[v] >> 24);
                }
            }
            *(uint64_t *)(p->state + 48) = cc;


            p->ptr = 0;
        }
    };

    RNG_Emulator rng;
    for (size_t i = 0; i < KATNUM; ++i)
    {
        std::getline(responses, expected);
        EXPECT_TRUE(expected == "");

        std::getline(responses, expected);
        EXPECT_TRUE(expected == ("count = " + std::to_string(i)));

        std::getline(responses, expected); //seed line

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

        std::vector<uint8_t> sm(smlen);
        std::getline(responses, expected);
        Hex::to_uint_8_t(expected, "sm = ", sm.data(), sm.size());

        rng.init();
        PQC_random_from_external(RNG_Emulator::generate);
        EXPECT_EQ(PQC_generate_key_pair(PQC_CIPHER_FALCON, pk.data(), pk.size(), sk.data(), sk.size()), PQC_OK)
            << "keys made";
        EXPECT_EQ(memcmp(pk.data(), kat_pk.data(), pk.size()), 0) << "public key equal";
        EXPECT_EQ(memcmp(sk.data(), kat_sk.data(), sk.size()), 0) << "secure key equal";

        CIPHER_HANDLE alice = PQC_init_context(PQC_CIPHER_FALCON, sk.data(), sk.size());
        EXPECT_NE(alice, PQC_BAD_CIPHER) << "context initialization should pass";
        EXPECT_EQ(PQC_sign(alice, msg.data(), mlen, (uint8_t *)&signature, sizeof(signature)), PQC_OK)
            << "signing should succeed";

        EXPECT_EQ(memcmp(sm.data() + 2, (uint8_t *)&signature + 1, 40), 0) << "nonce equal";
        uint8_t * s_index = (uint8_t *)&signature + 40 + 1;
        uint8_t * nist_s_index = sm.data() + 2 + 40 + mlen + 1;
        size_t comp_sig_len = smlen - (2 + 40 + mlen + 1);

        if (i == 82)
        {
            // This template doesn't match recommended size for padded format of signature
            EXPECT_GT(comp_sig_len, PQC_FALCON_SIG_PADDED_SIZE(10) - 41);
        }
        else
        {
            EXPECT_LE(comp_sig_len, PQC_FALCON_SIG_PADDED_SIZE(10) - 41);
            EXPECT_EQ(memcmp(nist_s_index, s_index, comp_sig_len), 0) << "sig equal";
        }

        EXPECT_EQ(
            PQC_verify(
                PQC_CIPHER_FALCON, pk.data(), pk.size(), msg.data(), mlen, (uint8_t *)&signature, sizeof(signature)
            ),
            PQC_OK
        ) << "signature should match";
    }
}
