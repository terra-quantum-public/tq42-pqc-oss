#pragma once

#include <cstddef>
#include <cstdint>

#include <pqc/ml-dsa.h>

using std::int32_t;
using std::size_t;
using std::uint32_t;

namespace mldsa
{

constexpr size_t MODE_44 = 0;
constexpr size_t MODE_65 = 1;
constexpr size_t MODE_87 = 2;

constexpr size_t SEEDBYTES = 32;
constexpr size_t CRHBYTES = 48;
constexpr size_t N = 256;
constexpr int32_t Q = 8380417;
constexpr size_t D = 13;

constexpr size_t POLYT1_PACKEDBYTES = 320;
constexpr size_t POLYT0_PACKEDBYTES = 416;

constexpr size_t MAX_CONTEXT_LEN = 255;

struct ParameterSet
{
    constexpr ParameterSet(uint32_t id, size_t k, size_t l, size_t pk_len, size_t sk_len, size_t sig_len)
        : CIPHER_ID(id), K(k), L(l), PUBLIC_KEY_LEN(pk_len), PRIVATE_KEY_LEN(sk_len), SIGNATURE_LEN(sig_len)
    {
    }
    uint32_t CIPHER_ID;

    size_t K;
    size_t L;

    size_t PUBLIC_KEY_LEN;
    size_t PRIVATE_KEY_LEN;
    size_t SIGNATURE_LEN;
};

static constexpr ParameterSet ParameterSets[] = {
    ParameterSet{PQC_CIPHER_ML_DSA_44, 4, 4, 1312, 2560, 2420},
    ParameterSet{PQC_CIPHER_ML_DSA_65, 6, 5, 1952, 4032, 3309},
    ParameterSet{PQC_CIPHER_ML_DSA_87, 8, 7, 2592, 4896, 4627}};

#define K_87 8
#define L_87 7
#define K_65 6
#define L_65 5
#define K_44 4
#define L_44 4

#define CTILDEBYTES_87 64
#define CTILDEBYTES_65 48
#define CTILDEBYTES_44 32

#define ETA_44 2
#define TAU_44 39
#define BETA_44 78
#define GAMMA1_44 (1 << 17)
#define GAMMA2_44 ((Q - 1) / 88)
#define OMEGA_44 80

#define POLYZ_PACKEDBYTES_44 576
#define POLYW1_PACKEDBYTES_44 192
#define POLYETA_PACKEDBYTES_44 96

#define ETA_65 4
#define TAU_65 49
#define BETA_65 196
#define GAMMA1_65 (1 << 19)
#define GAMMA2_65 ((Q - 1) / 32)
#define OMEGA_65 55

#define POLYW1_PACKEDBYTES_65 128
#define POLYETA_PACKEDBYTES_65 128

#define ETA_87 2
#define TAU_87 60
#define BETA_87 120
#define GAMMA1_87 (1 << 19)
#define GAMMA2_87 ((Q - 1) / 32)
#define OMEGA_87 75

#define POLYZ_PACKEDBYTES_65 640
#define POLYZ_PACKEDBYTES_87 640
#define POLYZ_PACKEDBYTES_44 576

#define POLYW1_PACKEDBYTES_87 128
#define POLYW1_PACKEDBYTES_44 192

#define POLYETA_PACKEDBYTES_87 96
#define POLYETA_PACKEDBYTES_44 96

} // namespace mldsa
