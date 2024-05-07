#pragma once


#define PQC_PBKDF2_hLen 256 // hash function parameters
#define PQC_PBKDF2_L_SHA3 (PQC_PBKDF2_hLen / 8)
#define PQC_PBKDF2_B_SHA3 136

#define PQC_PBKDF2_ITERATIONS_NUMBER 4096 // number of iterations of the HMAC function
#include <stdint.h>
int * pbkdf_2(
    size_t password_len, const uint8_t * charset, size_t kLen, int * master_key, uint8_t * symbols_set,
    size_t symbols_setLength
);
