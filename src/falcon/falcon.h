#pragma once

#include <cstddef>
#include <cstdint>

#include <pqc/falcon.h>

#include <buffer.h>
#include <core.h>
#include <falcon/inner.h>


#define FALCON_ERR_RANDOM -1

#define FALCON_ERR_SIZE -2

#define FALCON_ERR_FORMAT -3

#define FALCON_ERR_BADSIG -4

#define FALCON_ERR_BADARG -5

#define FALCON_ERR_INTERNAL -6

#define FALCON_SIG_COMPRESSED 1

#define FALCON_SIG_PADDED 2

#define FALCON_SIG_CT 3

typedef struct
{
    uint64_t opaque_contents[26];
} shake256_context;

void shake_256_init(shake256_context * context);

void shake_256_inject(shake256_context * context, ConstBufferView buffer);

void shake_256_flip(shake256_context * context);

void shake_256_extract(shake256_context * context, BufferView RezBufferView);

void shake_256_init_prng_from_seed(shake256_context * context, ConstBufferView buffer);

void falcon_sign_start(ConstBufferView nonce, shake256_context * hash_data);

int falcon_sign_dyn_finish(
    ConstBufferView signature, int sign_type, ConstBufferView privkey, shake256_context * hash_data, const void * nonce,
    ConstBufferView useData
);

int falcon_verify_start(shake256_context * hash_data, ConstBufferView signature);

int falcon_verify_finish(
    ConstBufferView signature, int sign_type, ConstBufferView public_key, shake256_context * hash_data,
    BufferView useData
);
