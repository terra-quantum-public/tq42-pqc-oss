#pragma once

#include "pqc/kdf.h"

size_t pbkdf_2(
    int mode, size_t hash_length, size_t password_length, const uint8_t * password, size_t key_length,
    uint8_t * derived_key, size_t derived_key_length, uint8_t * salt, size_t salt_length, size_t iterations
);
