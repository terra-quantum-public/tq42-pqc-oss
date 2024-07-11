#include <pqc/aes.h>

int main()
{
    CIPHER_HANDLE context;

    uint8_t key[PQC_AES_KEYLEN] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
                                   '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2'};

    context = PQC_init_context(PQC_CIPHER_AES, key, PQC_AES_KEYLEN);
    if (context == PQC_BAD_CIPHER)
        return 1;

    if (PQC_close_context(context) != PQC_OK)
        return 1;

    return 0;
}
