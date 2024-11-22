#include "secure_delete.h"

#include <pqc/aes.h>
#include <pqc/delete.h>
#include <pqc/random.h>

void cb_cencrypt(uint8_t key[], uint8_t data[], size_t data_len, uint8_t iv[])
{
    CIPHER_HANDLE context;

    context = PQC_context_init_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    PQC_symmetric_encrypt(context, PQC_AES_M_CBC, data, data_len);

    PQC_context_close(context);
}

int secure_delete(const char * filename, IRandomGenerator * rng)
{
    StackBuffer<PQC_AES_KEYLEN> key;

    uint8_t iv[PQC_AES_IVLEN] = {238, 74, 52, 31, 248, 209, 168, 30, 54, 160, 230, 66, 86, 116, 215, 141};

    rng->random_bytes(key);

    std::fstream inp(filename, std::ios::ate | std::ios::binary | std::ios::out | std::ios::in);
    size_t file_size = inp.tellg();

    const size_t freadPeriod = PQC_AES_BLOCKLEN * 8;
    std::vector<char> readWriteUse(freadPeriod, 0);

    inp.seekg(0);
    for (size_t i = 0; i < file_size; i += freadPeriod)
    {
        size_t size = std::min(file_size - i, freadPeriod); // size = std::min(file_size - i, freadPeriod)
        inp.read(&readWriteUse[0], size);                   // read size bytes
        if (inp.fail())
        {
            return 0;
        }

        memset(readWriteUse.data() + size, 0, freadPeriod - size); // pad from size to freadPeriod
        cb_cencrypt(key.data(), reinterpret_cast<uint8_t *>(readWriteUse.data()), readWriteUse.size(), iv);

        inp.seekg(i);                      // seek i
        inp.write(&readWriteUse[0], size); // write size bytes, we will end up on pos=i
        if (inp.fail())
        {
            return 0;
        }
    }

    inp.close();
    remove(filename);

    return 1;
}

int file_delete(const char * filename, IRandomGenerator * rng)
{
    if (std::filesystem::is_regular_file(filename))
    {
        return secure_delete(filename, rng);
    }
    else
    {
        return 0;
    }
}
