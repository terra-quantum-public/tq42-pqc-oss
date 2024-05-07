#include "secure_delete.h"

#include <pqc/aes.h>
#include <pqc/delete.h>
#include <pqc/random.h>

void cb_cencrypt(uint8_t key[], uint8_t data[], size_t data_len, uint8_t iv[])
{
    CIPHER_HANDLE context;

    context = PQC_init_context_iv(PQC_CIPHER_AES, key, PQC_AES_KEYLEN, iv, PQC_AES_IVLEN);

    PQC_encrypt(context, PQC_AES_M_CBC, data, data_len);

    PQC_close_context(context);
}

int secure_delete(const char * filename)
{
    std::unique_ptr<uint8_t[]> key = std::make_unique<uint8_t[]>(32);

    uint8_t iv[PQC_AES_IVLEN] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    PQC_random_bytes(static_cast<void *>(key.get()), static_cast<size_t>(32));

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
        cb_cencrypt(key.get(), reinterpret_cast<uint8_t *>(readWriteUse.data()), readWriteUse.size(), iv);

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

int file_delete(const char * filename)
{
    if (std::filesystem::is_regular_file(filename))
    {
        return secure_delete(filename);
    }
    else
    {
        return 0;
    }
}
