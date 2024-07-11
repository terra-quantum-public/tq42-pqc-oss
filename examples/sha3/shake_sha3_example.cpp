// SHA3 is a hash-function. Input data - message of any size.
// Hash of arbitary size is saved into hash array.
#include <cstring>
#include <iostream>

#include <pqc/sha3.h>

/*
The hash taking mode SHAKE is the mode of the sha 3 hash function, but with a variable output size.
Simply put, you can take hash with any hash size.
The SHAKE function exists in two instances: SHAKE 128 and SHAKE 256. They differ somewhat in their internal
structure. In particular, SHAKE 256 will do more permutations with larger output hash sizes, which means it
will have higher reliability. However, this does not significantly affect the quality of hash functions. And
it has absolutely no effect on the interface to use.

In this example, we will create a message with data, take a hash from it and compare it with the default cache
that should be received.
*/

const int hash_size = 500; // Output hash size we want to have

int main(void)
{
    // message compare. We should get hash equal to this message
    uint8_t defaultHash[hash_size] = {
        205, 101, 164, 229, 83,  64,  91,  80,  194, 243, 112, 1,   234, 129, 144, 95,  54,  214, 80,  204, 119, 95,
        218, 216, 152, 178, 227, 67,  100, 76,  179, 219, 37,  107, 192, 233, 179, 1,   247, 242, 26,  219, 170, 250,
        217, 121, 49,  191, 41,  11,  51,  214, 57,  22,  134, 186, 17,  63,  163, 254, 152, 167, 170, 245, 125, 216,
        158, 51,  74,  128, 19,  212, 117, 46,  101, 219, 156, 53,  12,  128, 52,  29,  51,  57,  57,  96,  79,  98,
        221, 237, 241, 250, 62,  201, 189, 236, 185, 4,   73,  2,   44,  138, 79,  111, 255, 199, 122, 220, 122, 164,
        35,  176, 114, 94,  42,  219, 172, 130, 171, 7,   41,  181, 146, 68,  16,  25,  36,  255, 73,  170, 245, 103,
        42,  5,   208, 16,  252, 164, 211, 196, 173, 180, 84,  216, 137, 16,  214, 178, 217, 254, 162, 133, 153, 55,
        74,  172, 161, 157, 139, 201, 100, 79,  128, 68,  170, 148, 8,   148, 190, 5,   146, 176, 115, 174, 213, 75,
        189, 108, 192, 166, 197, 155, 182, 190, 208, 29,  241, 143, 211, 232, 116, 230, 33,  161, 199, 22,  21,  51,
        242, 240, 175, 166, 238, 189, 193, 123, 186, 185, 177, 176, 110, 66,  10,  31,  114, 54,  84,  52,  196, 229,
        135, 213, 67,  250, 246, 94,  207, 135, 138, 174, 81,  93,  70,  202, 64,  16,  106, 123, 160, 135, 75,  135,
        221, 90,  74,  180, 220, 71,  32,  185, 136, 9,   205, 215, 86,  110, 102, 69,  192, 196, 171, 221, 61,  110,
        51,  201, 200, 200, 7,   188, 162, 29,  152, 62,  183, 35,  161, 85,  20,  158, 172, 70,  100, 113, 39,  192,
        107, 173, 3,   186, 160, 29,  70,  79,  13,  8,   168, 118, 53,  215, 63,  133, 191, 71,  181, 58,  131, 86,
        2,   229, 50,  78,  71,  174, 120, 167, 124, 69,  100, 203, 38,  4,   126, 120, 55,  190, 152, 121, 217, 204,
        185, 128, 68,  146, 196, 168, 62,  193, 194, 66,  61,  200, 179, 62,  13,  185, 117, 23,  91,  66,  106, 181,
        181, 210, 190, 102, 10,  211, 94,  190, 73,  27,  252, 81,  253, 150, 121, 51,  198, 176, 59,  148, 198, 209,
        64,  114, 10,  130, 97,  133, 240, 133, 99,  48,  148, 178, 88,  17,  144, 111, 220, 219, 213, 232, 24,  242,
        212, 109, 238, 252, 167, 250, 123, 114, 65,  253, 118, 160, 219, 168, 100, 0,   126, 162, 214, 208, 227, 130,
        43,  255, 247, 215, 230, 226, 148, 55,  204, 136, 59,  221, 121, 210, 19,  64,  200, 232, 214, 52,  104, 141,
        198, 222, 244, 239, 105, 236, 194, 127, 214, 206, 79,  39,  41,  242, 96,  74,  210, 81,  118, 54,  93,  130,
        80,  184, 83,  37,  212, 55,  4,   10,  233, 196, 253, 51,  34,  158, 65,  10,  162, 7,   239, 147, 115, 43,
        253, 35,  106, 183, 160, 83,  104, 63,  120, 78,  242, 0,   72,  91,  22,  48};

    // Let's init memmory space for our output hash
    uint8_t out[hash_size];

    // Init context of sha3 SHAKE hash function using library API
    CIPHER_HANDLE sha3 = PQC_init_context_hash(PQC_CIPHER_SHA3, PQC_SHAKE_256);

    /*
    In detail. There is a function PQC_add_data(). It allows you to add data to the buffer from which the hash is taken.
    It is important to understand that this function can be applied to one hash function object many times. That is, if
    you need to take a hash from data of this type "1234567890", then you can add "1234" first, and then additionally
    add "567890" and take the hash. And it won't be any different from taking the hash from "1234567890". Moreover, you
    can first add "1234", take the hash from this data, and then add "567890" and again take the hash from the added
    data. And the resulting hash will be equivalent to the hash from "1234567890".

    In the example, we will first add "1234", then we will take a hash from this data, show that it is NOT equal to our
    default message. Then add "567890", take the hash again. And show that it is equal to our default message. After
    that, we will create a new hash function object and take the hash from "1234567890". And let's show that it is also
    equal to our default message.
    */
    PQC_add_data(sha3, (uint8_t *)"1234", 4);
    PQC_get_hash(sha3, out, hash_size);

    // So, now in out is hash of SHAKE256 fron "1234" data

    if (memcmp(out, defaultHash, hash_size) == 0)
        std::cout << "ERROR!!! The shouldn't be equal!!!";

    PQC_add_data(sha3, (uint8_t *)"567890", 6);
    PQC_get_hash(sha3, out, hash_size);
    if (memcmp(out, defaultHash, hash_size) != 0)
        std::cout << "ERROR!!! The should be equal!!!";

    // So, now in out is hash of SHAKE256 fron "1234567890" data

    PQC_close_context(sha3);


    // Let's create new context
    CIPHER_HANDLE sha3_new = PQC_init_context_hash(PQC_CIPHER_SHA3, PQC_SHAKE_256);
    PQC_add_data(sha3_new, (uint8_t *)"1234567890", 10);
    PQC_get_hash(sha3_new, out, hash_size);
    if (memcmp(out, defaultHash, hash_size) != 0)
        std::cout << "ERROR!!! The should be equal!!!";

    // So, now in out is hash of SHAKE256 fron "1234567890" data

    PQC_close_context(sha3_new);

    std::cout << "end of shake example";


    /*
    To use SHAKE128 intead of SHAKE256 it is nessary only to change PQC_SHAKE_256 to PQC_SHAKE_128 in initialization
    context
    */

    return 0;
}
