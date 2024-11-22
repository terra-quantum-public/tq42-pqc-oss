#include "indcpa.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"
#include <rng/random_generator.h>
#include <stddef.h>
#include <stdint.h>

/*************************************************
 * Name:        pack_pk
 *
 * Description: Serialize the public key as concatenation of the
 *              serialized vector of polynomials pk
 *              and the public seed used to generate the matrix A.
 *
 * Arguments:   uint8_t *r:          pointer to the output serialized public key
 *              polyvec *pk:         pointer to the input public-key polyvec
 *              const uint8_t *seed: pointer to the input public seed
 **************************************************/
static void pack_pk(const BufferView & r, polyvec * pk, const uint8_t seed[ML_RH_SIZE])
{
    polyvec_tobytes(r.data(), pk);
    size_t seed_start = r.size() - ML_RH_SIZE;
    for (size_t i = 0; i < ML_RH_SIZE; ++i)
        r[seed_start + i] = seed[i];
}

/*************************************************
 * Name:        unpack_pk
 *
 * Description: De-serialize public key from a byte array;
 *              approximate inverse of pack_pk
 *
 * Arguments:   - polyvec *pk:             pointer to output public-key
 *                                         polynomial vector
 *              - uint8_t *seed:           pointer to output seed to generate
 *                                         matrix A
 *              - const uint8_t *packedpk: pointer to input serialized public key
 **************************************************/
static void unpack_pk(polyvec * pk, uint8_t seed[ML_RH_SIZE], const ConstBufferView & packedpk)
{
    polyvec_frombytes(pk, packedpk.const_data());
    size_t seed_start = packedpk.size() - ML_RH_SIZE;
    for (size_t i = 0; i < ML_RH_SIZE; ++i)
        seed[i] = packedpk[seed_start + i];
}

/*************************************************
 * Name:        pack_sk
 *
 * Description: Serialize the secret key
 *
 * Arguments:   - uint8_t *r:  pointer to output serialized secret key
 *              - polyvec *sk: pointer to input vector of polynomials (secret key)
 **************************************************/
static void pack_sk(uint8_t * r, polyvec * sk) { polyvec_tobytes(r, sk); }

/*************************************************
 * Name:        unpack_sk
 *
 * Description: De-serialize the secret key;
 *              inverse of pack_sk
 *
 * Arguments:   - polyvec *sk:             pointer to output vector of
 *                                         polynomials (secret key)
 *              - const uint8_t *packedsk: pointer to input serialized secret key
 **************************************************/
static void unpack_sk(polyvec * sk, const ConstBufferView & packedsk) { polyvec_frombytes(sk, packedsk.const_data()); }

/*************************************************
 * Name:        rej_uniform
 *
 * Description: Run rejection sampling on uniform random bytes to generate
 *              uniform random integers mod q
 *
 * Arguments:   - int16_t *r:          pointer to output buffer
 *              - unsigned int len:    requested number of 16-bit integers
 *                                     (uniform mod q)
 *              - const uint8_t *buf:  pointer to input buffer
 *                                     (assumed to be uniform random bytes)
 *              - unsigned int buflen: length of input buffer in bytes
 *
 * Returns number of sampled 16-bit integers (at most len)
 **************************************************/
static unsigned int rej_uniform(int16_t * r, unsigned int len, const uint8_t * buf, unsigned int buflen)
{
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen)
    {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < ML_Q)
            r[ctr++] = val0;
        if (ctr < len && val1 < ML_Q)
            r[ctr++] = val1;
    }

    return ctr;
}

/*************************************************
 * Name:        gen_matrix
 *
 * Description: Deterministically generate matrix A (or the transpose of A)
 *              from a seed. Entries of the matrix are polynomials that look
 *              uniformly random. Performs rejection sampling on output of
 *              a XOF
 *
 * Arguments:   - polyvec *a:          pointer to ouptput matrix A
 *              - const uint8_t *seed: pointer to input seed
 *              - int transposed:      boolean deciding whether A or A^T
 *                                     is generated
 **************************************************/
#define GEN_MATRIX_NBLOCKS ((12 * ML_N / 8 * (1 << 12) / ML_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_matrix(polyvec * a, uint8_t param_k, const uint8_t seed[ML_RH_SIZE], int transposed)
{
    unsigned int ctr, k;
    unsigned int buflen, off;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2];
    xof_state state;

    for (uint8_t i = 0; i < param_k; i++)
    {
        for (uint8_t j = 0; j < param_k; j++)
        {
            if (transposed)
                xof_absorb(&state, seed, i, j);
            else
                xof_absorb(&state, seed, j, i);

            xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform((*a)[i * param_k + j].coeffs, ML_N, buf, buflen);

            while (ctr < ML_N)
            {
                off = buflen % 3;
                for (k = 0; k < off; k++)
                    buf[k] = buf[buflen - off + k];
                xof_squeezeblocks(buf + off, 1, &state);
                buflen = off + XOF_BLOCKBYTES;
                ctr += rej_uniform((*a)[i * param_k + j].coeffs + ctr, ML_N - ctr, buf, buflen);
            }
        }
    }
}

void indcpa_keypair(const BufferView & pubkey, const BufferView & seckey, size_t mode, IRandomGenerator * rng)
{
    uint8_t buf[2 * ML_RH_SIZE];
    const uint8_t * publicseed = buf;
    const uint8_t * noiseseed = buf + ML_RH_SIZE;
    uint8_t nonce = 0;
    polyvec a(ParameterSets[mode].K * ParameterSets[mode].K); // matrix
    polyvec e(ParameterSets[mode].K), pkpv(ParameterSets[mode].K), skpv(ParameterSets[mode].K);

    rng->random_bytes(BufferView(&buf, ML_RH_SIZE));
    if ((mode == ML_KEM_512) || (mode == ML_KEM_768) || (mode == ML_KEM_1024))
    {
        buf[ML_RH_SIZE] = (uint8_t)ParameterSets[mode].K;
        hash_g(buf, buf, ML_RH_SIZE + 1);
    }
    else
    {
        hash_g(buf, buf, ML_RH_SIZE);
    }

    gen_matrix(&a, (uint8_t)ParameterSets[mode].K, publicseed, 0);

    for (size_t i = 0; i < ParameterSets[mode].K; i++)
        poly_getnoise_eta1(&(skpv[i]), noiseseed, nonce++, ParameterSets[mode].ETA_1);
    for (size_t i = 0; i < ParameterSets[mode].K; i++)
        poly_getnoise_eta1(&(e[i]), noiseseed, nonce++, ParameterSets[mode].ETA_1);

    polyvec_ntt(&skpv);
    polyvec_ntt(&e);

    // matrix-vector multiplication
    for (size_t i = 0; i < ParameterSets[mode].K; i++)
    {
        polyvec_pointwise_acc_montgomery(&(pkpv[i]), &a, i * ParameterSets[mode].K, &skpv);
        poly_tomont(&(pkpv[i]));
    }

    polyvec_add(&pkpv, &pkpv, &e);
    polyvec_reduce(&pkpv);

    pack_sk(seckey.data(), &skpv);
    pack_pk(pubkey, &pkpv, publicseed);
}


/*************************************************
 * Name:        indcpa_enc
 *
 * Description: Encryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - uint8_t *c:           pointer to output ciphertext
 *              - const uint8_t *m:     pointer to input message
 *                                      (of length ML_RH_SIZE bytes)
 *              - const uint8_t *pk:    pointer to input public key
 *              - const uint8_t *coins: pointer to input random coins
 *                                      used as seed (of length ML_RH_SIZE)
 *                                      to deterministically generate all
 *                                      randomness
 **************************************************/
void indcpa_enc(
    uint8_t * c, const uint8_t m[ML_RH_SIZE], const ConstBufferView & pk, const uint8_t coins[ML_RH_SIZE], size_t mode
)
{
    unsigned int i;
    uint8_t seed[ML_RH_SIZE];
    uint8_t nonce = 0;
    polyvec sp(ParameterSets[mode].K), pkpv(ParameterSets[mode].K), ep(ParameterSets[mode].K),
        bp(ParameterSets[mode].K);
    polyvec at(ParameterSets[mode].K * ParameterSets[mode].K); // matrix
    poly v, k, epp;

    unpack_pk(&pkpv, seed, pk);
    poly_frommsg(&k, m);
    gen_matrix(&at, (uint8_t)ParameterSets[mode].K, seed, 1);

    for (i = 0; i < ParameterSets[mode].K; i++)
        poly_getnoise_eta1(&(sp[i]), coins, nonce++, ParameterSets[mode].ETA_1);
    for (i = 0; i < ParameterSets[mode].K; i++)
        poly_getnoise_eta2(&(ep[i]), coins, nonce++);
    poly_getnoise_eta2(&epp, coins, nonce++);

    polyvec_ntt(&sp);

    // matrix-vector multiplication
    for (i = 0; i < ParameterSets[mode].K; i++)
        polyvec_pointwise_acc_montgomery(&(bp[i]), &at, i * ParameterSets[mode].K, &sp);

    polyvec_pointwise_acc_montgomery(&v, &pkpv, 0, &sp);

    polyvec_invntt_tomont(&bp);
    poly_invntt_tomont(&v);

    polyvec_add(&bp, &bp, &ep);
    poly_add(&v, &v, &epp);
    poly_add(&v, &v, &k);
    polyvec_reduce(&bp);
    poly_reduce(&v);

    // packing
    polyvec_compress(c, ParameterSets[mode].POLYVECCOMPRESSED_SIZE, &bp, ParameterSets[mode].K);
    poly_compress(c + ParameterSets[mode].POLYVECCOMPRESSED_SIZE, ParameterSets[mode].POLYCOMPRESSED_SIZE, &v);
}

/*************************************************
 * Name:        indcpa_dec
 *
 * Description: Decryption function of the CPA-secure
 *              public-key encryption scheme underlying Kyber.
 *
 * Arguments:   - uint8_t *m:        pointer to output decrypted message
 *                                   (of length ML_RH_SIZE)
 *              - const uint8_t *c:  pointer to input ciphertext
 *              - const uint8_t *sk: pointer to input secret key
 **************************************************/
void indcpa_dec(uint8_t m[ML_RH_SIZE], const uint8_t * c, const ConstBufferView & sk, size_t mode)
{
    polyvec bp(ParameterSets[mode].K), skpv(ParameterSets[mode].K);
    poly v, mp;

    // unpack_ciphertext
    polyvec_decompress(&bp, c, ParameterSets[mode].POLYVECCOMPRESSED_SIZE, ParameterSets[mode].K);
    poly_decompress(&v, c + ParameterSets[mode].POLYVECCOMPRESSED_SIZE, ParameterSets[mode].POLYCOMPRESSED_SIZE);

    unpack_sk(&skpv, sk);

    polyvec_ntt(&bp);
    polyvec_pointwise_acc_montgomery(&mp, &skpv, 0, &bp);
    poly_invntt_tomont(&mp);

    poly_sub(&mp, &v, &mp);
    poly_reduce(&mp);

    poly_tomsg(m, &mp);
}
