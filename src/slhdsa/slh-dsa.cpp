#include "slh-dsa.h"
#include <buffer.h>
#include <rng/rng.h>

#include "address.h"
#include "converter.h"
#include "params.h"
#include "xmss.h"

#include "fors.h"
#include "hypertree.h"

using namespace slh_dsa;

SLHDSAFactory::SLHDSAFactory() {}

uint32_t SLHDSAFactory::cipher_id() const { return PQC_CIPHER_SLH_DSA_SHAKE_256F; }

std::unique_ptr<PQC_Context> SLHDSAFactory::create_context(const ConstBufferView & private_key) const
{
    if (private_key.size() != PQC_SLH_DSA_PRIVATE_KEY_LEN)
    {
        throw BadLength();
    }
    return std::make_unique<SLHDSAContext>(reinterpret_cast<const pqc_slh_dsa_private_key *>(private_key.const_data()));
}

void SLHDSAFactory::generate_keypair(const BufferView & public_key, const BufferView & private_key) const
{

    if (private_key.size() != PQC_SLH_DSA_PRIVATE_KEY_LEN || public_key.size() != PQC_SLH_DSA_PUBLIC_KEY_LEN)
    {
        throw BadLength();
    }
    else
    {
        randombytes(private_key.mid(0, 3 * PQC_SLH_DSA_N));

        Address addr;
        BufferView layer_addr = address::layer_address(addr);
        Converter::toByte(layer_addr, PQC_SLH_DSA_D - 1);

        BufferView pkroot = private_key.mid(3 * PQC_SLH_DSA_N, PQC_SLH_DSA_N);
        ConstBufferView pkseed = private_key.mid(2 * PQC_SLH_DSA_N, PQC_SLH_DSA_N);
        ConstBufferView skseed = private_key.mid(0, PQC_SLH_DSA_N);
        xmss_node(pkroot, skseed, 0, PQC_SLH_DSA_H_PRIME, pkseed, addr);

        public_key.store(private_key.mid(2 * PQC_SLH_DSA_N, 2 * PQC_SLH_DSA_N));
    }
}


bool SLHDSAFactory::verify(
    const ConstBufferView & public_key, const ConstBufferView buffer, const ConstBufferView signature
) const
{
    if (signature.size() != PQC_SLH_DSA_SIGNATURE_LEN)
    {
        throw BadLength();
    }

    if (public_key.size() != PQC_SLH_DSA_PUBLIC_KEY_LEN)
    {
        throw BadLength();
    }

    auto [PKseed, PKroot] = public_key.split((size_t)PQC_SLH_DSA_N, (size_t)PQC_SLH_DSA_N);
    auto [R, sig_fors, sig_ht] = signature.split(
        (size_t)PQC_SLH_DSA_N, (size_t)(PQC_SLH_DSA_K * (1 + PQC_SLH_DSA_A) * PQC_SLH_DSA_N),
        (size_t)((PQC_SLH_DSA_H + PQC_SLH_DSA_D * PQC_SLH_DSA_LEN) * PQC_SLH_DSA_N)
    );

    StackBuffer<PQC_SLH_DSA_M> digest;
    function_Hmsg(R, PKseed, PKroot, buffer, digest);

    size_t start = 0;
    size_t first_part_len = (PQC_SLH_DSA_K * PQC_SLH_DSA_A + 8 - 1) / 8;
    ConstBufferView md = digest.mid(start, first_part_len);

    start += first_part_len;
    size_t second_part_len = ((PQC_SLH_DSA_H - PQC_SLH_DSA_H / PQC_SLH_DSA_D) + 8 - 1) / 8;
    ConstBufferView tmpIdxTree = digest.mid(start, second_part_len);

    start += second_part_len;
    size_t third_part_len = (PQC_SLH_DSA_H + 8 * PQC_SLH_DSA_D - 1) / (8 * PQC_SLH_DSA_D);
    ConstBufferView tmpIdxLeaf = digest.mid(start, third_part_len);

    size_t idxTree = Converter::toInteger(tmpIdxTree);
    size_t idxLeaf = Converter::toInteger(tmpIdxLeaf) % (1 << (PQC_SLH_DSA_H / PQC_SLH_DSA_D));

    Address adrs;
    BufferView tree_address = address::tree_address(adrs);
    Converter::toByte(tree_address, idxTree);
    address::setTypeAndClear(adrs, FORS_TREE);
    BufferView keypair_address = address::keypair_address(adrs);
    Converter::toByte(keypair_address, idxLeaf);

    StackBuffer<PQC_SLH_DSA_N> pk_fors;
    fors_pkFromSig(pk_fors, sig_fors, md, PKseed, adrs);

    return ht_verify(pk_fors, sig_ht, PKseed, idxTree, (int)idxLeaf, PKroot);
}


size_t SLHDSAFactory::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_PUBLIC:
        return PQC_SLH_DSA_PUBLIC_KEY_LEN;
    case PQC_LENGTH_PRIVATE:
        return PQC_SLH_DSA_PRIVATE_KEY_LEN;
    case PQC_LENGTH_SIGNATURE:
        return PQC_SLH_DSA_SIGNATURE_LEN;
    }
    return 0;
}

size_t SLHDSAContext::get_length(uint32_t type) const { return SLHDSAFactory().get_length(type); }

void SLHDSAContext::sign(const ConstBufferView & buffer, const BufferView & signature) const
{
    if (signature.size() != PQC_SLH_DSA_SIGNATURE_LEN)
    {
        throw BadLength();
    }

    ConstBufferView sk(private_key_.private_key, PQC_SLH_DSA_PRIVATE_KEY_LEN);
    auto [SKseed, SKprf, PKseed, PKroot] =
        sk.split((size_t)PQC_SLH_DSA_N, (size_t)PQC_SLH_DSA_N, (size_t)PQC_SLH_DSA_N, (size_t)PQC_SLH_DSA_N);
    auto [R, sig_fors, sig_ht] = signature.split(
        (size_t)PQC_SLH_DSA_N, (size_t)(PQC_SLH_DSA_K * (1 + PQC_SLH_DSA_A) * PQC_SLH_DSA_N),
        (size_t)((PQC_SLH_DSA_H + PQC_SLH_DSA_D * PQC_SLH_DSA_LEN) * PQC_SLH_DSA_N)
    );

    if (PQC_SLH_DSA_SIGN_RANDOMIZED)
    {
        StackBuffer<PQC_SLH_DSA_N> opt_rand;
        randombytes(opt_rand);
        function_PRFmsg(SKprf, opt_rand, buffer, R);
    }
    else
    {
        function_PRFmsg(SKprf, PKseed, buffer, R);
    }

    StackBuffer<PQC_SLH_DSA_M> digest;
    function_Hmsg(R, PKseed, PKroot, buffer, digest);

    size_t start = 0;
    size_t first_part_len = (PQC_SLH_DSA_K * PQC_SLH_DSA_A + 8 - 1) / 8;
    ConstBufferView md = digest.mid(start, first_part_len);

    start += first_part_len;
    size_t second_part_len = ((PQC_SLH_DSA_H - PQC_SLH_DSA_H / PQC_SLH_DSA_D) + 8 - 1) / 8;
    ConstBufferView tmpIdxTree = digest.mid(start, second_part_len);

    start += second_part_len;
    size_t third_part_len = (PQC_SLH_DSA_H + 8 * PQC_SLH_DSA_D - 1) / (8 * PQC_SLH_DSA_D);
    ConstBufferView tmpIdxLeaf = digest.mid(start, third_part_len);

    size_t idxTree = Converter::toInteger(tmpIdxTree);
    size_t idxLeaf = Converter::toInteger(tmpIdxLeaf) % (1 << (PQC_SLH_DSA_H / PQC_SLH_DSA_D));

    Address adrs;
    BufferView tree_address = address::tree_address(adrs);
    Converter::toByte(tree_address, idxTree);
    address::setTypeAndClear(adrs, FORS_TREE);
    BufferView keypair_address = address::keypair_address(adrs);
    Converter::toByte(keypair_address, idxLeaf);

    fors_sign(sig_fors, md, SKseed, PKseed, adrs);

    StackBuffer<PQC_SLH_DSA_N> pk_fors;
    fors_pkFromSig(pk_fors, sig_fors, md, PKseed, adrs);

    ht_sign(sig_ht, pk_fors, SKseed, PKseed, idxTree, (int)idxLeaf);
}
