#include "slh-dsa.h"
#include <buffer.h>
#include <rng/random_generator.h>

#include "address.h"
#include "converter.h"
#include "fors.h"
#include "hypertree.h"
#include "params.h"
#include "xmss.h"
#include <cstdio>

using namespace slh_dsa;

template <size_t MODE> SLHDSAFactory<MODE>::SLHDSAFactory() {}

template <size_t MODE> uint32_t SLHDSAFactory<MODE>::cipher_id() const { return ParameterSets[MODE].CIPHER_ID; }

template <size_t MODE> void SLHDSAContext<MODE>::generate_keypair()
{
    auto [public_key, private_key] =
        allocate_keys(ParameterSets[MODE].PUBLIC_KEY_LEN, ParameterSets[MODE].PRIVATE_KEY_LEN);

    get_random_generator().random_bytes(private_key.mid(0, 3 * ParameterSets[MODE].N));

    Address addr;
    BufferView layer_addr = address::layer_address(addr);
    Converter::toByte(layer_addr, ParameterSets[MODE].D - 1);

    BufferView pkroot = private_key.mid(3 * ParameterSets[MODE].N, ParameterSets[MODE].N);
    ConstBufferView pkseed = private_key.mid(2 * ParameterSets[MODE].N, ParameterSets[MODE].N);
    ConstBufferView skseed = private_key.mid(0, ParameterSets[MODE].N);
    xmss_node(pkroot, skseed, 0, ParameterSets[MODE].H_PRIME, pkseed, addr, MODE);

    public_key.store(private_key.mid(2 * ParameterSets[MODE].N, 2 * ParameterSets[MODE].N));
}

template <size_t MODE>
bool SLHDSAContext<MODE>::verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const
{
    if (signature.size() != ParameterSets[MODE].SIGNATURE_LEN)
    {
        throw BadLength();
    }

    auto [PKseed, PKroot] = public_key().split(ParameterSets[MODE].N, ParameterSets[MODE].N);
    auto [R, sig_fors, sig_ht] = signature.split(
        ParameterSets[MODE].N, (size_t)(ParameterSets[MODE].K * (1 + ParameterSets[MODE].A) * ParameterSets[MODE].N),
        (size_t)((ParameterSets[MODE].H + ParameterSets[MODE].D * ParameterSets[MODE].LEN) * ParameterSets[MODE].N)
    );

    StackBuffer<ParameterSets[MODE].M> digest;
    function_Hmsg(R, PKseed, PKroot, buffer, digest);

    size_t start = 0;
    size_t first_part_len = (ParameterSets[MODE].K * ParameterSets[MODE].A + 8 - 1) / 8;
    ConstBufferView md = digest.mid(start, first_part_len);

    start += first_part_len;
    size_t second_part_len = ((ParameterSets[MODE].H - ParameterSets[MODE].H / ParameterSets[MODE].D) + 8 - 1) / 8;
    ConstBufferView tmpIdxTree = digest.mid(start, second_part_len);

    start += second_part_len;
    size_t third_part_len = (ParameterSets[MODE].H + 8 * ParameterSets[MODE].D - 1) / (8 * ParameterSets[MODE].D);
    ConstBufferView tmpIdxLeaf = digest.mid(start, third_part_len);

    size_t idxTree = Converter::toInteger(tmpIdxTree);
    constexpr size_t shift = ParameterSets[MODE].H - ParameterSets[MODE].H / ParameterSets[MODE].D;
    if constexpr (shift < 8 * sizeof(size_t))
        idxTree = idxTree % ((size_t)1 << shift);
    size_t idxLeaf = Converter::toInteger(tmpIdxLeaf) % ((size_t)1 << (ParameterSets[MODE].H / ParameterSets[MODE].D));

    Address adrs;
    BufferView tree_address = address::tree_address(adrs);
    Converter::toByte(tree_address, idxTree);
    address::setTypeAndClear(adrs, FORS_TREE);
    BufferView keypair_address = address::keypair_address(adrs);
    Converter::toByte(keypair_address, idxLeaf);

    StackBuffer<ParameterSets[MODE].N> pk_fors;
    fors_pkFromSig(pk_fors, sig_fors, md, PKseed, adrs, MODE);

    return ht_verify(pk_fors, sig_ht, PKseed, idxTree, idxLeaf, PKroot, MODE);
}

template <size_t MODE> size_t SLHDSAFactory<MODE>::get_length(uint32_t type) const
{
    switch (type)
    {
    case PQC_LENGTH_PUBLIC:
        return ParameterSets[MODE].PUBLIC_KEY_LEN;
    case PQC_LENGTH_PRIVATE:
        return ParameterSets[MODE].PRIVATE_KEY_LEN;
    case PQC_LENGTH_SIGNATURE:
        return ParameterSets[MODE].SIGNATURE_LEN;
    }
    return 0;
}

template <size_t MODE>
SLHDSAContext<MODE>::SLHDSAContext(const ConstBufferView & public_key, const ConstBufferView & private_key)
    : SignatureContext(public_key, private_key)
{
}

template <size_t MODE> size_t SLHDSAContext<MODE>::get_length(uint32_t type) const
{
    return SLHDSAFactory<MODE>().get_length(type);
}

template <size_t MODE>
void SLHDSAContext<MODE>::create_signature(const ConstBufferView & buffer, const BufferView & signature)
{
    if (signature.size() != ParameterSets[MODE].SIGNATURE_LEN)
    {
        throw BadLength();
    }

    auto [SKseed, SKprf, PKseed, PKroot] =
        private_key().split(ParameterSets[MODE].N, ParameterSets[MODE].N, ParameterSets[MODE].N, ParameterSets[MODE].N);
    auto [R, sig_fors, sig_ht] = signature.split(
        ParameterSets[MODE].N, (size_t)(ParameterSets[MODE].K * (1 + ParameterSets[MODE].A) * ParameterSets[MODE].N),
        (size_t)((ParameterSets[MODE].H + ParameterSets[MODE].D * ParameterSets[MODE].LEN) * ParameterSets[MODE].N)
    );

    if (PQC_SLH_DSA_SIGN_RANDOMIZED)
    {
        StackBuffer<ParameterSets[MODE].N> opt_rand;
        get_random_generator().random_bytes(opt_rand);
        function_PRFmsg(SKprf, opt_rand, buffer, R);
    }
    else
    {
        function_PRFmsg(SKprf, PKseed, buffer, R);
    }

    StackBuffer<ParameterSets[MODE].M> digest;
    function_Hmsg(R, PKseed, PKroot, buffer, digest);

    size_t start = 0;
    size_t first_part_len = (ParameterSets[MODE].K * ParameterSets[MODE].A + 8 - 1) / 8;
    ConstBufferView md = digest.mid(start, first_part_len);

    start += first_part_len;
    size_t second_part_len = ((ParameterSets[MODE].H - ParameterSets[MODE].H / ParameterSets[MODE].D) + 8 - 1) / 8;
    ConstBufferView tmpIdxTree = digest.mid(start, second_part_len);

    start += second_part_len;
    size_t third_part_len = (ParameterSets[MODE].H + 8 * ParameterSets[MODE].D - 1) / (8 * ParameterSets[MODE].D);
    ConstBufferView tmpIdxLeaf = digest.mid(start, third_part_len);

    size_t idxTree = Converter::toInteger(tmpIdxTree);
    constexpr size_t shift = ParameterSets[MODE].H - ParameterSets[MODE].H / ParameterSets[MODE].D;
    if constexpr (shift < 8 * sizeof(size_t))
        idxTree = idxTree % ((size_t)1 << shift);
    size_t idxLeaf = Converter::toInteger(tmpIdxLeaf) % ((size_t)1 << (ParameterSets[MODE].H / ParameterSets[MODE].D));

    Address adrs;
    BufferView tree_address = address::tree_address(adrs);
    Converter::toByte(tree_address, idxTree);
    address::setTypeAndClear(adrs, FORS_TREE);
    BufferView keypair_address = address::keypair_address(adrs);
    Converter::toByte(keypair_address, idxLeaf);

    fors_sign(sig_fors, md, SKseed, PKseed, adrs, MODE);

    StackBuffer<ParameterSets[MODE].N> pk_fors;
    fors_pkFromSig(pk_fors, sig_fors, md, PKseed, adrs, MODE);

    ht_sign(sig_ht, pk_fors, SKseed, PKseed, idxTree, idxLeaf, MODE);
}

template class SLHDSAFactory<SLH_DSA_SHAKE_128S>;
template class SLHDSAFactory<SLH_DSA_SHAKE_128F>;
template class SLHDSAFactory<SLH_DSA_SHAKE_192S>;
template class SLHDSAFactory<SLH_DSA_SHAKE_192F>;
template class SLHDSAFactory<SLH_DSA_SHAKE_256S>;
template class SLHDSAFactory<SLH_DSA_SHAKE_256F>;
