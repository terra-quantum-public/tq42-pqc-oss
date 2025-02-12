#include "slhdsa_internal.h"

#include <cassert>
#include <core.h>

#include "address.h"
#include "converter.h"
#include "fors.h"
#include "hypertree.h"
#include "params.h"


namespace slh_dsa
{

void PQC_API slh_sign_internal(
    const ConstBufferView & msg, const ConstBufferView & sk, const ConstBufferView & optrand,
    const BufferView & signature, size_t mode, const std::optional<ConstBufferView> & context
)
{
    assert(sk.size() == ParameterSets[mode].PRIVATE_KEY_LEN);
    assert(optrand.size() == ParameterSets[mode].N);
    assert(signature.size() == ParameterSets[mode].SIGNATURE_LEN);

    auto [SKseed, SKprf, PKseed, PKroot] =
        sk.split(ParameterSets[mode].N, ParameterSets[mode].N, ParameterSets[mode].N, ParameterSets[mode].N);
    auto [R, sig_fors, sig_ht] = signature.split(
        ParameterSets[mode].N, (size_t)(ParameterSets[mode].K * (1 + ParameterSets[mode].A) * ParameterSets[mode].N),
        (size_t)((ParameterSets[mode].H + ParameterSets[mode].D * ParameterSets[mode].LEN) * ParameterSets[mode].N)
    );

    if (context)
    {
        StackBuffer<2> header;
        BufferView sign_type = header.mid(0, 1);
        Converter::toByte(sign_type, 0);
        BufferView ctx_len_view = header.mid(1, 1);
        Converter::toByte(ctx_len_view, context.value().size());
        function_PRFmsg_ctx(SKprf, optrand, header, context.value(), msg, R);
    }
    else
    {
        function_PRFmsg(SKprf, optrand, msg, R);
    }

    std::vector<uint8_t> digest_vector(ParameterSets[mode].M);
    BufferView digest(digest_vector);
    if (context)
    {
        StackBuffer<2> header;
        BufferView sign_type = header.mid(0, 1);
        Converter::toByte(sign_type, 0);
        BufferView ctx_len_view = header.mid(1, 1);
        Converter::toByte(ctx_len_view, context.value().size());
        function_Hmsg_ctx(R, PKseed, PKroot, header, context.value(), msg, digest);
    }
    else
    {
        function_Hmsg(R, PKseed, PKroot, msg, digest);
    }

    size_t start = 0;
    size_t first_part_len = (ParameterSets[mode].K * ParameterSets[mode].A + 8 - 1) / 8;
    ConstBufferView md = digest.mid(start, first_part_len);

    start += first_part_len;
    size_t second_part_len = ((ParameterSets[mode].H - ParameterSets[mode].H / ParameterSets[mode].D) + 8 - 1) / 8;
    ConstBufferView tmpIdxTree = digest.mid(start, second_part_len);

    start += second_part_len;
    size_t third_part_len = (ParameterSets[mode].H + 8 * ParameterSets[mode].D - 1) / (8 * ParameterSets[mode].D);
    ConstBufferView tmpIdxLeaf = digest.mid(start, third_part_len);

    size_t idxTree = Converter::toInteger(tmpIdxTree);
    const size_t shift = ParameterSets[mode].H - ParameterSets[mode].H / ParameterSets[mode].D;
    if (shift < 8 * sizeof(size_t))
        idxTree = idxTree % ((size_t)1 << shift);
    size_t idxLeaf = Converter::toInteger(tmpIdxLeaf) % ((size_t)1 << (ParameterSets[mode].H / ParameterSets[mode].D));

    Address adrs;
    BufferView tree_address = address::tree_address(adrs);
    Converter::toByte(tree_address, idxTree);
    address::setTypeAndClear(adrs, FORS_TREE);
    BufferView keypair_address = address::keypair_address(adrs);
    Converter::toByte(keypair_address, idxLeaf);

    fors_sign(sig_fors, md, SKseed, PKseed, adrs, mode);

    std::vector<uint8_t> pk_fors_vector(ParameterSets[mode].N);
    BufferView pk_fors(pk_fors_vector);
    fors_pkFromSig(pk_fors, sig_fors, md, PKseed, adrs, mode);

    ht_sign(sig_ht, pk_fors, SKseed, PKseed, idxTree, idxLeaf, mode);
}

bool PQC_API slh_verify_internal(
    const ConstBufferView & msg, const ConstBufferView & pk, const ConstBufferView & signature, size_t mode,
    const std::optional<ConstBufferView> & context
)
{
    if (signature.size() != ParameterSets[mode].SIGNATURE_LEN || pk.size() != ParameterSets[mode].PUBLIC_KEY_LEN)
    {
        return false;
    }

    auto [PKseed, PKroot] = pk.split(ParameterSets[mode].N, ParameterSets[mode].N);
    auto [R, sig_fors, sig_ht] = signature.split(
        ParameterSets[mode].N, (size_t)(ParameterSets[mode].K * (1 + ParameterSets[mode].A) * ParameterSets[mode].N),
        (size_t)((ParameterSets[mode].H + ParameterSets[mode].D * ParameterSets[mode].LEN) * ParameterSets[mode].N)
    );

    std::vector<uint8_t> digest_vector(ParameterSets[mode].M);
    BufferView digest(digest_vector);
    if (context)
    {
        StackBuffer<2> header;
        BufferView sign_type = header.mid(0, 1);
        Converter::toByte(sign_type, 0);
        BufferView ctx_len_view = header.mid(1, 1);
        Converter::toByte(ctx_len_view, context.value().size());
        function_Hmsg_ctx(R, PKseed, PKroot, header, context.value(), msg, digest);
    }
    else
    {
        function_Hmsg(R, PKseed, PKroot, msg, digest);
    }

    size_t start = 0;
    size_t first_part_len = (ParameterSets[mode].K * ParameterSets[mode].A + 8 - 1) / 8;
    ConstBufferView md = digest.mid(start, first_part_len);

    start += first_part_len;
    size_t second_part_len = ((ParameterSets[mode].H - ParameterSets[mode].H / ParameterSets[mode].D) + 8 - 1) / 8;
    ConstBufferView tmpIdxTree = digest.mid(start, second_part_len);

    start += second_part_len;
    size_t third_part_len = (ParameterSets[mode].H + 8 * ParameterSets[mode].D - 1) / (8 * ParameterSets[mode].D);
    ConstBufferView tmpIdxLeaf = digest.mid(start, third_part_len);

    size_t idxTree = Converter::toInteger(tmpIdxTree);
    const size_t shift = ParameterSets[mode].H - ParameterSets[mode].H / ParameterSets[mode].D;
    if (shift < 8 * sizeof(size_t))
        idxTree = idxTree % ((size_t)1 << shift);
    size_t idxLeaf = Converter::toInteger(tmpIdxLeaf) % ((size_t)1 << (ParameterSets[mode].H / ParameterSets[mode].D));

    Address adrs;
    BufferView tree_address = address::tree_address(adrs);
    Converter::toByte(tree_address, idxTree);
    address::setTypeAndClear(adrs, FORS_TREE);
    BufferView keypair_address = address::keypair_address(adrs);
    Converter::toByte(keypair_address, idxLeaf);

    std::vector<uint8_t> pk_fors_vector(ParameterSets[mode].N);
    BufferView pk_fors(pk_fors_vector);
    fors_pkFromSig(pk_fors, sig_fors, md, PKseed, adrs, mode);

    return ht_verify(pk_fors, sig_ht, PKseed, idxTree, idxLeaf, PKroot, mode);
}

} // namespace slh_dsa
