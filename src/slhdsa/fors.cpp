#include "fors.h"

#include <cassert>
#include <core.h>

#include "address.h"
#include "converter.h"
#include "params.h"

namespace slh_dsa
{

// Algorithm 13: Generate a FORS private-key value
void fors_SKgen(
    const BufferView & sk, const ConstBufferView & skseed, const ConstBufferView & pkseed, const BufferView & addr,
    size_t idx, size_t mode
)
{
    assert(sk.size() == ParameterSets[mode].N);
    assert(skseed.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    Address skAddr;
    skAddr.store(addr);
    address::setTypeAndClear(skAddr, FORS_PRF);
    BufferView keypair_address = address::keypair_address(skAddr);
    keypair_address.store(address::keypair_address(addr));
    BufferView tree_index = address::tree_index(skAddr);
    Converter::toByte(tree_index, idx);

    function_PRF(pkseed, skAddr, skseed, sk);
}

// Algorithm 14: Compute the root of a Merkle subtree of FORS public values
void fors_node(
    const BufferView & node, const ConstBufferView & skseed, const ConstBufferView & pkseed, size_t i, size_t z,
    const BufferView & addr, size_t mode
)
{
    assert(node.size() == ParameterSets[mode].N);
    assert(skseed.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    if (z > ParameterSets[mode].A || i >= (ParameterSets[mode].K * ((size_t)1 << (ParameterSets[mode].A - z))))
        throw InternalError();

    if (z == 0)
    {
        std::vector<uint8_t> sk_data(ParameterSets[mode].N);
        BufferView sk(sk_data);
        fors_SKgen(sk, skseed, pkseed, addr, i, mode);

        BufferView tree_height = address::tree_height(addr);
        Converter::toByte(tree_height, 0);
        BufferView tree_index = address::tree_index(addr);
        Converter::toByte(tree_index, i);

        function_F(pkseed, addr, sk, node);
    }
    else
    {
        std::vector<uint8_t> node_data(ParameterSets[mode].N * 2);
        BufferView lr_nodes(node_data);

        fors_node(lr_nodes.mid(0, ParameterSets[mode].N), skseed, pkseed, 2 * i, z - 1, addr, mode);
        fors_node(
            lr_nodes.mid(ParameterSets[mode].N, ParameterSets[mode].N), skseed, pkseed, 2 * i + 1, z - 1, addr, mode
        );

        BufferView tree_height = address::tree_height(addr);
        Converter::toByte(tree_height, z);
        BufferView tree_index = address::tree_index(addr);
        Converter::toByte(tree_index, i);

        function_F(pkseed, addr, lr_nodes, node);
    }
}

// Algorithm 15: Generate a FORS signature
void fors_sign(
    const BufferView & sig_fors, const ConstBufferView & md, const ConstBufferView & skseed,
    const ConstBufferView & pkseed, const BufferView & addr, size_t mode
)
{
    assert(sig_fors.size() == ParameterSets[mode].K * (1 + ParameterSets[mode].A) * ParameterSets[mode].N);
    assert(md.size() == ParameterSets[mode].MSG_DIGEST_LEN);
    assert(skseed.size() == ParameterSets[mode].N);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    std::vector<int> indices(ParameterSets[mode].K);
    Converter::base_2b(indices.data(), indices.size(), md, (int)ParameterSets[mode].A);

    for (size_t i = 0; i < ParameterSets[mode].K; ++i)
    {
        BufferView ski = sig_fors.mid(i * ((ParameterSets[mode].A + 1) * ParameterSets[mode].N), ParameterSets[mode].N);
        fors_SKgen(ski, skseed, pkseed, addr, i * ((size_t)1 << ParameterSets[mode].A) + indices[i], mode);

        for (size_t j = 0; j < ParameterSets[mode].A; ++j)
        {
            int s = (indices[i] / (int)(1 << j)) ^ 1;
            BufferView authj = sig_fors.mid(
                (i * (ParameterSets[mode].A + 1) * ParameterSets[mode].N) + ParameterSets[mode].N +
                    j * ParameterSets[mode].N,
                ParameterSets[mode].N
            );
            fors_node(authj, skseed, pkseed, i * ((size_t)1 << (ParameterSets[mode].A - j)) + s, j, addr, mode);
        }
    }
}

// Algorithm 16: Compute a FORS public key from a FORS signature
void fors_pkFromSig(
    const BufferView & pk, const ConstBufferView & sig_fors, const ConstBufferView & md, const ConstBufferView & pkseed,
    const BufferView & addr, size_t mode
)
{
    assert(pk.size() == ParameterSets[mode].N);
    assert(sig_fors.size() == ParameterSets[mode].K * (1 + ParameterSets[mode].A) * ParameterSets[mode].N);
    assert(md.size() == ParameterSets[mode].MSG_DIGEST_LEN);
    assert(pkseed.size() == ParameterSets[mode].N);
    assert(addr.size() == ADDRESS_SIZE);

    std::vector<int> indices(ParameterSets[mode].K);
    Converter::base_2b(indices.data(), indices.size(), md, (int)ParameterSets[mode].A);

    BufferView tree_height = address::tree_height(addr);
    BufferView tree_index = address::tree_index(addr);

    std::vector<uint8_t> v_root(ParameterSets[mode].K * ParameterSets[mode].N);
    BufferView root(v_root);

    std::vector<uint8_t> v_node0(ParameterSets[mode].N);
    BufferView node0(v_node0);

    for (size_t i = 0; i < ParameterSets[mode].K; ++i)
    {
        ConstBufferView ski =
            sig_fors.mid(i * ((ParameterSets[mode].A + 1) * ParameterSets[mode].N), ParameterSets[mode].N);
        Converter::toByte(tree_height, 0);
        Converter::toByte(tree_index, i * ((size_t)1 << ParameterSets[mode].A) + indices[i]);

        function_F(pkseed, addr, ski, node0);

        for (size_t j = 0; j < ParameterSets[mode].A; ++j)
        {
            ConstBufferView authj = sig_fors.mid(
                (i * (ParameterSets[mode].A + 1) * ParameterSets[mode].N) + ParameterSets[mode].N +
                    j * ParameterSets[mode].N,
                ParameterSets[mode].N
            );
            Converter::toByte(tree_height, j + 1);

            if ((indices[i] / (int)(1 << j)) % 2 == 0)
            {
                Converter::toByte(tree_index, Converter::toInteger(tree_index) / 2);
                function_H(pkseed, addr, node0, authj, node0);
            }
            else
            {
                Converter::toByte(tree_index, (Converter::toInteger(tree_index) - 1) / 2);
                function_H(pkseed, addr, authj, node0, node0);
            }
        }
        root.mid(i * ParameterSets[mode].N, ParameterSets[mode].N).store(node0);
    }

    Address forspkADRS;
    forspkADRS.store(addr);
    address::setTypeAndClear(forspkADRS, FORS_ROOTS);
    address::keypair_address(forspkADRS).store(address::keypair_address(addr));
    function_Tl(pkseed, forspkADRS, root, pk);
}

} // namespace slh_dsa
