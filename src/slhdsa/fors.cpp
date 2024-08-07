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
    int idx
)
{
    assert(sk.size() == PQC_SLH_DSA_N);
    assert(skseed.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    Address skAddr;
    skAddr.store(addr);
    address::setTypeAndClear(skAddr, FORS_PRF);
    BufferView keypair_address = address::keypair_address(skAddr);
    keypair_address.store(address::keypair_address(addr));
    BufferView tree_index = address::tree_index(skAddr);
    Converter::toByte(tree_index, idx);

    StackBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N> joined; // PK.seed || ADRS || SK.seed
    joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
    joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE).store(skAddr);
    joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N).store(skseed);
    function_PRF(joined, sk);
}

// Algorithm 14: Compute the root of a Merkle subtree of FORS public values
void fors_node(
    const BufferView & node, const ConstBufferView & skseed, const ConstBufferView & pkseed, int i, int z,
    const BufferView & addr
)
{
    assert(node.size() == PQC_SLH_DSA_N);
    assert(skseed.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    if (z > PQC_SLH_DSA_A || i >= (PQC_SLH_DSA_K * (1 << (PQC_SLH_DSA_A - z))))
        throw InternalError();

    if (z == 0)
    {
        HeapBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N> joined; // PKseed || ADDR || sk

        BufferView sk = joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N);
        fors_SKgen(sk, skseed, pkseed, addr, i);

        BufferView tree_height = address::tree_height(addr);
        Converter::toByte(tree_height, 0);
        BufferView tree_index = address::tree_index(addr);
        Converter::toByte(tree_index, i);

        joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
        joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE).store(addr);

        function_F(joined, node);
    }
    else
    {
        HeapBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N * 2> joined; // pkseed || ADRS || lnode || rnode

        fors_node(joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N), skseed, pkseed, 2 * i, z - 1, addr);
        fors_node(
            joined.mid(PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N, PQC_SLH_DSA_N), skseed, pkseed, 2 * i + 1, z - 1,
            addr
        );

        BufferView tree_height = address::tree_height(addr);
        Converter::toByte(tree_height, z);
        BufferView tree_index = address::tree_index(addr);
        Converter::toByte(tree_index, i);

        joined.mid(0, PQC_SLH_DSA_N).store(pkseed);
        joined.mid(PQC_SLH_DSA_N, ADDRESS_SIZE).store(addr);

        function_F(joined, node);
    }
}

// Algorithm 15: Generate a FORS signature
void fors_sign(
    const BufferView & sig_fors, const ConstBufferView & md, const ConstBufferView & skseed,
    const ConstBufferView & pkseed, const BufferView & addr
)
{
    assert(sig_fors.size() == PQC_SLH_DSA_K * (1 + PQC_SLH_DSA_A) * PQC_SLH_DSA_N);
    assert(md.size() == PQC_SLH_DSA_MSG_DIGEST_LEN);
    assert(skseed.size() == PQC_SLH_DSA_N);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    std::array<int, PQC_SLH_DSA_K> indices;
    Converter::base_2b(indices.data(), indices.size(), md, PQC_SLH_DSA_A);

    for (int i = 0; i < PQC_SLH_DSA_K; ++i)
    {
        BufferView ski = sig_fors.mid(i * ((PQC_SLH_DSA_A + 1) * PQC_SLH_DSA_N), PQC_SLH_DSA_N);
        fors_SKgen(ski, skseed, pkseed, addr, i * (1 << PQC_SLH_DSA_A) + indices[i]);

        for (int j = 0; j < PQC_SLH_DSA_A; j++)
        {
            int s = (indices[i] / (int)(1 << j)) ^ 1;
            BufferView authj = sig_fors.mid(
                (i * (PQC_SLH_DSA_A + 1) * PQC_SLH_DSA_N) + PQC_SLH_DSA_N + j * PQC_SLH_DSA_N, PQC_SLH_DSA_N
            );
            fors_node(authj, skseed, pkseed, i * (1 << (PQC_SLH_DSA_A - j)) + s, j, addr);
        }
    }
}

// Algorithm 16: Compute a FORS public key from a FORS signature
void fors_pkFromSig(
    const BufferView & pk, const ConstBufferView & sig_fors, const ConstBufferView & md, const ConstBufferView & pkseed,
    const BufferView & addr
)
{
    assert(pk.size() == PQC_SLH_DSA_N);
    assert(sig_fors.size() == PQC_SLH_DSA_K * (1 + PQC_SLH_DSA_A) * PQC_SLH_DSA_N);
    assert(md.size() == PQC_SLH_DSA_MSG_DIGEST_LEN);
    assert(pkseed.size() == PQC_SLH_DSA_N);
    assert(addr.size() == ADDRESS_SIZE);

    std::array<int, PQC_SLH_DSA_K> indices;
    Converter::base_2b(indices.data(), indices.size(), md, PQC_SLH_DSA_A);

    BufferView tree_height = address::tree_height(addr);
    BufferView tree_index = address::tree_index(addr);

    HeapBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_K * PQC_SLH_DSA_N>
        joined_for_Tk; // PK.seed || forspkADRS || root
    joined_for_Tk.mid(0, PQC_SLH_DSA_N).store(pkseed);

    HeapBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N + PQC_SLH_DSA_N>
        joined_for_H; // PK.seed || ADRS || node[0] || auth[j]
    joined_for_H.mid(0, PQC_SLH_DSA_N).store(pkseed);
    HeapBuffer<PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N> joined_for_F; // PK.seed || ADRS || sk
    joined_for_F.mid(0, PQC_SLH_DSA_N).store(pkseed);
    StackBuffer<PQC_SLH_DSA_N> node0;

    for (int i = 0; i < PQC_SLH_DSA_K; ++i)
    {
        ConstBufferView ski = sig_fors.mid(i * ((PQC_SLH_DSA_A + 1) * PQC_SLH_DSA_N), PQC_SLH_DSA_N);
        Converter::toByte(tree_height, 0);
        Converter::toByte(tree_index, i * (1 << PQC_SLH_DSA_A) + indices[i]);

        joined_for_F.mid(PQC_SLH_DSA_N, ADDRESS_SIZE).store(addr);
        joined_for_F.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N).store(ski);
        function_F(joined_for_F, node0);

        for (int j = 0; j < PQC_SLH_DSA_A; ++j)
        {
            ConstBufferView authj = sig_fors.mid(
                (i * (PQC_SLH_DSA_A + 1) * PQC_SLH_DSA_N) + PQC_SLH_DSA_N + j * PQC_SLH_DSA_N, PQC_SLH_DSA_N
            );
            Converter::toByte(tree_height, j + 1);

            if ((indices[i] / (int)(1 << j)) % 2 == 0)
            {
                Converter::toByte(tree_index, Converter::toInteger(tree_index) / 2);
                joined_for_H.mid(PQC_SLH_DSA_N, ADDRESS_SIZE).store(addr);
                joined_for_H.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N).store(node0);
                joined_for_H.mid(PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N, PQC_SLH_DSA_N).store(authj);
                function_H(joined_for_H, node0);
            }
            else
            {
                Converter::toByte(tree_index, (Converter::toInteger(tree_index) - 1) / 2);
                joined_for_H.mid(PQC_SLH_DSA_N, ADDRESS_SIZE).store(addr);
                joined_for_H.mid(PQC_SLH_DSA_N + ADDRESS_SIZE, PQC_SLH_DSA_N).store(authj);
                joined_for_H.mid(PQC_SLH_DSA_N + ADDRESS_SIZE + PQC_SLH_DSA_N, PQC_SLH_DSA_N).store(node0);
                function_H(joined_for_H, node0);
            }
        }
        joined_for_Tk.mid(PQC_SLH_DSA_N + ADDRESS_SIZE + i * PQC_SLH_DSA_N, PQC_SLH_DSA_N).store(node0);
    }

    Address forspkADRS;
    forspkADRS.store(addr);
    address::setTypeAndClear(forspkADRS, FORS_ROOTS);
    address::keypair_address(forspkADRS).store(address::keypair_address(addr));
    joined_for_Tk.mid(PQC_SLH_DSA_N, ADDRESS_SIZE).store(forspkADRS);
    function_Tl(joined_for_Tk, pk);
}

} // namespace slh_dsa
