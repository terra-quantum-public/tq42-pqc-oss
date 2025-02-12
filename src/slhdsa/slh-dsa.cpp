#include "slh-dsa.h"
#include <buffer.h>
#include <rng/random_generator.h>

#include "address.h"
#include "converter.h"
#include "params.h"
#include "slhdsa_internal.h"
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

    return slh_dsa::slh_verify_internal(buffer, public_key(), signature, MODE, context.mid(0, context_len));
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
    : SignatureContext(public_key, private_key), context_len(0)
{
}

template <size_t MODE> size_t SLHDSAContext<MODE>::get_length(uint32_t type) const
{
    return SLHDSAFactory<MODE>().get_length(type);
}

template <size_t MODE> void SLHDSAContext<MODE>::set_iv(const ConstBufferView & iv)
{
    if (iv.size() > MAX_CONTEXT_LEN)
    {
        throw BadLength();
    }
    context_len = iv.size();
    context.mid(0, context_len).store(iv);
}

template <size_t MODE>
void SLHDSAContext<MODE>::create_signature(const ConstBufferView & buffer, const BufferView & signature)
{
    if (signature.size() != ParameterSets[MODE].SIGNATURE_LEN)
    {
        throw BadLength();
    }

    if (PQC_SLH_DSA_SIGN_RANDOMIZED)
    {
        StackBuffer<ParameterSets[MODE].N> opt_rand;
        get_random_generator().random_bytes(opt_rand);
        slh_dsa::slh_sign_internal(buffer, private_key(), opt_rand, signature, MODE, context.mid(0, context_len));
    }
    else
    {
        auto sk = private_key();
        ConstBufferView pkseed = sk.mid(2 * ParameterSets[MODE].N, ParameterSets[MODE].N);
        slh_dsa::slh_sign_internal(buffer, sk, pkseed, signature, MODE, context.mid(0, context_len));
    }
}

template class SLHDSAFactory<SLH_DSA_SHAKE_128S>;
template class SLHDSAFactory<SLH_DSA_SHAKE_128F>;
template class SLHDSAFactory<SLH_DSA_SHAKE_192S>;
template class SLHDSAFactory<SLH_DSA_SHAKE_192F>;
template class SLHDSAFactory<SLH_DSA_SHAKE_256S>;
template class SLHDSAFactory<SLH_DSA_SHAKE_256F>;
