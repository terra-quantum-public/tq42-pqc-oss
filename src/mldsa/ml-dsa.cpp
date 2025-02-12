#include "ml-dsa.h"
#include "mldsa_internal.h"
#include <rng/random_generator.h>

using namespace mldsa;

template <size_t MODE> MLDSAFactory<MODE>::MLDSAFactory() {}

template <size_t MODE> uint32_t MLDSAFactory<MODE>::cipher_id() const { return ParameterSets[MODE].CIPHER_ID; }

template <size_t MODE> void MLDSAContext<MODE>::generate_keypair()
{
    auto [public_key, private_key] =
        allocate_keys(ParameterSets[MODE].PUBLIC_KEY_LEN, ParameterSets[MODE].PRIVATE_KEY_LEN);

    StackBuffer<SEEDBYTES> seed;
    get_random_generator().random_bytes(seed); // get seed
    if constexpr (MODE == MODE_44)
        mldsa_keygen_internal_44(public_key, private_key, seed, MODE);
    else if constexpr (MODE == MODE_65)
        mldsa_keygen_internal_65(public_key, private_key, seed, MODE);
    else if constexpr (MODE == MODE_87)
        mldsa_keygen_internal_87(public_key, private_key, seed, MODE);
}


template <size_t MODE>
bool MLDSAContext<MODE>::verify_signature(const ConstBufferView buffer, const ConstBufferView signature) const
{
    if (signature.size() != ParameterSets[MODE].SIGNATURE_LEN)
    {
        throw BadLength();
    }

    if constexpr (MODE == MODE_44)
        return mldsa_verify_internal_44(buffer, public_key(), signature, MODE, context.mid(0, context_len));
    else if constexpr (MODE == MODE_65)
        return mldsa_verify_internal_65(buffer, public_key(), signature, MODE, context.mid(0, context_len));
    else if constexpr (MODE == MODE_87)
        return mldsa_verify_internal_87(buffer, public_key(), signature, MODE, context.mid(0, context_len));
    else
        return false;
}


template <size_t MODE> size_t MLDSAFactory<MODE>::get_length(uint32_t type) const
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

template <size_t MODE> size_t MLDSAContext<MODE>::get_length(uint32_t type) const
{
    return MLDSAFactory<MODE>().get_length(type);
}

template <size_t MODE>
MLDSAContext<MODE>::MLDSAContext(const ConstBufferView & public_key, const ConstBufferView & private_key)
    : SignatureContext(public_key, private_key), context_len(0)
{
}

template <size_t MODE> void MLDSAContext<MODE>::set_iv(const ConstBufferView & iv)
{
    if (iv.size() > MAX_CONTEXT_LEN)
    {
        throw BadLength();
    }
    context_len = iv.size();
    context.mid(0, context_len).store(iv);
}

template <size_t MODE>
void MLDSAContext<MODE>::create_signature(const ConstBufferView & buffer, const BufferView & signature)
{
    if (signature.size() != ParameterSets[MODE].SIGNATURE_LEN)
    {
        throw BadLength();
    }

    StackBuffer<SEEDBYTES> optrand;
    get_random_generator().random_bytes(optrand);

    if constexpr (MODE == MODE_44)
        mldsa_sign_internal_44(buffer, private_key(), optrand, signature, MODE, context.mid(0, context_len));
    else if constexpr (MODE == MODE_65)
        mldsa_sign_internal_65(buffer, private_key(), optrand, signature, MODE, context.mid(0, context_len));
    else if constexpr (MODE == MODE_87)
        mldsa_sign_internal_87(buffer, private_key(), optrand, signature, MODE, context.mid(0, context_len));
}

template class MLDSAFactory<MODE_44>;
template class MLDSAFactory<MODE_65>;
template class MLDSAFactory<MODE_87>;
