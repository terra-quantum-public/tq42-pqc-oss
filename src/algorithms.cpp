#include <aes.h>
#include <core.h>
#include <dilithium/dilithium.h>
#include <falcon/falcon_main.h>
#include <mceliece/mceliece.h>
#include <mldsa/ml-dsa.h>
#include <mlkem/kyber.h>
#include <mlkem/ml-kem.h>
#include <slhdsa/slh-dsa.h>

#include <sha3.h>

AlgorithmRegistry::AlgorithmRegistry()
{
    register_factory(std::make_unique<const AESFactory>());
    register_factory(std::make_unique<const DilithiumFactory>());
    register_factory(std::make_unique<const FalconFactory>());
    register_factory(std::make_unique<const McElieceFactory>());
    register_factory(std::make_unique<const KyberFactory<KYBER_512>>());
    register_factory(std::make_unique<const KyberFactory<KYBER_768>>());
    register_factory(std::make_unique<const KyberFactory<KYBER_1024>>());
    register_factory(std::make_unique<const MLKEMFactory<ML_KEM_512>>());
    register_factory(std::make_unique<const MLKEMFactory<ML_KEM_768>>());
    register_factory(std::make_unique<const MLKEMFactory<ML_KEM_1024>>());
    register_factory(std::make_unique<const MLDSAFactory<mldsa::MODE_44>>());
    register_factory(std::make_unique<const MLDSAFactory<mldsa::MODE_65>>());
    register_factory(std::make_unique<const MLDSAFactory<mldsa::MODE_87>>());
    register_factory(std::make_unique<const SHA3Factory>());
    register_factory(std::make_unique<const SLHDSAFactory<SLH_DSA_SHAKE_128S>>());
    register_factory(std::make_unique<const SLHDSAFactory<SLH_DSA_SHAKE_128F>>());
    register_factory(std::make_unique<const SLHDSAFactory<SLH_DSA_SHAKE_192S>>());
    register_factory(std::make_unique<const SLHDSAFactory<SLH_DSA_SHAKE_192F>>());
    register_factory(std::make_unique<const SLHDSAFactory<SLH_DSA_SHAKE_256S>>());
    register_factory(std::make_unique<const SLHDSAFactory<SLH_DSA_SHAKE_256F>>());
}
