#include <aes.h>
#include <core.h>
#include <falcon/falcon_main.h>
#include <mceliece/mceliece.h>
#include <mldsa/dilithium.h>
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
    register_factory(std::make_unique<const KyberFactory>());
    register_factory(std::make_unique<const MLKEMFactory>());
    register_factory(std::make_unique<const MLDSAFactory>());
    register_factory(std::make_unique<const SHA3Factory>());
    register_factory(std::make_unique<const SLHDSAFactory>());
}
