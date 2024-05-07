#include <aes.h>
#include <core.h>
#include <mceliece/mceliece.h>

#include <falcon/falcon_main.h>

#include <sha3.h>

AlgorithmRegistry::AlgorithmRegistry()
{
    register_factory(std::make_unique<const AESFactory>());
    register_factory(std::make_unique<const FalconFactory>());
    register_factory(std::make_unique<const McElieceFactory>());
    register_factory(std::make_unique<const SHA3Factory>());
}
