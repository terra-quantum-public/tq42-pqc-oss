#pragma once

#include <optional>

#include <buffer.h>
#include <pqc/common.h>

namespace mldsa
{

void PQC_API
mldsa_keygen_internal_44(const BufferView & pk, const BufferView & sk, const ConstBufferView & optrand, size_t mode);

void PQC_API mldsa_sign_internal_44(
    const ConstBufferView & msg, const ConstBufferView & sk, const ConstBufferView & optrand,
    const BufferView & signature, size_t mode, const std::optional<ConstBufferView> & context = std::nullopt
);

bool PQC_API mldsa_verify_internal_44(
    const ConstBufferView & msg, const ConstBufferView & pk, const ConstBufferView & signature, size_t mode,
    const std::optional<ConstBufferView> & context = std::nullopt
);

void PQC_API
mldsa_keygen_internal_65(const BufferView & pk, const BufferView & sk, const ConstBufferView & optrand, size_t mode);

void PQC_API mldsa_sign_internal_65(
    const ConstBufferView & msg, const ConstBufferView & sk, const ConstBufferView & optrand,
    const BufferView & signature, size_t mode, const std::optional<ConstBufferView> & context = std::nullopt
);

bool PQC_API mldsa_verify_internal_65(
    const ConstBufferView & msg, const ConstBufferView & pk, const ConstBufferView & signature, size_t mode,
    const std::optional<ConstBufferView> & context = std::nullopt
);

void PQC_API
mldsa_keygen_internal_87(const BufferView & pk, const BufferView & sk, const ConstBufferView & optrand, size_t mode);

void PQC_API mldsa_sign_internal_87(
    const ConstBufferView & msg, const ConstBufferView & sk, const ConstBufferView & optrand,
    const BufferView & signature, size_t mode, const std::optional<ConstBufferView> & context = std::nullopt
);

bool PQC_API mldsa_verify_internal_87(
    const ConstBufferView & msg, const ConstBufferView & pk, const ConstBufferView & signature, size_t mode,
    const std::optional<ConstBufferView> & context = std::nullopt
);

} // namespace mldsa
