#pragma once

#include <optional>

#include <buffer.h>
#include <pqc/common.h>

namespace slh_dsa
{

void PQC_API slh_sign_internal(
    const ConstBufferView & msg, const ConstBufferView & sk, const ConstBufferView & optrand,
    const BufferView & signature, size_t mode, const std::optional<ConstBufferView> & context = std::nullopt
);

bool PQC_API slh_verify_internal(
    const ConstBufferView & msg, const ConstBufferView & pk, const ConstBufferView & signature, size_t mode,
    const std::optional<ConstBufferView> & context = std::nullopt
);

} // namespace slh_dsa
