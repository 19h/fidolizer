#pragma once

#include "fidolizer/authenticator.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fidolizer {

// One WebAuthn request in, one PublicKeyCredential JSON object out.
//
// Input is {"type":"create"|"get","origin":"https://…","request":{…options…}}.
// `request` is PublicKeyCredential parseCreationOptionsFromJSON /
// parseRequestOptionsFromJSON (base64url byte fields). The caller origin is
// separate because Chrome's requestDetailsJson does not carry it.
// Success is PublicKeyCredential.toJSON(). Failure is
// {"error":{"name":"…","message":"…"}}.
std::string transactWebAuthn(Authenticator& authenticator, std::string_view message);

std::string base64UrlEncode(std::span<const std::uint8_t> data);
std::optional<std::vector<std::uint8_t>> base64UrlDecode(std::string_view text);

}  // namespace fidolizer
