#include "fidolizer/webauthn.hpp"

#include "fidolizer/cbor.hpp"
#include "fidolizer/crypto.hpp"
#include "fidolizer/json.hpp"
#include "fidolizer/status.hpp"

#include <cstdio>
#include <cstring>
#include <string>

namespace fidolizer {
namespace {

constexpr std::uint8_t kSpkiPrefix[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
};

std::string webauthnError(std::string_view name, std::string_view message) {
  return Json::object({
                           {"error", Json::object({
                                         {"name", Json::str(std::string(name))},
                                         {"message", Json::str(std::string(message))},
                                     })},
                       })
      .dump();
}

std::string statusMessage(std::uint8_t status) {
  if (status == 0x2e) return "no credential on this authenticator matches this account";
  char buf[48];
  std::snprintf(buf, sizeof(buf), "CTAP status 0x%02x", status);
  return buf;
}

const char* statusName(std::uint8_t status) {
  switch (status) {
    case 0x19:
      return "InvalidStateError";
    case 0x26:
      return "NotSupportedError";
    case 0x27:
    case 0x2e:
    case 0x2f:
    case 0x35:
    case 0x36:
      return "NotAllowedError";
    case 0x2d:
      return "AbortError";
    default:
      return "UnknownError";
  }
}

const Json* objectField(const Json& value, std::string_view key) {
  if (value.kind() != Json::Kind::Object) return nullptr;
  return value.find(key);
}

bool parseOrigin(std::string_view in, std::string& canonical, std::string& host) {
  std::string scheme;
  std::string_view rest;
  if (in.starts_with("https://")) {
    scheme = "https";
    rest = in.substr(8);
  } else if (in.starts_with("http://")) {
    scheme = "http";
    rest = in.substr(7);
  } else {
    return false;
  }
  if (rest.empty() || rest.find('/') != std::string_view::npos ||
      rest.find('?') != std::string_view::npos || rest.find('#') != std::string_view::npos ||
      rest.find('@') != std::string_view::npos || rest.find(' ') != std::string_view::npos) {
    return false;
  }
  std::string parsed_host;
  std::string port;
  if (rest.front() == '[') {
    const auto end = rest.find(']');
    if (end == std::string_view::npos || end == 1) return false;
    parsed_host.assign(rest.substr(1, end - 1));
    if (end + 1 < rest.size()) {
      if (rest[end + 1] != ':') return false;
      port.assign(rest.substr(end + 2));
    }
  } else {
    const auto colon = rest.rfind(':');
    if (colon != std::string_view::npos) {
      parsed_host.assign(rest.substr(0, colon));
      port.assign(rest.substr(colon + 1));
    } else {
      parsed_host.assign(rest);
    }
  }
  if (parsed_host.empty()) return false;
  for (char& ch : parsed_host) {
    if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
  }
  if (!port.empty()) {
    if (port.size() > 5 || port.find_first_not_of("0123456789") != std::string::npos) return false;
  }
  if (scheme == "http" && parsed_host != "localhost" && parsed_host != "127.0.0.1" &&
      parsed_host != "::1") {
    return false;
  }
  host = parsed_host;
  const bool v6 = parsed_host.find(':') != std::string::npos;
  canonical = scheme + "://" + (v6 ? "[" + parsed_host + "]" : parsed_host);
  if (!port.empty()) {
    const bool default_port = (scheme == "https" && port == "443") || (scheme == "http" && port == "80");
    if (!default_port) canonical += ":" + port;
  }
  return true;
}

bool rpIdMatches(std::string_view host, std::string_view rp_id) {
  if (host.empty() || rp_id.empty()) return false;
  if (host == rp_id) return true;
  return host.size() > rp_id.size() && host.ends_with(rp_id) &&
         host[host.size() - rp_id.size() - 1] == '.';
}

std::string lower(std::string value) {
  for (char& ch : value) {
    if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
  }
  return value;
}

std::optional<std::vector<std::uint8_t>> b64Field(const Json& object, std::string_view key) {
  const Json* field = objectField(object, key);
  if (field == nullptr || field->kind() != Json::Kind::String) return std::nullopt;
  return base64UrlDecode(field->text());
}

std::string textOr(const Json& object, std::string_view key) {
  const Json* field = objectField(object, key);
  if (field == nullptr || field->kind() != Json::Kind::String) return {};
  return field->text();
}

bool flagFrom(const Json* selection, std::string_view key, bool fallback) {
  if (selection == nullptr) return fallback;
  const Json* field = objectField(*selection, key);
  if (field == nullptr || field->kind() != Json::Kind::String) return fallback;
  const std::string& value = field->text();
  if (value == "required" || value == "preferred") return true;
  if (value == "discouraged") return false;
  return fallback;
}

struct Selection {
  bool rk{false};
  bool uv{false};
};

Selection readSelection(const Json& request, bool is_create) {
  Selection out;
  const Json* selection = is_create ? objectField(request, "authenticatorSelection") : nullptr;
  bool require_rk = false;
  if (selection != nullptr) {
    if (const Json* legacy = objectField(*selection, "requireResidentKey");
        legacy && legacy->kind() == Json::Kind::Bool && legacy->boolean()) {
      require_rk = true;
    }
  }
  if (is_create) {
    out.rk = flagFrom(selection, "residentKey", require_rk);
  }
  const Json* uv_source = is_create ? selection : &request;
  const char* uv_key = is_create ? "userVerification" : "userVerification";
  const bool uv_default = true;
  if (uv_source == nullptr) {
    out.uv = uv_default;
  } else if (const Json* field = objectField(*uv_source, uv_key);
             field && field->kind() == Json::Kind::String) {
    if (field->text() == "discouraged") out.uv = false;
    else out.uv = true;
  } else {
    out.uv = uv_default;
  }
  return out;
}

std::vector<std::uint8_t> callCtap(Authenticator& authenticator, std::uint8_t command, const Cbor& body) {
  auto encoded = body.encode();
  std::vector<std::uint8_t> payload;
  payload.reserve(1 + encoded.size());
  payload.push_back(command);
  payload.insert(payload.end(), encoded.begin(), encoded.end());
  NullKeepalive io;
  return authenticator.cbor(payload, io);
}

Cbor credentialDescriptor(const std::vector<std::uint8_t>& id) {
  return Cbor::textMap({
      {"id", Cbor::bytes(id)},
      {"type", Cbor::text("public-key")},
  });
}

std::optional<std::vector<Cbor>> descriptorList(const Json& request, std::string_view key,
                                                std::string& error) {
  const Json* list = objectField(request, key);
  if (list == nullptr) return std::vector<Cbor>{};
  if (list->kind() != Json::Kind::Array) {
    error = std::string(key) + " is not an array";
    return std::nullopt;
  }
  std::vector<Cbor> out;
  for (const Json& item : list->array()) {
    if (item.kind() != Json::Kind::Object) continue;
    if (const Json* type = objectField(item, "type");
        type && type->kind() == Json::Kind::String && type->text() != "public-key") {
      continue;
    }
    auto id = b64Field(item, "id");
    if (!id) {
      error = std::string(key) + " entry has no credential id";
      return std::nullopt;
    }
    out.push_back(credentialDescriptor(*id));
  }
  return out;
}

Cbor algorithmList(const Json& request) {
  std::vector<Cbor> algs;
  if (const Json* params = objectField(request, "pubKeyCredParams");
      params && params->kind() == Json::Kind::Array) {
    for (const Json& item : params->array()) {
      if (item.kind() != Json::Kind::Object) continue;
      const Json* alg = objectField(item, "alg");
      if (alg == nullptr || alg->kind() != Json::Kind::Int) continue;
      if (const Json* type = objectField(item, "type");
          type && type->kind() == Json::Kind::String && type->text() != "public-key") {
        continue;
      }
      algs.push_back(Cbor::textMap({
          {"type", Cbor::text("public-key")},
          {"alg", Cbor::integer(alg->integer())},
      }));
    }
  }
  if (algs.empty()) {
    algs.push_back(Cbor::textMap({
        {"type", Cbor::text("public-key")},
        {"alg", Cbor::integer(-7)},
    }));
  }
  return Cbor::array(std::move(algs));
}

std::string clientDataJson(std::string_view type, std::string_view challenge, std::string_view origin,
                           bool cross_origin, std::string_view top_origin) {
  std::vector<std::pair<std::string, Json>> fields;
  fields.emplace_back("type", Json::str(std::string(type)));
  fields.emplace_back("challenge", Json::str(std::string(challenge)));
  fields.emplace_back("origin", Json::str(std::string(origin)));
  fields.emplace_back("crossOrigin", Json::boolean(cross_origin));
  if (cross_origin && !top_origin.empty()) {
    fields.emplace_back("topOrigin", Json::str(std::string(top_origin)));
  }
  return Json::object(std::move(fields)).dump();
}

bool coseXY(std::span<const std::uint8_t> cose, P256Public& pub) {
  auto key = Cbor::decode(cose);
  if (!key || key->kind() != Cbor::Kind::Map) return false;
  const Cbor* x = key->find(-2);
  const Cbor* y = key->find(-3);
  if (x == nullptr || y == nullptr || x->kind() != Cbor::Kind::Bytes || y->kind() != Cbor::Kind::Bytes ||
      x->bytes().size() != 32 || y->bytes().size() != 32) {
    return false;
  }
  std::memcpy(pub.x.data(), x->bytes().data(), 32);
  std::memcpy(pub.y.data(), y->bytes().data(), 32);
  return true;
}

std::vector<std::uint8_t> spki(const P256Public& pub) {
  std::vector<std::uint8_t> out(std::begin(kSpkiPrefix), std::end(kSpkiPrefix));
  out.insert(out.end(), pub.x.begin(), pub.x.end());
  out.insert(out.end(), pub.y.begin(), pub.y.end());
  return out;
}

struct Created {
  std::vector<std::uint8_t> auth_data;
  std::vector<std::uint8_t> credential_id;
  P256Public pub{};
  Cbor attestation_object = Cbor::null();
};

std::optional<Created> readMake(const Cbor& body, std::string& error) {
  const Cbor* fmt = body.find(1);
  const Cbor* auth = body.find(2);
  const Cbor* stmt = body.find(3);
  if (fmt == nullptr || auth == nullptr || stmt == nullptr || fmt->kind() != Cbor::Kind::Text ||
      auth->kind() != Cbor::Kind::Bytes || stmt->kind() != Cbor::Kind::Map) {
    error = "authenticator makeCredential response is incomplete";
    return std::nullopt;
  }
  const auto& auth_data = auth->bytes();
  if (auth_data.size() < 55 || (auth_data[32] & 0x40) == 0) {
    error = "authenticator data has no attested credential";
    return std::nullopt;
  }
  const std::uint16_t id_len = static_cast<std::uint16_t>((auth_data[53] << 8) | auth_data[54]);
  if (auth_data.size() < 55u + id_len) {
    error = "attested credential id is truncated";
    return std::nullopt;
  }
  Created created;
  created.auth_data = auth_data;
  created.credential_id.assign(auth_data.begin() + 55, auth_data.begin() + 55 + id_len);
  if (!coseXY(std::span<const std::uint8_t>(auth_data.data() + 55 + id_len,
                                            auth_data.size() - (55 + id_len)),
              created.pub)) {
    error = "attested credential public key is not ES256";
    return std::nullopt;
  }
  created.attestation_object = Cbor::textMap({
      {"fmt", Cbor::text(fmt->text())},
      {"authData", Cbor::bytes(auth_data)},
      {"attStmt", *stmt},
  });
  return created;
}

std::string finishCreate(std::string_view client_json, const Created& created, bool cred_props,
                        bool resident) {
  const auto id = base64UrlEncode(created.credential_id);
  const auto client = base64UrlEncode(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(client_json.data()), client_json.size()));
  const auto attestation = created.attestation_object.encode();
  Json extensions = Json::object({});
  if (cred_props) {
    extensions = Json::object({
        {"credProps", Json::object({{"rk", Json::boolean(resident)}})},
    });
  }
  return Json::object({
                          {"authenticatorAttachment", Json::str("platform")},
                          {"clientExtensionResults", std::move(extensions)},
                          {"id", Json::str(id)},
                          {"rawId", Json::str(id)},
                          {"response",
                           Json::object({
                               {"attestationObject", Json::str(base64UrlEncode(attestation))},
                               {"authenticatorData", Json::str(base64UrlEncode(created.auth_data))},
                               {"clientDataJSON", Json::str(client)},
                               {"publicKey", Json::str(base64UrlEncode(spki(created.pub)))},
                               {"publicKeyAlgorithm", Json::integer(-7)},
                               {"transports", Json::array({Json::str("internal")})},
                           })},
                          {"type", Json::str("public-key")},
                      })
      .dump();
}

std::string finishGet(std::string_view client_json, const Cbor& body) {
  const Cbor* cred = body.find(1);
  const Cbor* auth = body.find(2);
  const Cbor* sig = body.find(3);
  if (cred == nullptr || auth == nullptr || sig == nullptr || cred->kind() != Cbor::Kind::Map ||
      auth->kind() != Cbor::Kind::Bytes || sig->kind() != Cbor::Kind::Bytes) {
    return webauthnError("UnknownError", "authenticator getAssertion response is incomplete");
  }
  const Cbor* id = cred->find("id");
  if (id == nullptr || id->kind() != Cbor::Kind::Bytes) {
    return webauthnError("UnknownError", "assertion is missing a credential id");
  }
  // Chromium's GetAssertionResponseFromValue rejects a JSON null userHandle.
  // Omit the member when CTAP did not return a user, which is every non-resident get.
  std::optional<std::string> user_handle;
  if (const Cbor* user = body.find(4); user && user->kind() == Cbor::Kind::Map) {
    if (const Cbor* user_id = user->find("id"); user_id && user_id->kind() == Cbor::Kind::Bytes) {
      user_handle = base64UrlEncode(user_id->bytes());
    }
  }
  const auto encoded_id = base64UrlEncode(id->bytes());
  const auto client = base64UrlEncode(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(client_json.data()), client_json.size()));
  std::vector<std::pair<std::string, Json>> response_fields;
  response_fields.emplace_back("authenticatorData", Json::str(base64UrlEncode(auth->bytes())));
  response_fields.emplace_back("clientDataJSON", Json::str(client));
  response_fields.emplace_back("signature", Json::str(base64UrlEncode(sig->bytes())));
  if (user_handle) response_fields.emplace_back("userHandle", Json::str(std::move(*user_handle)));
  return Json::object({
                          {"authenticatorAttachment", Json::str("platform")},
                          {"clientExtensionResults", Json::object({})},
                          {"id", Json::str(encoded_id)},
                          {"rawId", Json::str(encoded_id)},
                          {"response", Json::object(std::move(response_fields))},
                          {"type", Json::str("public-key")},
                      })
      .dump();
}

std::string transactParsed(Authenticator& authenticator, const Json& message) {
  const Json* type_field = objectField(message, "type");
  const Json* origin_field = objectField(message, "origin");
  const Json* request_field = objectField(message, "request");
  if (type_field == nullptr || type_field->kind() != Json::Kind::String) {
    return webauthnError("NotAllowedError", "missing request type");
  }
  const bool is_create = type_field->text() == "create";
  const bool is_get = type_field->text() == "get";
  if (!is_create && !is_get) return webauthnError("NotAllowedError", "unknown request type");
  if (origin_field == nullptr || origin_field->kind() != Json::Kind::String) {
    return webauthnError("SecurityError", "missing caller origin");
  }
  std::string origin;
  std::string host;
  if (!parseOrigin(origin_field->text(), origin, host)) {
    return webauthnError("SecurityError", "caller origin is not a WebAuthn origin");
  }
  if (request_field == nullptr || request_field->kind() != Json::Kind::Object) {
    return webauthnError("NotAllowedError", "missing WebAuthn request");
  }
  const Json& request = *request_field;

  bool cross_origin = false;
  if (const Json* cross = objectField(message, "crossOrigin");
      cross && cross->kind() == Json::Kind::Bool) {
    cross_origin = cross->boolean();
  }
  std::string top_origin;
  if (const Json* top = objectField(message, "topOrigin"); top && top->kind() == Json::Kind::String) {
    std::string top_host;
    if (!parseOrigin(top->text(), top_origin, top_host)) top_origin.clear();
  }

  const Json* challenge_field = objectField(request, "challenge");
  if (challenge_field == nullptr || challenge_field->kind() != Json::Kind::String) {
    return webauthnError("NotAllowedError", "missing challenge");
  }
  auto challenge_bytes = base64UrlDecode(challenge_field->text());
  if (!challenge_bytes || challenge_bytes->empty()) {
    return webauthnError("NotAllowedError", "challenge is not base64url");
  }
  const std::string& challenge = challenge_field->text();

  std::string rp_id = host;
  std::string rp_name = host;
  if (is_create) {
    const Json* rp = objectField(request, "rp");
    if (rp == nullptr || rp->kind() != Json::Kind::Object) {
      return webauthnError("NotAllowedError", "missing relying party");
    }
    if (const Json* id = objectField(*rp, "id"); id && id->kind() == Json::Kind::String && !id->text().empty()) {
      rp_id = lower(id->text());
    }
    if (const Json* name = objectField(*rp, "name"); name && name->kind() == Json::Kind::String) {
      rp_name = name->text();
    }
  } else if (const Json* id = objectField(request, "rpId");
             id && id->kind() == Json::Kind::String && !id->text().empty()) {
    rp_id = lower(id->text());
  }
  if (!rpIdMatches(host, rp_id)) {
    return webauthnError("SecurityError", "relying party id does not match the caller origin");
  }

  const auto client_json = clientDataJson(is_create ? "webauthn.create" : "webauthn.get", challenge, origin,
                                          cross_origin, top_origin);
  const auto client_hash = sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(client_json.data()), client_json.size()));
  const Selection selection = readSelection(request, is_create);
  if (selection.rk && !selection.uv) {
    return webauthnError("NotAllowedError",
                         "a resident credential needs user verification or a PIN");
  }

  std::string list_error;
  std::vector<std::pair<std::int64_t, Cbor>> fields;
  fields.emplace_back(is_create ? 1 : 2, Cbor::bytes(std::span<const std::uint8_t>(client_hash.data(), 32)));
  if (is_create) {
    const Json* user = objectField(request, "user");
    if (user == nullptr || user->kind() != Json::Kind::Object) {
      return webauthnError("NotAllowedError", "missing user");
    }
    auto user_id = b64Field(*user, "id");
    if (!user_id || user_id->empty()) return webauthnError("NotAllowedError", "missing user id");
    auto exclude = descriptorList(request, "excludeCredentials", list_error);
    if (!exclude) return webauthnError("NotAllowedError", list_error);
    fields.emplace_back(2, Cbor::textMap({
                               {"id", Cbor::text(rp_id)},
                               {"name", Cbor::text(rp_name)},
                           }));
    fields.emplace_back(3, Cbor::textMap({
                               {"id", Cbor::bytes(*user_id)},
                               {"name", Cbor::text(textOr(*user, "name"))},
                               {"displayName", Cbor::text(textOr(*user, "displayName"))},
                           }));
    fields.emplace_back(4, algorithmList(request));
    if (!exclude->empty()) fields.emplace_back(5, Cbor::array(std::move(*exclude)));
    fields.emplace_back(7, Cbor::textMap({
                               {"rk", Cbor::boolean(selection.rk)},
                               {"up", Cbor::boolean(true)},
                               {"uv", Cbor::boolean(selection.uv)},
                           }));
  } else {
    auto allow = descriptorList(request, "allowCredentials", list_error);
    if (!allow) return webauthnError("NotAllowedError", list_error);
    fields.emplace_back(1, Cbor::text(rp_id));
    if (!allow->empty()) fields.emplace_back(3, Cbor::array(std::move(*allow)));
    fields.emplace_back(5, Cbor::textMap({
                               {"up", Cbor::boolean(true)},
                               {"uv", Cbor::boolean(selection.uv)},
                           }));
  }

  const auto response = callCtap(authenticator, is_create ? 0x01 : 0x02, Cbor::intMap(std::move(fields)));
  if (response.empty()) return webauthnError("UnknownError", "empty authenticator response");
  if (response[0] != static_cast<std::uint8_t>(Status::Ok)) {
    return webauthnError(statusName(response[0]), statusMessage(response[0]));
  }
  auto body = Cbor::decode(std::span<const std::uint8_t>(response.data() + 1, response.size() - 1));
  if (!body || body->kind() != Cbor::Kind::Map) {
    return webauthnError("UnknownError", "authenticator response is not CBOR");
  }
  if (is_create) {
    std::string error;
    auto created = readMake(*body, error);
    if (!created) return webauthnError("UnknownError", error);
    bool cred_props = false;
    if (const Json* ext = objectField(request, "extensions");
        ext && ext->kind() == Json::Kind::Object) {
      if (const Json* flag = objectField(*ext, "credProps");
          flag && flag->kind() == Json::Kind::Bool && flag->boolean()) {
        cred_props = true;
      }
    }
    return finishCreate(client_json, *created, cred_props, selection.rk);
  }
  return finishGet(client_json, *body);
}

}  // namespace

std::string base64UrlEncode(std::span<const std::uint8_t> data) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve((data.size() + 2) / 3 * 4);
  std::size_t index = 0;
  while (index + 3 <= data.size()) {
    const unsigned n = (unsigned{data[index]} << 16) | (unsigned{data[index + 1]} << 8) | data[index + 2];
    out.push_back(kAlphabet[(n >> 18) & 63]);
    out.push_back(kAlphabet[(n >> 12) & 63]);
    out.push_back(kAlphabet[(n >> 6) & 63]);
    out.push_back(kAlphabet[n & 63]);
    index += 3;
  }
  if (index < data.size()) {
    unsigned n = unsigned{data[index]} << 16;
    if (index + 1 < data.size()) n |= unsigned{data[index + 1]} << 8;
    out.push_back(kAlphabet[(n >> 18) & 63]);
    out.push_back(kAlphabet[(n >> 12) & 63]);
    if (index + 1 < data.size()) out.push_back(kAlphabet[(n >> 6) & 63]);
  }
  return out;
}

std::optional<std::vector<std::uint8_t>> base64UrlDecode(std::string_view text) {
  auto value = [](char ch) -> int {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '-' || ch == '+') return 62;
    if (ch == '_' || ch == '/') return 63;
    return -1;
  };
  std::vector<std::uint8_t> out;
  unsigned accumulator = 0;
  int bits = 0;
  for (char ch : text) {
    if (ch == '=') break;
    const int digit = value(ch);
    if (digit < 0) return std::nullopt;
    accumulator = (accumulator << 6) | static_cast<unsigned>(digit);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<std::uint8_t>((accumulator >> bits) & 0xff));
    }
  }
  return out;
}

std::string transactWebAuthn(Authenticator& authenticator, std::string_view message) {
  try {
    auto parsed = Json::parse(message);
    if (!parsed || parsed->kind() != Json::Kind::Object) {
      return webauthnError("NotAllowedError", "request is not a JSON object");
    }
    return transactParsed(authenticator, *parsed);
  } catch (const std::exception& ex) {
    return webauthnError("UnknownError", ex.what());
  }
}

}  // namespace fidolizer
