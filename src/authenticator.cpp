#include "fidolizer/authenticator.hpp"

#include "fidolizer/cbor.hpp"
#include "fidolizer/crypto.hpp"
#include "fidolizer/identity.hpp"
#include "fidolizer/status.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <optional>
#include <thread>
#include <tuple>
#include <utility>

namespace fidolizer {
namespace {

constexpr std::uint8_t kFlagUp = 0x01;
constexpr std::uint8_t kFlagUv = 0x04;
constexpr std::uint8_t kFlagAt = 0x40;
constexpr std::uint8_t kFlagEd = 0x80;
constexpr std::uint8_t kPermMake = 0x01;
constexpr std::uint8_t kPermGet = 0x02;
constexpr std::uint8_t kPermMgmt = 0x04;
constexpr std::uint8_t kPermBio = 0x08;
constexpr std::uint8_t kPermLarge = 0x10;
constexpr std::uint8_t kPermConfig = 0x20;
constexpr std::uint8_t kPinRetriesMax = 8;

std::vector<std::uint8_t> withStatus(Status status, const Cbor& body) {
  auto encoded = body.encode();
  std::vector<std::uint8_t> out;
  out.reserve(1 + encoded.size());
  out.push_back(static_cast<std::uint8_t>(status));
  out.insert(out.end(), encoded.begin(), encoded.end());
  return out;
}

std::vector<std::uint8_t> okBody(const Cbor& body) { return withStatus(Status::Ok, body); }

void putBe16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value >> 8));
  out.push_back(static_cast<std::uint8_t>(value));
}

void putBe32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
  }
}

std::array<std::uint8_t, 32> hashRp(std::string_view rp_id) {
  return sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(rp_id.data()),
                                              rp_id.size()));
}

std::vector<std::uint8_t> pinDigest(std::string_view pin) {
  const auto digest = sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(pin.data()), pin.size()));
  return {digest.begin(), digest.begin() + 16};
}

Cbor cosePublic(const P256Public& pub) {
  return Cbor::intMap({
      {1, Cbor::integer(2)},
      {3, Cbor::integer(-7)},
      {-1, Cbor::integer(1)},
      {-2, Cbor::bytes(std::span<const std::uint8_t>(pub.x.data(), 32))},
      {-3, Cbor::bytes(std::span<const std::uint8_t>(pub.y.data(), 32))},
  });
}

Cbor coseAgreement(const P256Public& pub) {
  return Cbor::intMap({
      {1, Cbor::integer(2)},
      {3, Cbor::integer(-25)},
      {-1, Cbor::integer(1)},
      {-2, Cbor::bytes(std::span<const std::uint8_t>(pub.x.data(), 32))},
      {-3, Cbor::bytes(std::span<const std::uint8_t>(pub.y.data(), 32))},
  });
}

bool parseCose(const Cbor& key, P256Public& out) {
  if (key.kind() != Cbor::Kind::Map) return false;
  const Cbor* x = key.find(-2);
  const Cbor* y = key.find(-3);
  if (x == nullptr || y == nullptr || x->kind() != Cbor::Kind::Bytes ||
      y->kind() != Cbor::Kind::Bytes || x->bytes().size() != 32 || y->bytes().size() != 32) {
    return false;
  }
  std::memcpy(out.x.data(), x->bytes().data(), 32);
  std::memcpy(out.y.data(), y->bytes().data(), 32);
  return true;
}

struct Options {
  bool rk{false};
  bool uv{false};
  bool up{true};
  Status error{Status::Ok};
};

Options parseOptions(const Cbor* options) {
  Options parsed;
  if (options == nullptr) return parsed;
  if (options->kind() != Cbor::Kind::Map) {
    parsed.error = Status::CborUnexpectedType;
    return parsed;
  }
  auto flag = [&](const char* name, bool& dest) {
    const Cbor* value = options->find(name);
    if (value == nullptr) return true;
    if (value->kind() != Cbor::Kind::Bool) {
      parsed.error = Status::InvalidOption;
      return false;
    }
    dest = value->boolean();
    return true;
  };
  if (!flag("rk", parsed.rk) || !flag("uv", parsed.uv) || !flag("up", parsed.up)) return parsed;
  return parsed;
}

std::optional<Cbor> decodeMap(std::span<const std::uint8_t> body, Status& error) {
  if (body.empty()) {
    error = Status::MissingParameter;
    return std::nullopt;
  }
  auto value = Cbor::decode(body);
  if (!value) {
    error = Status::InvalidCbor;
    return std::nullopt;
  }
  if (value->kind() != Cbor::Kind::Map) {
    error = Status::CborUnexpectedType;
    return std::nullopt;
  }
  return std::move(*value);
}

class Pump {
 public:
  explicit Pump(Keepalive& io) : io_(io) {
    thread_ = std::thread([this] {
      while (!done_.load()) {
        io_.keepalive(0x02);
        for (int i = 0; i < 8 && !done_.load(); ++i) {
          std::this_thread::sleep_for(std::chrono::milliseconds(12));
        }
      }
    });
  }
  ~Pump() {
    done_.store(true);
    if (thread_.joinable()) thread_.join();
  }
  Pump(const Pump&) = delete;
  Pump& operator=(const Pump&) = delete;

 private:
  Keepalive& io_;
  std::atomic<bool> done_{false};
  std::thread thread_;
};

Status ask(Presence& presence, Keepalive& io, std::string_view rp, std::string_view action, bool uv) {
  Pump pump(io);
  const Decision decision = presence.confirm(rp, action, uv, [&] { return io.cancelled(); });
  if (io.cancelled() || decision == Decision::Cancelled) return Status::KeepaliveCancel;
  if (decision == Decision::Timeout) return Status::UserActionTimeout;
  if (decision == Decision::Deny) return Status::OperationDenied;
  return Status::Ok;
}

std::vector<std::uint8_t> sw(std::uint16_t code) {
  return {static_cast<std::uint8_t>(code >> 8), static_cast<std::uint8_t>(code)};
}

std::vector<std::uint8_t> wrapCredential(const Credential& cred, std::span<const std::uint8_t, 32> key,
                                         std::span<const std::uint8_t, 32> rp_hash) {
  std::vector<std::uint8_t> plain;
  plain.insert(plain.end(), cred.priv.begin(), cred.priv.end());
  plain.push_back(cred.cred_protect);
  plain.push_back(static_cast<std::uint8_t>(cred.hmac_secret.size()));
  plain.insert(plain.end(), cred.hmac_secret.begin(), cred.hmac_secret.end());
  plain.push_back(static_cast<std::uint8_t>(cred.cred_blob.size()));
  plain.insert(plain.end(), cred.cred_blob.begin(), cred.cred_blob.end());
  auto nonce_bytes = randomBytes(12);
  std::array<std::uint8_t, 12> nonce{};
  std::memcpy(nonce.data(), nonce_bytes.data(), nonce_bytes.size());
  auto sealed = aes256GcmEncrypt(key, nonce, rp_hash, plain);
  OPENSSL_cleanse(plain.data(), plain.size());
  std::vector<std::uint8_t> id;
  id.push_back(0x01);
  const auto alg = static_cast<std::uint16_t>(static_cast<std::int16_t>(cred.alg));
  id.push_back(static_cast<std::uint8_t>(alg >> 8));
  id.push_back(static_cast<std::uint8_t>(alg));
  id.insert(id.end(), nonce.begin(), nonce.end());
  id.insert(id.end(), sealed.begin(), sealed.end());
  return id;
}

std::optional<Credential> unwrapCredential(std::span<const std::uint8_t> id,
                                           std::span<const std::uint8_t, 32> key,
                                           std::span<const std::uint8_t, 32> rp_hash) {
  if (id.size() < 31 || id[0] != 0x01) return std::nullopt;
  std::array<std::uint8_t, 12> nonce{};
  std::memcpy(nonce.data(), id.data() + 3, 12);
  auto plain = aes256GcmDecrypt(key, nonce, rp_hash, id.subspan(15));
  if (plain.size() < 35) return std::nullopt;
  Credential cred;
  cred.wrapped = true;
  std::memcpy(cred.priv.data(), plain.data(), 32);
  cred.cred_protect = plain[32];
  const std::size_t hmac_len = plain[33];
  if (34 + hmac_len >= plain.size()) return std::nullopt;
  cred.hmac_secret.assign(plain.begin() + 34, plain.begin() + 34 + static_cast<std::ptrdiff_t>(hmac_len));
  const std::size_t blob_at = 34 + hmac_len;
  const std::size_t blob_len = plain[blob_at];
  if (blob_at + 1 + blob_len != plain.size()) return std::nullopt;
  cred.cred_blob.assign(plain.begin() + static_cast<std::ptrdiff_t>(blob_at + 1), plain.end());
  cred.alg = static_cast<std::int16_t>(static_cast<std::uint16_t>((id[1] << 8) | id[2]));
  cred.id.assign(id.begin(), id.end());
  OPENSSL_cleanse(plain.data(), plain.size());
  return cred;
}

bool credVisible(const Credential& cred, bool uv, bool in_allow_list) {
  const std::uint8_t policy = cred.cred_protect == 0 ? 1 : cred.cred_protect;
  if (policy >= 3 && !uv) return false;
  if (policy == 2 && !uv && !in_allow_list) return false;
  return true;
}

std::vector<std::uint8_t> authenticatorData(std::span<const std::uint8_t, 32> rp_hash, std::uint8_t flags,
                                            std::uint32_t counter, std::span<const std::uint8_t, 16> aaguid,
                                            const std::vector<std::uint8_t>* cred_id, const P256Public* pub,
                                            const Cbor* extensions) {
  std::vector<std::uint8_t> out(rp_hash.begin(), rp_hash.end());
  out.push_back(flags);
  putBe32(out, counter);
  if ((flags & kFlagAt) != 0 && cred_id != nullptr && pub != nullptr) {
    out.insert(out.end(), aaguid.begin(), aaguid.end());
    putBe16(out, static_cast<std::uint16_t>(cred_id->size()));
    out.insert(out.end(), cred_id->begin(), cred_id->end());
    auto cose = cosePublic(*pub).encode();
    out.insert(out.end(), cose.begin(), cose.end());
  }
  if ((flags & kFlagEd) != 0 && extensions != nullptr) {
    auto encoded = extensions->encode();
    out.insert(out.end(), encoded.begin(), encoded.end());
  }
  return out;
}

std::vector<std::uint8_t> signEs256(std::span<const std::uint8_t, 32> priv,
                                    std::span<const std::uint8_t> message) {
  std::array<std::uint8_t, 32> scalar{};
  std::memcpy(scalar.data(), priv.data(), 32);
  return P256Key::fromPrivate(scalar).sign(message);
}

}  // namespace

Authenticator::Authenticator(StateStore& store, Presence& presence)
    : store_(store), presence_(presence) {}

void Authenticator::setPin(std::string_view pin) {
  if (pin.size() < store_.state().min_pin_length || pin.size() > 63) {
    throw std::runtime_error("PIN length must be between the minimum and 63 bytes");
  }
  store_.state().pin_hash = pinDigest(pin);
  store_.state().pin_retries = kPinRetriesMax;
  pin_power_cycle_ = false;
  boot_pin_attempts_ = 0;
  token_ = {};
  store_.save();
}

void Authenticator::changePin(std::string_view old_pin, std::string_view new_pin) {
  if (store_.state().pin_hash.empty()) throw std::runtime_error("PIN is not set");
  const auto old_hash = pinDigest(old_pin);
  if (!constantTimeEqual(old_hash, store_.state().pin_hash)) throw std::runtime_error("wrong PIN");
  setPin(new_pin);
}

void Authenticator::resetState() {
  auto wrap = randomBytes(32);
  std::memcpy(store_.state().wrap_key.data(), wrap.data(), wrap.size());
  OPENSSL_cleanse(wrap.data(), wrap.size());
  store_.state().credentials.clear();
  store_.state().pin_hash.clear();
  store_.state().pin_retries = kPinRetriesMax;
  store_.state().global_counter = 0;
  token_ = {};
  if (!agreement_priv_.empty()) OPENSSL_cleanse(agreement_priv_.data(), agreement_priv_.size());
  agreement_priv_.clear();
  have_pending_ = false;
  cred_enum_ = {};
  store_.save();
}

std::vector<std::uint8_t> Authenticator::cbor(std::span<const std::uint8_t> payload, Keepalive& io) {
  if (payload.empty()) return statusOnly(Status::InvalidCommand);
  const auto command = payload[0];
  if (command != 0x08) have_pending_ = false;
  if (command != 0x0a && command != 0x41) cred_enum_ = {};
  try {
    const auto body = payload.subspan(1);
    switch (command) {
      case 0x01:
        return makeCredential(body, io);
      case 0x02:
        return getAssertion(body, io);
      case 0x04:
        return getInfo();
      case 0x06:
        return clientPin(body, io);
      case 0x07:
        return reset(io);
      case 0x08:
        return getNextAssertion(io);
      case 0x0a:
        return credMgmt(0x0a, body);
      case 0x0b:
        return selection(io);
      case 0x41:
        return credMgmt(0x41, body);
      default:
        return statusOnly(Status::InvalidCommand);
    }
  } catch (const std::exception& ex) {
    std::cerr << "fidolizer: " << ex.what() << '\n';
    return statusOnly(Status::Other);
  }
}

std::vector<std::uint8_t> Authenticator::getInfo() const {
  const bool pin_set = !store_.state().pin_hash.empty();
  return okBody(Cbor::intMap({
      {1, Cbor::array({Cbor::text("U2F_V2"), Cbor::text("FIDO_2_0"), Cbor::text("FIDO_2_1")})},
      {2, Cbor::array({Cbor::text("credProtect"), Cbor::text("hmac-secret"), Cbor::text("credBlob")})},
      {3, Cbor::bytes(std::span<const std::uint8_t>(store_.state().aaguid.data(), 16))},
      {4, Cbor::textMap({
              {"rk", Cbor::boolean(true)},
              {"up", Cbor::boolean(true)},
              {"uv", Cbor::boolean(true)},
              {"plat", Cbor::boolean(false)},
              {"clientPin", Cbor::boolean(pin_set)},
              {"pinUvAuthToken", Cbor::boolean(true)},
              {"makeCredUvNotRqd", Cbor::boolean(true)},
              {"credentialMgmtPreview", Cbor::boolean(true)},
          })},
      {5, Cbor::integer(static_cast<std::int64_t>(kMaxMessage))},
      {6, Cbor::array({Cbor::integer(2), Cbor::integer(1)})},
      {7, Cbor::integer(32)},
      {8, Cbor::integer(255)},
      {9, Cbor::array({Cbor::text("usb")})},
      {10, Cbor::array({Cbor::textMap({{"alg", Cbor::integer(-7)}, {"type", Cbor::text("public-key")}})})},
      {13, Cbor::integer(store_.state().min_pin_length)},
      {14, Cbor::integer(kFirmwareVersion)},
      {15, Cbor::integer(32)},
  }));
}

namespace {

P256Key keyFromState(std::span<const std::uint8_t, 32> priv) { return P256Key::fromPrivate(priv); }

}  // namespace

std::vector<std::uint8_t> Authenticator::makeCredential(std::span<const std::uint8_t> body, Keepalive& io) {
  Status error = Status::Ok;
  auto params = decodeMap(body, error);
  if (!params) return statusOnly(error);
  const Cbor* client_hash = params->find(1);
  const Cbor* rp = params->find(2);
  const Cbor* user = params->find(3);
  const Cbor* algorithms = params->find(4);
  if (client_hash == nullptr || rp == nullptr || user == nullptr || algorithms == nullptr) {
    return statusOnly(Status::MissingParameter);
  }
  if (client_hash->kind() != Cbor::Kind::Bytes || client_hash->bytes().size() != 32) {
    return statusOnly(Status::InvalidLength);
  }
  if (rp->kind() != Cbor::Kind::Map || user->kind() != Cbor::Kind::Map ||
      algorithms->kind() != Cbor::Kind::Array) {
    return statusOnly(Status::CborUnexpectedType);
  }
  const Cbor* rp_id_v = rp->find("id");
  const Cbor* user_id_v = user->find("id");
  if (rp_id_v == nullptr || rp_id_v->kind() != Cbor::Kind::Text || rp_id_v->text().empty()) {
    return statusOnly(Status::MissingParameter);
  }
  if (user_id_v == nullptr || user_id_v->kind() != Cbor::Kind::Bytes) {
    return statusOnly(Status::MissingParameter);
  }
  if (rp_id_v->text().size() > 253 || user_id_v->bytes().size() > 64) {
    return statusOnly(Status::LimitExceeded);
  }
  std::string user_name;
  std::string user_display;
  std::string rp_name;
  if (const Cbor* name = user->find("name"); name && name->kind() == Cbor::Kind::Text) {
    if (name->text().size() > 64) return statusOnly(Status::LimitExceeded);
    user_name = name->text();
  }
  if (const Cbor* name = user->find("displayName"); name && name->kind() == Cbor::Kind::Text) {
    if (name->text().size() > 64) return statusOnly(Status::LimitExceeded);
    user_display = name->text();
  }
  if (const Cbor* name = rp->find("name"); name && name->kind() == Cbor::Kind::Text) rp_name = name->text();

  bool supported = false;
  for (const Cbor& item : algorithms->array()) {
    if (item.kind() != Cbor::Kind::Map) continue;
    const Cbor* type = item.find("type");
    const Cbor* alg = item.find("alg");
    if (alg == nullptr || alg->kind() != Cbor::Kind::Int) continue;
    if (type != nullptr && (type->kind() != Cbor::Kind::Text || type->text() != "public-key")) continue;
    if (alg->integer() == -7) supported = true;
  }
  if (!supported) return statusOnly(Status::UnsupportedAlgorithm);

  Options options = parseOptions(params->find(7));
  if (options.error != Status::Ok) return statusOnly(options.error);
  if (const Cbor* enterprise = params->find(10);
      enterprise && enterprise->kind() == Cbor::Kind::Int && enterprise->integer() != 0) {
    return statusOnly(Status::InvalidOption);
  }

  std::uint8_t cred_protect = 0;
  bool want_hmac = false;
  std::vector<std::uint8_t> cred_blob;
  bool want_blob = false;
  if (const Cbor* extensions = params->find(6)) {
    if (extensions->kind() != Cbor::Kind::Map) return statusOnly(Status::CborUnexpectedType);
    if (const Cbor* protect = extensions->find("credProtect")) {
      if (protect->kind() != Cbor::Kind::Int) return statusOnly(Status::InvalidOption);
      const auto policy = protect->integer();
      if (policy < 1 || policy > 3) return statusOnly(Status::InvalidOption);
      cred_protect = static_cast<std::uint8_t>(policy);
    }
    if (const Cbor* hmac = extensions->find("hmac-secret");
        hmac && hmac->kind() == Cbor::Kind::Bool && hmac->boolean()) {
      want_hmac = true;
    }
    if (const Cbor* blob = extensions->find("credBlob")) {
      if (blob->kind() != Cbor::Kind::Bytes) return statusOnly(Status::InvalidOption);
      if (blob->bytes().size() > 32) return statusOnly(Status::LimitExceeded);
      cred_blob = blob->bytes();
      want_blob = true;
    }
  }

  const auto rp_hash = hashRp(rp_id_v->text());
  if (const Cbor* exclude = params->find(5)) {
    if (exclude->kind() != Cbor::Kind::Array) return statusOnly(Status::CborUnexpectedType);
    bool hit = false;
    for (const Cbor& item : exclude->array()) {
      if (item.kind() != Cbor::Kind::Map) continue;
      const Cbor* id = item.find("id");
      if (id == nullptr || id->kind() != Cbor::Kind::Bytes) continue;
      for (const Credential& cred : store_.state().credentials) {
        if (cred.discoverable && cred.rp_id == rp_id_v->text() && cred.id == id->bytes()) hit = true;
      }
      if (unwrapCredential(id->bytes(), store_.state().wrap_key, rp_hash)) hit = true;
    }
    if (hit) {
      if (options.up) {
        const Status touched = ask(presence_, io, rp_id_v->text(), "confirm it is you", false);
        if (touched != Status::Ok) return statusOnly(touched);
      }
      return statusOnly(Status::CredentialExcluded);
    }
  }

  bool uv = false;
  bool up = false;
  const Cbor* pin_param = params->find(8);
  const Cbor* pin_protocol = params->find(9);
  if ((pin_param == nullptr) != (pin_protocol == nullptr)) return statusOnly(Status::MissingParameter);
  if (pin_param != nullptr) {
    if (pin_param->kind() != Cbor::Kind::Bytes || pin_protocol->kind() != Cbor::Kind::Int) {
      return statusOnly(Status::CborUnexpectedType);
    }
    if (!token_.valid || token_.protocol != pin_protocol->integer()) return statusOnly(Status::PinAuthInvalid);
    if (pin_auth_blocked_) return statusOnly(Status::PinAuthBlocked);
    if ((token_.permissions & kPermMake) == 0) return statusOnly(Status::UnauthorizedPermission);
    if (token_.rp_bound && token_.rp_id != rp_id_v->text()) return statusOnly(Status::PinAuthInvalid);
    const auto mac = tokenMac(token_.protocol, token_.token, client_hash->bytes());
    if (!constantTimeEqual(mac, pin_param->bytes())) {
      if (++pin_auth_failures_ >= 3) pin_auth_blocked_ = true;
      return statusOnly(Status::PinAuthInvalid);
    }
    pin_auth_failures_ = 0;
    uv = true;
  } else if (options.uv) {
    const Status verified = ask(presence_, io, rp_id_v->text(), "create a passkey", true);
    if (verified != Status::Ok) return statusOnly(verified);
    uv = true;
    up = true;
  } else if (options.rk && store_.state().pin_hash.empty()) {
    return statusOnly(Status::PinNotSet);
  } else if (options.rk && !store_.state().pin_hash.empty()) {
    return statusOnly(Status::PuatRequired);
  }
  if (cred_protect >= 3 && !uv) return statusOnly(Status::PuatRequired);
  if (options.up && !up) {
    const Status touched = ask(presence_, io, rp_id_v->text(), "create a credential", false);
    if (touched != Status::Ok) return statusOnly(touched);
    up = true;
  }
  if (!uv) {
    want_blob = false;
    cred_blob.clear();
  }

  if (options.rk) {
    std::size_t residents = 0;
    for (const Credential& cred : store_.state().credentials) {
      if (cred.discoverable) ++residents;
    }
    if (residents >= kMaxResidentCredentials) return statusOnly(Status::KeyStoreFull);
  }

  Credential cred;
  auto fresh = P256Key::generate();
  std::memcpy(cred.priv.data(), fresh.privateKey().data(), 32);
  cred.alg = -7;
  cred.rp_id = rp_id_v->text();
  cred.rp_name = rp_name;
  cred.user_id = user_id_v->bytes();
  cred.user_name = user_name;
  cred.user_display_name = user_display;
  cred.discoverable = options.rk;
  cred.cred_protect = cred_protect;
  cred.cred_blob = std::move(cred_blob);
  if (want_hmac) cred.hmac_secret = randomBytes(32);
  if (options.rk) {
    cred.id = randomBytes(16);
    store_.state().credentials.push_back(cred);
  } else {
    cred.id = wrapCredential(cred, store_.state().wrap_key, rp_hash);
  }

  std::vector<std::pair<std::string, Cbor>> extension_fields;
  if (cred_protect != 0) extension_fields.emplace_back("credProtect", Cbor::integer(cred_protect));
  if (want_hmac) extension_fields.emplace_back("hmac-secret", Cbor::boolean(true));
  if (want_blob) extension_fields.emplace_back("credBlob", Cbor::boolean(true));
  std::optional<Cbor> extensions;
  std::uint8_t flags = kFlagAt;
  if (up) flags |= kFlagUp;
  if (uv) flags |= kFlagUv;
  if (!extension_fields.empty()) {
    flags |= kFlagEd;
    extensions = Cbor::textMap(std::move(extension_fields));
  }
  const auto counter = ++store_.state().global_counter;
  if (options.rk) store_.state().credentials.back().sign_count = counter;
  const P256Public pub = fresh.publicKey();
  auto auth_data = authenticatorData(rp_hash, flags, counter, store_.state().aaguid, &cred.id, &pub,
                                     extensions ? &*extensions : nullptr);
  std::vector<std::uint8_t> signed_data = auth_data;
  signed_data.insert(signed_data.end(), client_hash->bytes().begin(), client_hash->bytes().end());
  std::array<std::uint8_t, 32> att_priv{};
  std::memcpy(att_priv.data(), store_.state().attestation_priv.data(), 32);
  const auto signature = keyFromState(att_priv).sign(signed_data);
  store_.save();

  Cbor statement = Cbor::textMap({
      {"alg", Cbor::integer(-7)},
      {"sig", Cbor::bytes(signature)},
      {"x5c", Cbor::array({Cbor::bytes(store_.state().attestation_cert)})},
  });
  return okBody(Cbor::intMap({
      {1, Cbor::text("packed")},
      {2, Cbor::bytes(std::move(auth_data))},
      {3, std::move(statement)},
  }));
}

std::vector<std::uint8_t> Authenticator::getAssertion(std::span<const std::uint8_t> body, Keepalive& io) {
  Status error = Status::Ok;
  auto params = decodeMap(body, error);
  if (!params) return statusOnly(error);
  const Cbor* rp_id_v = params->find(1);
  const Cbor* client_hash = params->find(2);
  if (rp_id_v == nullptr || client_hash == nullptr) return statusOnly(Status::MissingParameter);
  if (rp_id_v->kind() != Cbor::Kind::Text || rp_id_v->text().empty()) return statusOnly(Status::MissingParameter);
  if (client_hash->kind() != Cbor::Kind::Bytes || client_hash->bytes().size() != 32) {
    return statusOnly(Status::InvalidLength);
  }
  Options options = parseOptions(params->find(5));
  if (options.error != Status::Ok) return statusOnly(options.error);

  const auto rp_hash = hashRp(rp_id_v->text());
  struct Candidate {
    Credential* resident{nullptr};
    Credential wrapped;
    bool is_wrapped{false};
    bool in_allow{false};
  };
  std::vector<Candidate> pool;
  if (const Cbor* allow = params->find(3)) {
    if (allow->kind() != Cbor::Kind::Array) return statusOnly(Status::CborUnexpectedType);
    if (allow->array().size() > 32) return statusOnly(Status::LimitExceeded);
    for (const Cbor& item : allow->array()) {
      if (item.kind() != Cbor::Kind::Map) continue;
      const Cbor* id = item.find("id");
      if (id == nullptr || id->kind() != Cbor::Kind::Bytes) continue;
      Candidate candidate;
      candidate.in_allow = true;
      bool found = false;
      for (Credential& cred : store_.state().credentials) {
        if (cred.discoverable && cred.id == id->bytes() && cred.rp_id == rp_id_v->text()) {
          candidate.resident = &cred;
          found = true;
          break;
        }
      }
      if (!found) {
        if (auto wrapped = unwrapCredential(id->bytes(), store_.state().wrap_key, rp_hash)) {
          candidate.wrapped = std::move(*wrapped);
          candidate.is_wrapped = true;
          found = true;
        }
      }
      if (found) pool.push_back(std::move(candidate));
    }
  } else {
    for (Credential& cred : store_.state().credentials) {
      if (cred.discoverable && cred.rp_id == rp_id_v->text()) {
        Candidate candidate;
        candidate.resident = &cred;
        pool.push_back(std::move(candidate));
      }
    }
  }
  if (pool.empty()) return statusOnly(Status::NoCredentials);

  bool uv = false;
  bool up = false;
  const Cbor* pin_param = params->find(6);
  const Cbor* pin_protocol = params->find(7);
  if ((pin_param == nullptr) != (pin_protocol == nullptr)) return statusOnly(Status::MissingParameter);
  if (pin_param != nullptr) {
    if (pin_param->kind() != Cbor::Kind::Bytes || pin_protocol->kind() != Cbor::Kind::Int) {
      return statusOnly(Status::CborUnexpectedType);
    }
    if (pin_auth_blocked_) return statusOnly(Status::PinAuthBlocked);
    if (!token_.valid || token_.protocol != pin_protocol->integer()) return statusOnly(Status::PinAuthInvalid);
    if ((token_.permissions & kPermGet) == 0) return statusOnly(Status::UnauthorizedPermission);
    if (token_.rp_bound && token_.rp_id != rp_id_v->text()) return statusOnly(Status::PinAuthInvalid);
    const auto mac = tokenMac(token_.protocol, token_.token, client_hash->bytes());
    if (!constantTimeEqual(mac, pin_param->bytes())) {
      if (++pin_auth_failures_ >= 3) pin_auth_blocked_ = true;
      return statusOnly(Status::PinAuthInvalid);
    }
    pin_auth_failures_ = 0;
    uv = true;
  }

  auto visible_count = [&](bool verified) {
    std::size_t count = 0;
    bool hidden = false;
    for (const Candidate& candidate : pool) {
      const Credential& cred = candidate.is_wrapped ? candidate.wrapped : *candidate.resident;
      if (credVisible(cred, verified, candidate.in_allow)) ++count;
      else hidden = true;
    }
    return std::pair{count, hidden};
  };
  auto [count, hidden] = visible_count(uv);
  if (count == 0 && hidden && !uv) {
    if (options.uv) {
      const Status verified = ask(presence_, io, rp_id_v->text(), "verify it is you", true);
      if (verified != Status::Ok) return statusOnly(verified);
      uv = true;
      up = true;
      std::tie(count, hidden) = visible_count(uv);
    } else {
      return statusOnly(Status::PuatRequired);
    }
  }
  if (count == 0) return statusOnly(Status::NoCredentials);
  if (!uv && options.uv) {
    const Status verified = ask(presence_, io, rp_id_v->text(), "verify it is you", true);
    if (verified != Status::Ok) return statusOnly(verified);
    uv = true;
    up = true;
    std::tie(count, hidden) = visible_count(uv);
    if (count == 0) return statusOnly(Status::NoCredentials);
  }
  if (options.up && !up) {
    const Status touched = ask(presence_, io, rp_id_v->text(), "sign in", false);
    if (touched != Status::Ok) return statusOnly(touched);
    up = true;
  }

  pending_ = {};
  pending_.client_data_hash = client_hash->bytes();
  pending_.uv = uv;
  pending_.up = up;
  if (const Cbor* extensions = params->find(4); extensions && extensions->kind() == Cbor::Kind::Map) {
    if (const Cbor* hmac = extensions->find("hmac-secret"); hmac && hmac->kind() == Cbor::Kind::Map) {
      const Cbor* agreement = hmac->find(1);
      const Cbor* salt_enc = hmac->find(2);
      const Cbor* salt_auth = hmac->find(3);
      if (agreement == nullptr || salt_enc == nullptr || salt_auth == nullptr) {
        return statusOnly(Status::MissingParameter);
      }
      int protocol = 1;
      if (const Cbor* version = hmac->find(4)) {
        if (version->kind() != Cbor::Kind::Int) return statusOnly(Status::InvalidOption);
        protocol = static_cast<int>(version->integer());
      }
      if (protocol != 1 && protocol != 2) return statusOnly(Status::InvalidParameter);
      if (agreement_priv_.size() != 32) return statusOnly(Status::MissingParameter);
      P256Public peer;
      if (!parseCose(*agreement, peer)) return statusOnly(Status::InvalidParameter);
      std::array<std::uint8_t, 32> scalar{};
      std::memcpy(scalar.data(), agreement_priv_.data(), 32);
      const auto x = keyFromState(scalar).ecdhX(peer);
      OPENSSL_cleanse(agreement_priv_.data(), agreement_priv_.size());
      agreement_priv_.clear();
      const PinKeys shared = derivePinKeys(protocol, x);
      if (salt_enc->kind() != Cbor::Kind::Bytes || salt_auth->kind() != Cbor::Kind::Bytes) {
        return statusOnly(Status::CborUnexpectedType);
      }
      const auto mac = pinMac(shared, salt_enc->bytes());
      if (!constantTimeEqual(mac, salt_auth->bytes())) return statusOnly(Status::InvalidParameter);
      auto salts = pinDecrypt(shared, salt_enc->bytes());
      if (salts.size() != 32 && salts.size() != 64) return statusOnly(Status::InvalidLength);
      pending_.have_hmac = true;
      pending_.hmac_protocol = protocol;
      pending_.hmac_salts = std::move(salts);
      pending_.hmac_shared_mac.assign(shared.hmac.begin(), shared.hmac.end());
      pending_.hmac_shared_aes.assign(shared.aes.begin(), shared.aes.end());
    }
  }

  for (Candidate& candidate : pool) {
    const Credential& cred = candidate.is_wrapped ? candidate.wrapped : *candidate.resident;
    if (!credVisible(cred, uv, candidate.in_allow)) continue;
    if (candidate.is_wrapped) {
      candidate.wrapped.rp_id = rp_id_v->text();
      pending_.credentials.push_back(std::move(candidate.wrapped));
    } else {
      pending_.credentials.push_back(*candidate.resident);
    }
  }
  if (pending_.credentials.empty()) return statusOnly(Status::NoCredentials);
  pending_.index = 0;
  have_pending_ = pending_.credentials.size() > 1;
  return getNextAssertion(io);
}

std::vector<std::uint8_t> Authenticator::getNextAssertion(Keepalive& io) {
  (void)io;
  if (pending_.credentials.empty() || pending_.index >= pending_.credentials.size()) {
    have_pending_ = false;
    return statusOnly(Status::NoOperations);
  }
  Credential& cred = pending_.credentials[pending_.index];
  const bool discoverable = !cred.wrapped && cred.discoverable;
  std::uint32_t counter = 0;
  if (discoverable) {
    for (Credential& stored : store_.state().credentials) {
      if (stored.discoverable && stored.id == cred.id) {
        counter = ++stored.sign_count;
        cred.sign_count = counter;
        break;
      }
    }
  } else {
    counter = ++store_.state().global_counter;
  }
  const auto rp_hash_bytes = hashRp(cred.rp_id);

  std::vector<std::pair<std::string, Cbor>> extension_fields;
  if (pending_.have_hmac && cred.hmac_secret.size() == 32 &&
      (pending_.hmac_salts.size() == 32 || pending_.hmac_salts.size() == 64)) {
    std::vector<std::uint8_t> output = [&] {
      std::vector<std::uint8_t> bytes;
      auto first = hmacSha256(cred.hmac_secret, std::span<const std::uint8_t>(pending_.hmac_salts.data(), 32));
      bytes.insert(bytes.end(), first.begin(), first.end());
      if (pending_.hmac_salts.size() == 64) {
        auto second = hmacSha256(cred.hmac_secret,
                                 std::span<const std::uint8_t>(pending_.hmac_salts.data() + 32, 32));
        bytes.insert(bytes.end(), second.begin(), second.end());
      }
      return bytes;
    }();
    PinKeys shared;
    shared.version = pending_.hmac_protocol;
    std::memcpy(shared.hmac.data(), pending_.hmac_shared_mac.data(), 32);
    std::memcpy(shared.aes.data(), pending_.hmac_shared_aes.data(), 32);
    extension_fields.emplace_back("hmac-secret", Cbor::bytes(pinEncrypt(shared, output)));
  }
  if (pending_.uv && !cred.cred_blob.empty()) {
    extension_fields.emplace_back("credBlob", Cbor::bytes(cred.cred_blob));
  }
  std::optional<Cbor> extensions;
  std::uint8_t flags = 0;
  if (pending_.up) flags |= kFlagUp;
  if (pending_.uv) flags |= kFlagUv;
  if (!extension_fields.empty()) {
    flags |= kFlagEd;
    extensions = Cbor::textMap(std::move(extension_fields));
  }
  auto auth_data = authenticatorData(rp_hash_bytes, flags, counter, store_.state().aaguid, nullptr, nullptr,
                                     extensions ? &*extensions : nullptr);
  std::vector<std::uint8_t> message = auth_data;
  message.insert(message.end(), pending_.client_data_hash.begin(), pending_.client_data_hash.end());
  const auto signature = signEs256(cred.priv, message);
  store_.save();

  std::vector<std::pair<std::int64_t, Cbor>> fields;
  fields.emplace_back(1, Cbor::textMap({{"id", Cbor::bytes(cred.id)}, {"type", Cbor::text("public-key")}}));
  fields.emplace_back(2, Cbor::bytes(std::move(auth_data)));
  fields.emplace_back(3, Cbor::bytes(signature));
  if (discoverable) {
    std::vector<std::pair<std::string, Cbor>> user_fields;
    user_fields.emplace_back("id", Cbor::bytes(cred.user_id));
    if (pending_.uv) {
      user_fields.emplace_back("name", Cbor::text(cred.user_name));
      user_fields.emplace_back("displayName", Cbor::text(cred.user_display_name));
    }
    fields.emplace_back(4, Cbor::textMap(std::move(user_fields)));
  }
  if (pending_.index == 0 && pending_.credentials.size() > 1) {
    fields.emplace_back(5, Cbor::integer(static_cast<std::int64_t>(pending_.credentials.size())));
  }
  ++pending_.index;
  if (pending_.index >= pending_.credentials.size()) have_pending_ = false;
  return okBody(Cbor::intMap(std::move(fields)));
}

std::vector<std::uint8_t> Authenticator::reset(Keepalive& io) {
  const auto age = std::chrono::steady_clock::now() - booted_;
  if (age > std::chrono::seconds(10)) return statusOnly(Status::NotAllowed);
  const Status touched = ask(presence_, io, "fidolizer", "reset this authenticator", true);
  if (touched != Status::Ok) return statusOnly(touched);
  resetState();
  return statusOnly(Status::Ok);
}

std::vector<std::uint8_t> Authenticator::selection(Keepalive& io) {
  const Status touched = ask(presence_, io, "fidolizer", "select this authenticator", false);
  if (touched != Status::Ok) return statusOnly(touched);
  return statusOnly(Status::Ok);
}

std::vector<std::uint8_t> Authenticator::clientPin(std::span<const std::uint8_t> body, Keepalive& io) {
  Status error = Status::Ok;
  auto params = decodeMap(body, error);
  if (!params) return statusOnly(error);
  const Cbor* protocol_v = params->find(1);
  const Cbor* sub_v = params->find(2);
  if (protocol_v == nullptr || sub_v == nullptr) return statusOnly(Status::MissingParameter);
  if (protocol_v->kind() != Cbor::Kind::Int || sub_v->kind() != Cbor::Kind::Int) {
    return statusOnly(Status::CborUnexpectedType);
  }
  const int protocol = static_cast<int>(protocol_v->integer());
  const int sub = static_cast<int>(sub_v->integer());
  if (protocol != 1 && protocol != 2) return statusOnly(Status::InvalidParameter);

  auto consume_shared = [&](const Cbor& cose) -> std::optional<PinKeys> {
    if (agreement_priv_.size() != 32) return std::nullopt;
    P256Public peer;
    if (!parseCose(cose, peer)) return std::nullopt;
    std::array<std::uint8_t, 32> scalar{};
    std::memcpy(scalar.data(), agreement_priv_.data(), 32);
    const auto x = P256Key::fromPrivate(scalar).ecdhX(peer);
    OPENSSL_cleanse(agreement_priv_.data(), agreement_priv_.size());
    agreement_priv_.clear();
    return derivePinKeys(protocol, x);
  };

  auto pin_invalid = [&](Status status) {
    if (status != Status::PinInvalid) return statusOnly(status);
    return withStatus(Status::PinInvalid, Cbor::intMap({{3, Cbor::integer(store_.state().pin_retries)}}));
  };

  auto check_hash = [&](std::span<const std::uint8_t> hash) -> Status {
    if (store_.state().pin_hash.empty()) return Status::PinNotSet;
    if (store_.state().pin_retries == 0) return Status::PinBlocked;
    if (pin_power_cycle_) return Status::PinAuthBlocked;
    const auto presented = hash.size() >= 16 ? hash.first(16) : hash;
    if (presented.size() != 16 || !constantTimeEqual(presented, store_.state().pin_hash)) {
      if (store_.state().pin_retries > 0) --store_.state().pin_retries;
      ++boot_pin_attempts_;
      store_.save();
      if (store_.state().pin_retries == 0) return Status::PinBlocked;
      if (boot_pin_attempts_ >= 3) pin_power_cycle_ = true;
      return Status::PinInvalid;
    }
    store_.state().pin_retries = kPinRetriesMax;
    boot_pin_attempts_ = 0;
    pin_power_cycle_ = false;
    store_.save();
    return Status::Ok;
  };

  auto parse_permissions = [&](std::uint8_t& perms, std::string& rp, bool& bound) -> Status {
    const Cbor* value = params->find(9);
    if (value == nullptr || value->kind() != Cbor::Kind::Int) return Status::MissingParameter;
    if (value->integer() <= 0 || value->integer() > 0xff) return Status::InvalidParameter;
    auto mask = static_cast<std::uint8_t>(value->integer());
    if ((mask & (kPermBio | kPermLarge | kPermConfig)) != 0) return Status::UnauthorizedPermission;
    mask = static_cast<std::uint8_t>(mask & (kPermMake | kPermGet | kPermMgmt));
    if (mask == 0) return Status::InvalidParameter;
    perms = mask;
    if (const Cbor* rp_v = params->find(0x0a)) {
      if (rp_v->kind() != Cbor::Kind::Text) return Status::CborUnexpectedType;
      rp = rp_v->text();
      bound = true;
    }
    return Status::Ok;
  };

  auto issue = [&](const PinKeys& shared, std::uint8_t perms, std::string rp, bool bound) {
    const auto token = randomBytes(protocol == 1 ? 16 : 32);
    auto encrypted = pinEncrypt(shared, token);
    token_.valid = true;
    token_.protocol = protocol;
    token_.token = token;
    token_.permissions = perms;
    token_.rp_id = std::move(rp);
    token_.rp_bound = bound;
    pin_auth_failures_ = 0;
    return okBody(Cbor::intMap({{2, Cbor::bytes(std::move(encrypted))}}));
  };

  switch (sub) {
    case 0x01:
      return okBody(Cbor::intMap({
          {3, Cbor::integer(store_.state().pin_retries)},
          {4, Cbor::boolean(pin_power_cycle_)},
      }));
    case 0x07:
      return okBody(Cbor::intMap({{5, Cbor::integer(8)}}));
    case 0x02: {
      auto key = P256Key::generate();
      if (!agreement_priv_.empty()) OPENSSL_cleanse(agreement_priv_.data(), agreement_priv_.size());
      agreement_priv_.assign(key.privateKey().begin(), key.privateKey().end());
      return okBody(Cbor::intMap({{1, coseAgreement(key.publicKey())}}));
    }
    case 0x03: {
      if (!store_.state().pin_hash.empty()) return statusOnly(Status::NotAllowed);
      const Cbor* agreement = params->find(3);
      const Cbor* pin_auth = params->find(4);
      const Cbor* new_pin = params->find(5);
      if (agreement == nullptr || pin_auth == nullptr || new_pin == nullptr) {
        return statusOnly(Status::MissingParameter);
      }
      if (pin_auth->kind() != Cbor::Kind::Bytes || new_pin->kind() != Cbor::Kind::Bytes) {
        return statusOnly(Status::CborUnexpectedType);
      }
      auto shared = consume_shared(*agreement);
      if (!shared) return statusOnly(Status::PinAuthInvalid);
      if (!constantTimeEqual(pinMac(*shared, new_pin->bytes()), pin_auth->bytes())) {
        return statusOnly(Status::PinAuthInvalid);
      }
      auto plain = pinDecrypt(*shared, new_pin->bytes());
      if (plain.size() != 64) return statusOnly(Status::InvalidLength);
      std::string pin(plain.begin(), plain.end());
      while (!pin.empty() && pin.back() == '\0') pin.pop_back();
      OPENSSL_cleanse(plain.data(), plain.size());
      if (pin.size() < store_.state().min_pin_length || pin.size() > 63) {
        return statusOnly(Status::PinPolicyViolation);
      }
      setPin(pin);
      OPENSSL_cleanse(pin.data(), pin.size());
      return statusOnly(Status::Ok);
    }
    case 0x04: {
      if (store_.state().pin_hash.empty()) return statusOnly(Status::PinNotSet);
      const Cbor* agreement = params->find(3);
      const Cbor* pin_auth = params->find(4);
      const Cbor* new_pin = params->find(5);
      const Cbor* pin_hash_enc = params->find(6);
      if (agreement == nullptr || pin_auth == nullptr || new_pin == nullptr || pin_hash_enc == nullptr) {
        return statusOnly(Status::MissingParameter);
      }
      if (new_pin->kind() != Cbor::Kind::Bytes || pin_hash_enc->kind() != Cbor::Kind::Bytes ||
          pin_auth->kind() != Cbor::Kind::Bytes) {
        return statusOnly(Status::CborUnexpectedType);
      }
      auto shared = consume_shared(*agreement);
      if (!shared) return statusOnly(Status::PinAuthInvalid);
      std::vector<std::uint8_t> mac_input = new_pin->bytes();
      mac_input.insert(mac_input.end(), pin_hash_enc->bytes().begin(), pin_hash_enc->bytes().end());
      if (!constantTimeEqual(pinMac(*shared, mac_input), pin_auth->bytes())) {
        return statusOnly(Status::PinAuthInvalid);
      }
      auto old_hash = pinDecrypt(*shared, pin_hash_enc->bytes());
      const Status checked = check_hash(old_hash);
      OPENSSL_cleanse(old_hash.data(), old_hash.size());
      if (checked != Status::Ok) return pin_invalid(checked);
      auto plain = pinDecrypt(*shared, new_pin->bytes());
      if (plain.size() != 64) return statusOnly(Status::InvalidLength);
      std::string pin(plain.begin(), plain.end());
      while (!pin.empty() && pin.back() == '\0') pin.pop_back();
      OPENSSL_cleanse(plain.data(), plain.size());
      if (pin.size() < store_.state().min_pin_length || pin.size() > 63) {
        return statusOnly(Status::PinPolicyViolation);
      }
      setPin(pin);
      OPENSSL_cleanse(pin.data(), pin.size());
      return statusOnly(Status::Ok);
    }
    case 0x05:
    case 0x09: {
      if (store_.state().pin_hash.empty()) return statusOnly(Status::PinNotSet);
      const Cbor* agreement = params->find(3);
      const Cbor* pin_hash_enc = params->find(6);
      if (agreement == nullptr || pin_hash_enc == nullptr || pin_hash_enc->kind() != Cbor::Kind::Bytes) {
        return statusOnly(Status::MissingParameter);
      }
      std::uint8_t perms = static_cast<std::uint8_t>(kPermMake | kPermGet);
      std::string rp;
      bool bound = false;
      if (sub == 0x09) {
        const Status parsed = parse_permissions(perms, rp, bound);
        if (parsed != Status::Ok) return statusOnly(parsed);
      }
      auto shared = consume_shared(*agreement);
      if (!shared) return statusOnly(Status::PinAuthInvalid);
      auto hash = pinDecrypt(*shared, pin_hash_enc->bytes());
      const Status checked = check_hash(hash);
      OPENSSL_cleanse(hash.data(), hash.size());
      if (checked != Status::Ok) return pin_invalid(checked);
      return issue(*shared, perms, std::move(rp), bound);
    }
    case 0x06: {
      const Cbor* agreement = params->find(3);
      if (agreement == nullptr) return statusOnly(Status::MissingParameter);
      std::uint8_t perms = 0;
      std::string rp;
      bool bound = false;
      const Status parsed = parse_permissions(perms, rp, bound);
      if (parsed != Status::Ok) return statusOnly(parsed);
      auto shared = consume_shared(*agreement);
      if (!shared) return statusOnly(Status::PinAuthInvalid);
      const Status verified = ask(presence_, io, rp.empty() ? "fidolizer" : rp, "verify it is you", true);
      if (verified != Status::Ok) return statusOnly(verified);
      return issue(*shared, perms, std::move(rp), bound);
    }
    default:
      return statusOnly(Status::InvalidParameter);
  }
}

std::vector<std::uint8_t> Authenticator::credMgmt(std::uint8_t cmd, std::span<const std::uint8_t> body) {
  Status error = Status::Ok;
  auto params = decodeMap(body, error);
  if (!params) return statusOnly(error);
  const Cbor* sub_v = params->find(1);
  const Cbor* protocol_v = params->find(3);
  const Cbor* auth_v = params->find(4);
  if (sub_v == nullptr || protocol_v == nullptr || auth_v == nullptr) return statusOnly(Status::MissingParameter);
  if (sub_v->kind() != Cbor::Kind::Int || protocol_v->kind() != Cbor::Kind::Int ||
      auth_v->kind() != Cbor::Kind::Bytes) {
    return statusOnly(Status::CborUnexpectedType);
  }
  const int sub = static_cast<int>(sub_v->integer());
  const int protocol = static_cast<int>(protocol_v->integer());
  if (pin_auth_blocked_) return statusOnly(Status::PinAuthBlocked);
  if (!token_.valid || token_.protocol != protocol || (token_.permissions & kPermMgmt) == 0) {
    return statusOnly(Status::PinAuthInvalid);
  }
  std::vector<std::uint8_t> message{cmd, static_cast<std::uint8_t>(sub)};
  if (const Cbor* sub_params = params->find(2)) {
    std::vector<std::uint8_t> encoded;
    const std::vector<std::uint8_t>* raw = &sub_params->raw();
    if (raw->empty()) {
      encoded = sub_params->encode();
      raw = &encoded;
    }
    message.insert(message.end(), raw->begin(), raw->end());
  }
  const auto mac = tokenMac(protocol, token_.token, message);
  if (!constantTimeEqual(mac, auth_v->bytes())) {
    if (++pin_auth_failures_ >= 3) pin_auth_blocked_ = true;
    return statusOnly(Status::PinAuthInvalid);
  }
  pin_auth_failures_ = 0;

  auto residents = [&] {
    std::vector<std::size_t> indexes;
    for (std::size_t i = 0; i < store_.state().credentials.size(); ++i) {
      if (store_.state().credentials[i].discoverable) indexes.push_back(i);
    }
    return indexes;
  };

  auto rp_response = [&](const std::string& rp, bool with_total, std::int64_t total) {
    std::string name;
    for (const Credential& cred : store_.state().credentials) {
      if (cred.discoverable && cred.rp_id == rp) {
        name = cred.rp_name;
        break;
      }
    }
    const auto digest = hashRp(rp);
    std::vector<std::pair<std::int64_t, Cbor>> fields;
    fields.emplace_back(3, Cbor::textMap({{"id", Cbor::text(rp)}, {"name", Cbor::text(name)}}));
    fields.emplace_back(4, Cbor::bytes(std::span<const std::uint8_t>(digest.data(), digest.size())));
    if (with_total) fields.emplace_back(5, Cbor::integer(total));
    return okBody(Cbor::intMap(std::move(fields)));
  };

  auto cred_response = [&](const Credential& cred, bool with_total, std::int64_t total) {
    std::array<std::uint8_t, 32> scalar{};
    std::memcpy(scalar.data(), cred.priv.data(), 32);
    const auto pub = P256Key::fromPrivate(scalar).publicKey();
    std::vector<std::pair<std::int64_t, Cbor>> fields;
    fields.emplace_back(6, Cbor::textMap({
                                {"id", Cbor::bytes(cred.user_id)},
                                {"name", Cbor::text(cred.user_name)},
                                {"displayName", Cbor::text(cred.user_display_name)},
                            }));
    fields.emplace_back(7, Cbor::bytes(cred.id));
    fields.emplace_back(8, cosePublic(pub));
    if (with_total) fields.emplace_back(9, Cbor::integer(total));
    if (cred.cred_protect != 0) fields.emplace_back(10, Cbor::integer(cred.cred_protect));
    return okBody(Cbor::intMap(std::move(fields)));
  };

  switch (sub) {
    case 0x01: {
      const auto indexes = residents();
      const auto count = static_cast<std::int64_t>(indexes.size());
      const auto remain = static_cast<std::int64_t>(kMaxResidentCredentials - indexes.size());
      return okBody(Cbor::intMap({{1, Cbor::integer(count)}, {2, Cbor::integer(remain)}}));
    }
    case 0x02: {
      std::vector<std::string> rps;
      for (const Credential& cred : store_.state().credentials) {
        if (!cred.discoverable) continue;
        if (std::find(rps.begin(), rps.end(), cred.rp_id) == rps.end()) rps.push_back(cred.rp_id);
      }
      if (rps.empty()) return statusOnly(Status::NoCredentials);
      std::sort(rps.begin(), rps.end());
      cred_enum_.rp_active = true;
      cred_enum_.rps = rps;
      cred_enum_.rp_next = 1;
      return rp_response(rps.front(), true, static_cast<std::int64_t>(rps.size()));
    }
    case 0x03:
      if (!cred_enum_.rp_active || cred_enum_.rp_next >= cred_enum_.rps.size()) {
        return statusOnly(Status::NoCredentials);
      }
      return rp_response(cred_enum_.rps[cred_enum_.rp_next++], false, 0);
    case 0x04: {
      const Cbor* sub_params = params->find(2);
      if (sub_params == nullptr || sub_params->kind() != Cbor::Kind::Map) return statusOnly(Status::MissingParameter);
      const Cbor* hash = sub_params->find(1);
      if (hash == nullptr || hash->kind() != Cbor::Kind::Bytes || hash->bytes().size() != 32) {
        return statusOnly(Status::InvalidParameter);
      }
      std::string rp;
      for (const Credential& cred : store_.state().credentials) {
        if (!cred.discoverable) continue;
        const auto digest = hashRp(cred.rp_id);
        if (constantTimeEqual(digest, hash->bytes())) {
          rp = cred.rp_id;
          break;
        }
      }
      if (rp.empty()) return statusOnly(Status::NoCredentials);
      std::vector<std::size_t> indexes;
      for (std::size_t i = 0; i < store_.state().credentials.size(); ++i) {
        const Credential& cred = store_.state().credentials[i];
        if (cred.discoverable && cred.rp_id == rp) indexes.push_back(i);
      }
      cred_enum_.cred_active = true;
      cred_enum_.cred_rp = rp;
      cred_enum_.creds = indexes;
      cred_enum_.cred_next = 1;
      return cred_response(store_.state().credentials[indexes.front()], true,
                           static_cast<std::int64_t>(indexes.size()));
    }
    case 0x05:
      if (!cred_enum_.cred_active || cred_enum_.cred_next >= cred_enum_.creds.size()) {
        return statusOnly(Status::NoCredentials);
      }
      return cred_response(store_.state().credentials[cred_enum_.creds[cred_enum_.cred_next++]], false, 0);
    case 0x06: {
      const Cbor* sub_params = params->find(2);
      if (sub_params == nullptr || sub_params->kind() != Cbor::Kind::Map) return statusOnly(Status::MissingParameter);
      const Cbor* id = sub_params->find(1);
      if (id == nullptr || id->kind() != Cbor::Kind::Bytes) return statusOnly(Status::MissingParameter);
      auto& creds = store_.state().credentials;
      const auto it = std::find_if(creds.begin(), creds.end(), [&](const Credential& cred) {
        return cred.discoverable && cred.id == id->bytes();
      });
      if (it == creds.end()) return statusOnly(Status::NoCredentials);
      creds.erase(it);
      cred_enum_ = {};
      store_.save();
      return statusOnly(Status::Ok);
    }
    case 0x07: {
      const Cbor* sub_params = params->find(2);
      if (sub_params == nullptr || sub_params->kind() != Cbor::Kind::Map) return statusOnly(Status::MissingParameter);
      const Cbor* id = sub_params->find(1);
      const Cbor* user = sub_params->find(2);
      if (id == nullptr || user == nullptr || id->kind() != Cbor::Kind::Bytes || user->kind() != Cbor::Kind::Map) {
        return statusOnly(Status::MissingParameter);
      }
      for (Credential& cred : store_.state().credentials) {
        if (!cred.discoverable || cred.id != id->bytes()) continue;
        if (const Cbor* user_id = user->find("id"); user_id && user_id->kind() == Cbor::Kind::Bytes) {
          if (user_id->bytes().size() > 64) return statusOnly(Status::LimitExceeded);
          cred.user_id = user_id->bytes();
        }
        if (const Cbor* name = user->find("name"); name && name->kind() == Cbor::Kind::Text) {
          cred.user_name = name->text();
        }
        if (const Cbor* name = user->find("displayName"); name && name->kind() == Cbor::Kind::Text) {
          cred.user_display_name = name->text();
        }
        store_.save();
        return statusOnly(Status::Ok);
      }
      return statusOnly(Status::NoCredentials);
    }
    default:
      return statusOnly(Status::InvalidParameter);
  }
}

std::vector<std::uint8_t> Authenticator::u2f(std::span<const std::uint8_t> apdu, Keepalive& io) {
  auto fail = [](std::uint16_t code) { return sw(code); };
  if (apdu.size() < 4) return fail(0x6700);
  if (apdu[0] != 0x00) return fail(0x6e00);
  const std::uint8_t ins = apdu[1];
  const std::uint8_t p1 = apdu[2];
  std::span<const std::uint8_t> data;
  if (apdu.size() > 5) {
    const std::size_t lc = apdu[4];
    if (apdu.size() < 5 + lc) return fail(0x6700);
    data = apdu.subspan(5, lc);
  }
  try {
    if (ins == 0x03) {
      auto response = std::vector<std::uint8_t>{'U', '2', 'F', '_', 'V', '2'};
      auto tail = sw(0x9000);
      response.insert(response.end(), tail.begin(), tail.end());
      return response;
    }
    if (ins == 0x01) {
      if (data.size() != 64) return fail(0x6700);
      const auto challenge = data.first(32);
      std::array<std::uint8_t, 32> application{};
      std::memcpy(application.data(), data.data() + 32, 32);
      const Status touched = ask(presence_, io, "u2f", "register", false);
      if (touched != Status::Ok) return fail(0x6985);
      Credential cred;
      auto fresh = P256Key::generate();
      std::memcpy(cred.priv.data(), fresh.privateKey().data(), 32);
      cred.alg = -7;
      cred.id = wrapCredential(cred, store_.state().wrap_key, application);
      if (cred.id.size() > 255) return fail(0x6a80);
      std::vector<std::uint8_t> response{0x05};
      response.push_back(0x04);
      response.insert(response.end(), fresh.publicKey().x.begin(), fresh.publicKey().x.end());
      response.insert(response.end(), fresh.publicKey().y.begin(), fresh.publicKey().y.end());
      response.push_back(static_cast<std::uint8_t>(cred.id.size()));
      response.insert(response.end(), cred.id.begin(), cred.id.end());
      response.insert(response.end(), store_.state().attestation_cert.begin(),
                      store_.state().attestation_cert.end());
      std::vector<std::uint8_t> signed_data{0x00};
      signed_data.insert(signed_data.end(), application.begin(), application.end());
      signed_data.insert(signed_data.end(), challenge.begin(), challenge.end());
      signed_data.insert(signed_data.end(), cred.id.begin(), cred.id.end());
      signed_data.insert(signed_data.end(), response.begin() + 1, response.begin() + 66);
      std::array<std::uint8_t, 32> att{};
      std::memcpy(att.data(), store_.state().attestation_priv.data(), 32);
      auto signature = P256Key::fromPrivate(att).sign(signed_data);
      response.insert(response.end(), signature.begin(), signature.end());
      auto tail = sw(0x9000);
      response.insert(response.end(), tail.begin(), tail.end());
      ++store_.state().global_counter;
      store_.save();
      return response;
    }
    if (ins == 0x02) {
      if (data.size() < 65) return fail(0x6700);
      const auto challenge = data.first(32);
      std::array<std::uint8_t, 32> application{};
      std::memcpy(application.data(), data.data() + 32, 32);
      const std::size_t kh_len = data[64];
      if (data.size() < 65 + kh_len) return fail(0x6700);
      const auto key_handle = data.subspan(65, kh_len);
      auto cred = unwrapCredential(key_handle, store_.state().wrap_key, application);
      if (!cred) return fail(0x6a80);
      if (p1 == 0x07) return fail(0x6985);
      std::uint8_t presence = 0x01;
      if (p1 == 0x03 || p1 == 0x00) {
        const Status touched = ask(presence_, io, "u2f", "authenticate", false);
        if (touched != Status::Ok) return fail(0x6985);
      } else if (p1 == 0x08) {
        presence = 0x00;
      } else {
        return fail(0x6a86);
      }
      const std::uint32_t counter = ++store_.state().global_counter;
      std::vector<std::uint8_t> signed_data(application.begin(), application.end());
      signed_data.push_back(presence);
      putBe32(signed_data, counter);
      signed_data.insert(signed_data.end(), challenge.begin(), challenge.end());
      auto signature = signEs256(cred->priv, signed_data);
      store_.save();
      std::vector<std::uint8_t> response{presence};
      putBe32(response, counter);
      response.insert(response.end(), signature.begin(), signature.end());
      auto tail = sw(0x9000);
      response.insert(response.end(), tail.begin(), tail.end());
      return response;
    }
    return fail(0x6d00);
  } catch (const std::exception& ex) {
    std::cerr << "fidolizer: " << ex.what() << '\n';
    return fail(0x6f00);
  }
}

}  // namespace fidolizer
