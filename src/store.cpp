#include "fidolizer/store.hpp"

#include "fidolizer/cbor.hpp"
#include "fidolizer/crypto.hpp"
#include "fidolizer/identity.hpp"

#include <openssl/crypto.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <span>
#include <stdexcept>
#include <system_error>

namespace fidolizer {
namespace {

std::vector<std::uint8_t> readAll(int fd) {
  std::vector<std::uint8_t> out;
  std::uint8_t buf[4096];
  while (true) {
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      throw std::runtime_error("read authenticator state");
    }
    if (n == 0) break;
    out.insert(out.end(), buf, buf + n);
  }
  return out;
}

void writeAll(int fd, std::span<const std::uint8_t> data) {
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      throw std::runtime_error("write authenticator state");
    }
    off += static_cast<std::size_t>(n);
  }
}

std::string hex8(std::span<const std::uint8_t> bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = kHex[bytes[i] >> 4];
    out[i * 2 + 1] = kHex[bytes[i] & 0x0f];
  }
  return out;
}

std::array<std::uint8_t, 32> arr32(const std::vector<std::uint8_t>& in, const char* what) {
  if (in.size() != 32) throw std::runtime_error(what);
  std::array<std::uint8_t, 32> out{};
  std::memcpy(out.data(), in.data(), 32);
  return out;
}

const Cbor& need(const Cbor& map, std::int64_t key, const char* what) {
  const Cbor* value = map.find(key);
  if (value == nullptr) throw std::runtime_error(what);
  return *value;
}

Cbor encodeCredential(const Credential& cred) {
  return Cbor::intMap({
      {1, Cbor::bytes(cred.id)},
      {2, Cbor::text(cred.rp_id)},
      {3, Cbor::text(cred.rp_name)},
      {4, Cbor::bytes(cred.user_id)},
      {5, Cbor::text(cred.user_name)},
      {6, Cbor::text(cred.user_display_name)},
      {7, Cbor::bytes(std::span<const std::uint8_t>(cred.priv.data(), cred.priv.size()))},
      {8, Cbor::integer(cred.alg)},
      {9, Cbor::integer(cred.sign_count)},
      {10, Cbor::boolean(cred.discoverable)},
      {11, Cbor::integer(cred.cred_protect)},
      {12, Cbor::bytes(cred.hmac_secret)},
      {13, Cbor::bytes(cred.cred_blob)},
  });
}

Credential decodeCredential(const Cbor& value) {
  if (value.kind() != Cbor::Kind::Map) throw std::runtime_error("credential");
  Credential cred;
  cred.id = need(value, 1, "cred id").bytes();
  cred.rp_id = need(value, 2, "rp id").text();
  if (const Cbor* name = value.find(3); name && name->kind() == Cbor::Kind::Text) cred.rp_name = name->text();
  cred.user_id = need(value, 4, "user id").bytes();
  if (const Cbor* name = value.find(5); name && name->kind() == Cbor::Kind::Text) cred.user_name = name->text();
  if (const Cbor* name = value.find(6); name && name->kind() == Cbor::Kind::Text) {
    cred.user_display_name = name->text();
  }
  cred.priv = arr32(need(value, 7, "priv").bytes(), "credential private key");
  cred.alg = need(value, 8, "alg").integer();
  cred.sign_count = static_cast<std::uint32_t>(need(value, 9, "counter").integer());
  cred.discoverable = need(value, 10, "rk").boolean();
  if (const Cbor* protect = value.find(11); protect && protect->kind() == Cbor::Kind::Int) {
    cred.cred_protect = static_cast<std::uint8_t>(protect->integer());
  }
  if (const Cbor* hmac = value.find(12); hmac && hmac->kind() == Cbor::Kind::Bytes) cred.hmac_secret = hmac->bytes();
  if (const Cbor* blob = value.find(13); blob && blob->kind() == Cbor::Kind::Bytes) cred.cred_blob = blob->bytes();
  return cred;
}

Cbor encodeState(const State& state) {
  std::vector<Cbor> creds;
  creds.reserve(state.credentials.size());
  for (const Credential& cred : state.credentials) {
    if (!cred.discoverable) continue;
    creds.push_back(encodeCredential(cred));
  }
  return Cbor::intMap({
      {0, Cbor::integer(1)},
      {1, Cbor::bytes(std::span<const std::uint8_t>(state.aaguid.data(), state.aaguid.size()))},
      {2, Cbor::bytes(std::span<const std::uint8_t>(state.wrap_key.data(), state.wrap_key.size()))},
      {3, Cbor::bytes(std::span<const std::uint8_t>(state.attestation_priv.data(),
                                                   state.attestation_priv.size()))},
      {4, Cbor::bytes(state.attestation_cert)},
      {5, state.pin_hash.empty() ? Cbor::null() : Cbor::bytes(state.pin_hash)},
      {6, Cbor::integer(state.pin_retries)},
      {7, Cbor::integer(state.min_pin_length)},
      {8, Cbor::integer(state.global_counter)},
      {9, Cbor::text(state.serial)},
      {10, Cbor::array(std::move(creds))},
  });
}

State decodeState(const Cbor& value) {
  if (value.kind() != Cbor::Kind::Map) throw std::runtime_error("state is not a map");
  if (need(value, 0, "version").integer() != 1) throw std::runtime_error("unsupported state version");
  State state;
  const auto& aaguid = need(value, 1, "aaguid").bytes();
  if (aaguid.size() != 16) throw std::runtime_error("aaguid");
  std::memcpy(state.aaguid.data(), aaguid.data(), 16);
  state.wrap_key = arr32(need(value, 2, "wrap").bytes(), "wrap key");
  state.attestation_priv = arr32(need(value, 3, "att").bytes(), "attestation key");
  state.attestation_cert = need(value, 4, "cert").bytes();
  if (const Cbor* pin = value.find(5); pin && pin->kind() == Cbor::Kind::Bytes) state.pin_hash = pin->bytes();
  state.pin_retries = static_cast<std::uint8_t>(need(value, 6, "retries").integer());
  state.min_pin_length = static_cast<std::uint8_t>(need(value, 7, "minpin").integer());
  state.global_counter = static_cast<std::uint32_t>(need(value, 8, "counter").integer());
  state.serial = need(value, 9, "serial").text();
  for (const Cbor& cred : need(value, 10, "creds").array()) {
    state.credentials.push_back(decodeCredential(cred));
  }
  return state;
}

State makeFresh() {
  State state;
  state.aaguid = kAaguid;
  auto wrap = randomBytes(32);
  std::memcpy(state.wrap_key.data(), wrap.data(), 32);
  OPENSSL_cleanse(wrap.data(), wrap.size());
  AttestationIdentity attestation = makeAttestationIdentity(state.aaguid);
  std::memcpy(state.attestation_priv.data(), attestation.key.privateKey().data(), 32);
  state.attestation_cert = std::move(attestation.certificate);
  auto serial = randomBytes(4);
  state.serial = "fidolizer-" + hex8(serial);
  state.pin_retries = 8;
  state.min_pin_length = 4;
  return state;
}

}  // namespace

StateStore StateStore::open(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (!path.parent_path().empty()) {
    std::filesystem::permissions(path.parent_path(), std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
  }
  StateStore store(path);
  if (!std::filesystem::exists(path)) {
    store.state_ = makeFresh();
    store.save();
    return store;
  }
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) throw std::runtime_error("open authenticator state: " + path.string());
  auto bytes = readAll(fd);
  ::close(fd);
  auto decoded = Cbor::decode(bytes);
  OPENSSL_cleanse(bytes.data(), bytes.size());
  if (!decoded) throw std::runtime_error("authenticator state is not valid CBOR: " + path.string());
  store.state_ = decodeState(*decoded);
  return store;
}

void StateStore::save() {
  const auto encoded = encodeState(state_).encode();
  const auto tmp = path_.string() + ".tmp";
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) throw std::runtime_error("open state temp file");
  try {
    writeAll(fd, encoded);
    if (::fsync(fd) != 0) throw std::runtime_error("fsync state");
  } catch (...) {
    ::close(fd);
    ::unlink(tmp.c_str());
    throw;
  }
  ::close(fd);
  if (::rename(tmp.c_str(), path_.c_str()) != 0) {
    ::unlink(tmp.c_str());
    throw std::runtime_error("rename state");
  }
  ::chmod(path_.c_str(), 0600);
}

}  // namespace fidolizer
