#include "fidolizer/authenticator.hpp"
#include "fidolizer/cbor.hpp"
#include "fidolizer/crypto.hpp"
#include "fidolizer/ctaphid.hpp"
#include "fidolizer/identity.hpp"
#include "fidolizer/json.hpp"
#include "fidolizer/store.hpp"
#include "fidolizer/webauthn.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

int g_failed = 0;

void check(bool cond, const char* expr, const char* file, int line) {
  if (!cond) {
    std::cerr << "FAIL " << file << ":" << line << " " << expr << '\n';
    ++g_failed;
  }
}

#define CHECK(cond) check(static_cast<bool>(cond), #cond, __FILE__, __LINE__)

std::uint32_t be32(const std::uint8_t* p) {
  return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | p[3];
}

std::uint16_t be16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }

void putBe32(std::uint8_t* p, std::uint32_t v) {
  p[0] = static_cast<std::uint8_t>(v >> 24);
  p[1] = static_cast<std::uint8_t>(v >> 16);
  p[2] = static_cast<std::uint8_t>(v >> 8);
  p[3] = static_cast<std::uint8_t>(v);
}

class FakeTransport final : public fidolizer::ReportTransport {
 public:
  void start(std::function<void(std::span<const std::uint8_t>)>) override {}
  void sendInput(std::span<const std::uint8_t> report) override {
    std::lock_guard lock(mu_);
    sent_.emplace_back(report.begin(), report.end());
  }
  void stop() override {}

  std::vector<std::vector<std::uint8_t>> take() {
    std::lock_guard lock(mu_);
    auto out = std::move(sent_);
    sent_.clear();
    return out;
  }

 private:
  std::mutex mu_;
  std::vector<std::vector<std::uint8_t>> sent_;
};

struct Message {
  std::uint32_t cid{};
  std::uint8_t cmd{};
  std::vector<std::uint8_t> data;
};

std::vector<Message> reassemble(const std::vector<std::vector<std::uint8_t>>& packets) {
  std::vector<Message> out;
  for (std::size_t i = 0; i < packets.size();) {
    const auto& packet = packets[i];
    if (packet.size() < 7 || (packet[4] & 0x80) == 0) {
      ++i;
      continue;
    }
    Message msg;
    msg.cid = be32(packet.data());
    msg.cmd = static_cast<std::uint8_t>(packet[4] & 0x7f);
    const std::uint16_t len = be16(packet.data() + 5);
    const std::size_t first = std::min<std::size_t>(len, 57);
    msg.data.assign(packet.begin() + 7, packet.begin() + 7 + static_cast<std::ptrdiff_t>(first));
    ++i;
    std::uint8_t seq = 0;
    while (msg.data.size() < len && i < packets.size()) {
      const auto& cont = packets[i];
      if (cont.size() < 5 || cont[4] != seq || be32(cont.data()) != msg.cid) break;
      const std::size_t need = len - msg.data.size();
      const std::size_t take = std::min<std::size_t>(need, 59);
      msg.data.insert(msg.data.end(), cont.begin() + 5, cont.begin() + 5 + static_cast<std::ptrdiff_t>(take));
      ++seq;
      ++i;
    }
    out.push_back(std::move(msg));
  }
  return out;
}

void sendPackets(fidolizer::Ctaphid& hid, std::uint32_t cid, std::uint8_t cmd,
                 std::span<const std::uint8_t> payload) {
  std::array<std::uint8_t, 64> packet{};
  putBe32(packet.data(), cid);
  packet[4] = static_cast<std::uint8_t>(cmd | 0x80);
  packet[5] = static_cast<std::uint8_t>(payload.size() >> 8);
  packet[6] = static_cast<std::uint8_t>(payload.size());
  const std::size_t first = std::min<std::size_t>(payload.size(), 57);
  if (first) std::memcpy(packet.data() + 7, payload.data(), first);
  hid.handleReport(packet);
  std::size_t off = first;
  std::uint8_t seq = 0;
  while (off < payload.size()) {
    std::array<std::uint8_t, 64> cont{};
    putBe32(cont.data(), cid);
    cont[4] = seq++;
    const std::size_t n = std::min<std::size_t>(payload.size() - off, 59);
    std::memcpy(cont.data() + 5, payload.data() + off, n);
    off += n;
    hid.handleReport(cont);
  }
}

Message exchange(fidolizer::Ctaphid& hid, FakeTransport& transport, std::uint32_t cid, std::uint8_t cmd,
                 std::span<const std::uint8_t> payload) {
  transport.take();
  sendPackets(hid, cid, cmd, payload);
  auto messages = reassemble(transport.take());
  for (auto& msg : messages) {
    if (msg.cmd != 0x3b) return msg;
  }
  return {};
}

struct Session {
  std::filesystem::path dir;
  fidolizer::StateStore store;
  fidolizer::Presence presence;
  fidolizer::Authenticator authenticator;
  FakeTransport transport;
  fidolizer::Ctaphid hid;
  std::uint32_t cid{0};

  static std::unique_ptr<Session> open() {
    char tmpl[] = "/tmp/fidolizer-test-XXXXXX";
    if (mkdtemp(tmpl) == nullptr) {
      std::cerr << "mkdtemp failed\n";
      std::exit(1);
    }
    return std::make_unique<Session>(tmpl);
  }

  explicit Session(const char* path)
      : dir(path),
        store(fidolizer::StateStore::open(dir / "state.cbor")),
        presence(fidolizer::PresenceMode::Auto),
        authenticator(store, presence),
        hid(authenticator, transport) {
    std::array<std::uint8_t, 8> nonce{1, 2, 3, 4, 5, 6, 7, 8};
    auto init = exchange(hid, transport, 0xffffffffu, 0x06, nonce);
    CHECK(init.cmd == 0x06);
    CHECK(init.data.size() == 17);
    CHECK(std::memcmp(init.data.data(), nonce.data(), 8) == 0);
    cid = be32(init.data.data() + 8);
    CHECK(cid != 0 && cid != 0xffffffffu);
    CHECK(init.data[12] == 2);
    CHECK((init.data[16] & 0x04) != 0);
  }

  ~Session() { std::filesystem::remove_all(dir); }

  Message cbor(const fidolizer::Cbor& params, std::uint8_t command) {
    auto body = params.encode();
    body.insert(body.begin(), command);
    return exchange(hid, transport, cid, 0x10, body);
  }

  Message cborBytes(std::uint8_t command) {
    const std::uint8_t byte = command;
    return exchange(hid, transport, cid, 0x10, std::span<const std::uint8_t>(&byte, 1));
  }
};

fidolizer::Cbor clientPin(int protocol, int sub, std::vector<std::pair<std::int64_t, fidolizer::Cbor>> extra) {
  extra.insert(extra.begin(), {1, fidolizer::Cbor::integer(protocol)});
  extra.insert(extra.begin() + 1, {2, fidolizer::Cbor::integer(sub)});
  return fidolizer::Cbor::intMap(std::move(extra));
}

fidolizer::P256Key platformKey() { return fidolizer::P256Key::generate(); }

fidolizer::PinKeys agree(Session& session, int protocol, fidolizer::P256Key& platform) {
  auto resp = session.cbor(clientPin(protocol, 0x02, {}), 0x06);
  CHECK(resp.cmd == 0x10);
  CHECK(!resp.data.empty() && resp.data[0] == 0);
  auto body = fidolizer::Cbor::decode(std::span<const std::uint8_t>(resp.data.data() + 1, resp.data.size() - 1));
  CHECK(body.has_value());
  fidolizer::P256Public peer;
  const fidolizer::Cbor* key = body->find(1);
  CHECK(key != nullptr);
  const fidolizer::Cbor* x = key->find(-2);
  const fidolizer::Cbor* y = key->find(-3);
  CHECK(x && y && x->bytes().size() == 32 && y->bytes().size() == 32);
  std::memcpy(peer.x.data(), x->bytes().data(), 32);
  std::memcpy(peer.y.data(), y->bytes().data(), 32);
  const auto secret = platform.ecdhX(peer);
  return fidolizer::derivePinKeys(protocol, secret);
}

void testCbor() {
  auto map = fidolizer::Cbor::intMap({{24, fidolizer::Cbor::integer(1)}, {1, fidolizer::Cbor::integer(2)}});
  auto encoded = map.encode();
  CHECK(encoded[0] == 0xa2);
  CHECK(encoded[1] == 0x01);
  auto decoded = fidolizer::Cbor::decode(encoded);
  CHECK(decoded.has_value());
  CHECK(decoded->find(1)->integer() == 2);
  CHECK(decoded->find(24)->integer() == 1);
  auto text = fidolizer::Cbor::textMap({{"uv", fidolizer::Cbor::boolean(true)},
                                        {"rk", fidolizer::Cbor::boolean(false)}});
  auto text_bytes = text.encode();
  CHECK(text_bytes[1] == 0x62);
  CHECK(text_bytes[2] == 'r');
}

void testCrypto() {
  auto key = fidolizer::P256Key::generate();
  const std::uint8_t msg[] = "hello";
  auto sig = key.sign(msg);
  CHECK(fidolizer::verifyEs256(key.publicKey(), msg, sig));
  sig[sig.size() / 2] ^= 0x01;
  CHECK(!fidolizer::verifyEs256(key.publicKey(), msg, sig));

  std::array<std::uint8_t, 32> x{};
  x.fill(0x11);
  auto keys = fidolizer::derivePinKeys(1, x);
  std::vector<std::uint8_t> plain(16, 0xab);
  auto cipher = fidolizer::pinEncrypt(keys, plain);
  CHECK(cipher.size() == 16);
  auto back = fidolizer::pinDecrypt(keys, cipher);
  CHECK(back == plain);
  auto v2 = fidolizer::derivePinKeys(2, x);
  auto cipher2 = fidolizer::pinEncrypt(v2, plain);
  CHECK(cipher2.size() == 32);
  CHECK(fidolizer::pinDecrypt(v2, cipher2) == plain);
  CHECK(fidolizer::pinMac(keys, plain).size() == 16);
  CHECK(fidolizer::pinMac(v2, plain).size() == 32);

  auto id = fidolizer::makeAttestationIdentity(fidolizer::kAaguid);
  CHECK(fidolizer::verifyEs256Certificate(id.certificate, msg, id.key.sign(msg)));
  bool saw = false;
  for (std::size_t i = 0; i + 16 <= id.certificate.size(); ++i) {
    if (std::memcmp(id.certificate.data() + i, fidolizer::kAaguid.data(), 16) == 0) saw = true;
  }
  CHECK(saw);
}

void testMakeAndGet() {
  auto owned = Session::open();
  Session& session = *owned;
  auto info = session.cborBytes(0x04);
  CHECK(info.cmd == 0x10);
  CHECK(!info.data.empty() && info.data[0] == 0);
  auto info_body =
      fidolizer::Cbor::decode(std::span<const std::uint8_t>(info.data.data() + 1, info.data.size() - 1));
  CHECK(info_body.has_value());
  CHECK(info_body->find(3)->bytes().size() == 16);
  CHECK(std::memcmp(info_body->find(3)->bytes().data(), fidolizer::kAaguid.data(), 16) == 0);
  CHECK(info_body->find(4)->find("clientPin")->boolean() == false);
  CHECK(info_body->find(4)->find("rk")->boolean() == true);
  CHECK(info_body->find(9)->array()[0].text() == "usb");

  std::vector<std::uint8_t> hash(32, 0x42);
  auto made = session.cbor(
      fidolizer::Cbor::intMap({
          {1, fidolizer::Cbor::bytes(hash)},
          {2, fidolizer::Cbor::textMap({{"id", fidolizer::Cbor::text("example.com")},
                                        {"name", fidolizer::Cbor::text("Example")}})},
          {3, fidolizer::Cbor::textMap({{"id", fidolizer::Cbor::bytes(std::vector<std::uint8_t>{1, 2, 3, 4})},
                                        {"name", fidolizer::Cbor::text("ada")},
                                        {"displayName", fidolizer::Cbor::text("Ada")}})},
          {4, fidolizer::Cbor::array({fidolizer::Cbor::textMap(
                  {{"type", fidolizer::Cbor::text("public-key")}, {"alg", fidolizer::Cbor::integer(-7)}})})},
          {7, fidolizer::Cbor::textMap({{"rk", fidolizer::Cbor::boolean(false)}})},
      }),
      0x01);
  CHECK(made.data.size() > 1);
  CHECK(made.data[0] == 0);
  auto attestation =
      fidolizer::Cbor::decode(std::span<const std::uint8_t>(made.data.data() + 1, made.data.size() - 1));
  CHECK(attestation.has_value());
  CHECK(attestation->find(1)->text() == "packed");
  const auto& auth_data = attestation->find(2)->bytes();
  CHECK(auth_data.size() > 37);
  CHECK((auth_data[32] & 0x01) != 0);
  CHECK((auth_data[32] & 0x40) != 0);
  const auto sig = attestation->find(3)->find("sig")->bytes();
  const auto cert = attestation->find(3)->find("x5c")->array()[0].bytes();
  std::vector<std::uint8_t> signed_bytes = auth_data;
  signed_bytes.insert(signed_bytes.end(), hash.begin(), hash.end());
  CHECK(fidolizer::verifyEs256Certificate(cert, signed_bytes, sig));

  const std::uint16_t id_len = be16(auth_data.data() + 53);
  std::vector<std::uint8_t> cred_id(auth_data.begin() + 55, auth_data.begin() + 55 + id_len);
  std::vector<std::uint8_t> assertion_hash(32, 0x99);
  auto assertion = session.cbor(
      fidolizer::Cbor::intMap({
          {1, fidolizer::Cbor::text("example.com")},
          {2, fidolizer::Cbor::bytes(assertion_hash)},
          {3, fidolizer::Cbor::array({fidolizer::Cbor::textMap(
                  {{"type", fidolizer::Cbor::text("public-key")}, {"id", fidolizer::Cbor::bytes(cred_id)}})})},
      }),
      0x02);
  CHECK(!assertion.data.empty() && assertion.data[0] == 0);
  auto assertion_body = fidolizer::Cbor::decode(
      std::span<const std::uint8_t>(assertion.data.data() + 1, assertion.data.size() - 1));
  CHECK(assertion_body.has_value());
  const auto& assert_auth = assertion_body->find(2)->bytes();
  CHECK((assert_auth[32] & 0x01) != 0);
  CHECK((assert_auth[32] & 0x40) == 0);
  auto cose = fidolizer::Cbor::decode(std::span<const std::uint8_t>(auth_data.data() + 55 + id_len,
                                                                   auth_data.size() - (55 + id_len)));
  CHECK(cose.has_value());
  fidolizer::P256Public pub;
  std::memcpy(pub.x.data(), cose->find(-2)->bytes().data(), 32);
  std::memcpy(pub.y.data(), cose->find(-3)->bytes().data(), 32);
  std::vector<std::uint8_t> assert_message = assert_auth;
  assert_message.insert(assert_message.end(), assertion_hash.begin(), assertion_hash.end());
  CHECK(fidolizer::verifyEs256(pub, assert_message, assertion_body->find(3)->bytes()));
}

void testPinAndResident() {
  auto owned = Session::open();
  Session& session = *owned;
  auto platform = platformKey();
  auto shared = agree(session, 2, platform);
  std::string pin = "correct-horse";
  std::vector<std::uint8_t> padded(64, 0);
  std::memcpy(padded.data(), pin.data(), pin.size());
  auto enc = fidolizer::pinEncrypt(shared, padded);
  auto mac = fidolizer::pinMac(shared, enc);
  auto set = session.cbor(clientPin(2, 0x03,
                                    {
                                        {3, fidolizer::Cbor::intMap({
                                                {1, fidolizer::Cbor::integer(2)},
                                                {3, fidolizer::Cbor::integer(-25)},
                                                {-1, fidolizer::Cbor::integer(1)},
                                                {-2, fidolizer::Cbor::bytes(std::span(platform.publicKey().x.data(), 32))},
                                                {-3, fidolizer::Cbor::bytes(std::span(platform.publicKey().y.data(), 32))},
                                            })},
                                        {4, fidolizer::Cbor::bytes(mac)},
                                        {5, fidolizer::Cbor::bytes(enc)},
                                    }),
                          0x06);
  CHECK(!set.data.empty() && set.data[0] == 0);

  auto reloaded = fidolizer::StateStore::open(session.store.path());
  CHECK(!reloaded.state().pin_hash.empty());

  platform = platformKey();
  shared = agree(session, 2, platform);
  auto digest = fidolizer::sha256(std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(pin.data()), pin.size()));
  std::vector<std::uint8_t> pin_hash(digest.begin(), digest.begin() + 16);
  auto hash_enc = fidolizer::pinEncrypt(shared, pin_hash);
  fidolizer::Cbor agreement = fidolizer::Cbor::intMap({
      {1, fidolizer::Cbor::integer(2)},
      {3, fidolizer::Cbor::integer(-25)},
      {-1, fidolizer::Cbor::integer(1)},
      {-2, fidolizer::Cbor::bytes(std::span(platform.publicKey().x.data(), 32))},
      {-3, fidolizer::Cbor::bytes(std::span(platform.publicKey().y.data(), 32))},
  });
  auto token_msg = session.cbor(clientPin(2, 0x09,
                                          {
                                              {3, agreement},
                                              {6, fidolizer::Cbor::bytes(hash_enc)},
                                              {9, fidolizer::Cbor::integer(0x01 | 0x02 | 0x04)},
                                          }),
                                0x06);
  CHECK(!token_msg.data.empty() && token_msg.data[0] == 0);
  auto token_body = fidolizer::Cbor::decode(
      std::span<const std::uint8_t>(token_msg.data.data() + 1, token_msg.data.size() - 1));
  auto token = fidolizer::pinDecrypt(shared, token_body->find(2)->bytes());
  CHECK(token.size() == 32);

  std::vector<std::uint8_t> hash(32, 0x11);
  auto param = fidolizer::tokenMac(2, token, hash);
  auto made = session.cbor(
      fidolizer::Cbor::intMap({
          {1, fidolizer::Cbor::bytes(hash)},
          {2, fidolizer::Cbor::textMap({{"id", fidolizer::Cbor::text("rk.example")},
                                        {"name", fidolizer::Cbor::text("RK")}})},
          {3, fidolizer::Cbor::textMap({{"id", fidolizer::Cbor::bytes(std::vector<std::uint8_t>{9, 9})},
                                        {"name", fidolizer::Cbor::text("ada")},
                                        {"displayName", fidolizer::Cbor::text("Ada")}})},
          {4, fidolizer::Cbor::array({fidolizer::Cbor::textMap(
                  {{"type", fidolizer::Cbor::text("public-key")}, {"alg", fidolizer::Cbor::integer(-7)}})})},
          {6, fidolizer::Cbor::textMap({{"credProtect", fidolizer::Cbor::integer(2)},
                                        {"hmac-secret", fidolizer::Cbor::boolean(true)}})},
          {7, fidolizer::Cbor::textMap({{"rk", fidolizer::Cbor::boolean(true)}})},
          {8, fidolizer::Cbor::bytes(param)},
          {9, fidolizer::Cbor::integer(2)},
      }),
      0x01);
  CHECK(!made.data.empty());
  if (made.data[0] != 0) std::cerr << "make rk status " << std::hex << int(made.data[0]) << '\n';
  CHECK(made.data[0] == 0);

  platform = platformKey();
  shared = agree(session, 2, platform);
  std::vector<std::uint8_t> salt(32, 0x5a);
  auto salt_enc = fidolizer::pinEncrypt(shared, salt);
  auto salt_auth = fidolizer::pinMac(shared, salt_enc);
  std::vector<std::uint8_t> login(32, 0x22);
  auto login_auth = fidolizer::tokenMac(2, token, login);
  auto assertion = session.cbor(
      fidolizer::Cbor::intMap({
          {1, fidolizer::Cbor::text("rk.example")},
          {2, fidolizer::Cbor::bytes(login)},
          {4, fidolizer::Cbor::textMap({{"hmac-secret", fidolizer::Cbor::intMap({
                                                            {1, fidolizer::Cbor::intMap({
                                                                    {1, fidolizer::Cbor::integer(2)},
                                                                    {3, fidolizer::Cbor::integer(-25)},
                                                                    {-1, fidolizer::Cbor::integer(1)},
                                                                    {-2, fidolizer::Cbor::bytes(std::span(
                                                                             platform.publicKey().x.data(), 32))},
                                                                    {-3, fidolizer::Cbor::bytes(std::span(
                                                                             platform.publicKey().y.data(), 32))},
                                                                })},
                                                            {2, fidolizer::Cbor::bytes(salt_enc)},
                                                            {3, fidolizer::Cbor::bytes(salt_auth)},
                                                            {4, fidolizer::Cbor::integer(2)},
                                                        })}})},
          {6, fidolizer::Cbor::bytes(login_auth)},
          {7, fidolizer::Cbor::integer(2)},
      }),
      0x02);
  CHECK(!assertion.data.empty());
  if (assertion.data[0] != 0) {
    std::cerr << "assert rk status " << std::hex << int(assertion.data[0]) << '\n';
  }
  CHECK(assertion.data[0] == 0);
  auto body = fidolizer::Cbor::decode(
      std::span<const std::uint8_t>(assertion.data.data() + 1, assertion.data.size() - 1));
  CHECK(body->find(4)->find("name")->text() == "ada");
  const auto& auth = body->find(2)->bytes();
  CHECK((auth[32] & 0x80) != 0);
  auto ext = fidolizer::Cbor::decode(std::span<const std::uint8_t>(auth.data() + 37, auth.size() - 37));
  CHECK(ext.has_value());
  auto output = fidolizer::pinDecrypt(shared, ext->find("hmac-secret")->bytes());
  CHECK(output.size() == 32);

  auto meta_params = fidolizer::Cbor::intMap({});
  std::vector<std::uint8_t> meta_msg{0x0a, 0x01};
  auto meta_auth = fidolizer::tokenMac(2, token, meta_msg);
  auto meta = session.cbor(fidolizer::Cbor::intMap({
                               {1, fidolizer::Cbor::integer(1)},
                               {3, fidolizer::Cbor::integer(2)},
                               {4, fidolizer::Cbor::bytes(meta_auth)},
                           }),
                           0x0a);
  CHECK(!meta.data.empty() && meta.data[0] == 0);

  platform = platformKey();
  shared = agree(session, 2, platform);
  std::vector<std::uint8_t> bad(16, 0);
  auto bad_enc = fidolizer::pinEncrypt(shared, bad);
  auto bad_resp = session.cbor(clientPin(2, 0x05,
                                         {
                                             {3, fidolizer::Cbor::intMap({
                                                     {1, fidolizer::Cbor::integer(2)},
                                                     {3, fidolizer::Cbor::integer(-25)},
                                                     {-1, fidolizer::Cbor::integer(1)},
                                                     {-2, fidolizer::Cbor::bytes(std::span(
                                                              platform.publicKey().x.data(), 32))},
                                                     {-3, fidolizer::Cbor::bytes(std::span(
                                                              platform.publicKey().y.data(), 32))},
                                                 })},
                                             {6, fidolizer::Cbor::bytes(bad_enc)},
                                         }),
                               0x06);
  CHECK(!bad_resp.data.empty() && bad_resp.data[0] == 0x31);
}

void testU2fAndPing() {
  auto owned = Session::open();
  Session& session = *owned;
  std::vector<std::uint8_t> ping(80, 0x7e);
  auto echoed = exchange(session.hid, session.transport, session.cid, 0x01, ping);
  CHECK(echoed.cmd == 0x01);
  CHECK(echoed.data == ping);

  std::vector<std::uint8_t> apdu{0x00, 0x03, 0x00, 0x00};
  auto version = exchange(session.hid, session.transport, session.cid, 0x03, apdu);
  CHECK(version.cmd == 0x03);
  CHECK(version.data.size() >= 8);
  CHECK(std::string(version.data.begin(), version.data.begin() + 6) == "U2F_V2");
  CHECK(version.data[version.data.size() - 2] == 0x90);

  std::vector<std::uint8_t> reg{0x00, 0x01, 0x00, 0x00, 64};
  reg.insert(reg.end(), 32, 0x10);
  reg.insert(reg.end(), 32, 0x20);
  auto registered = exchange(session.hid, session.transport, session.cid, 0x03, reg);
  CHECK(registered.cmd == 0x03);
  CHECK(registered.data.size() > 70);
  CHECK(registered.data[0] == 0x05);
  CHECK(registered.data.back() == 0x00);
  const std::size_t kh_len = registered.data[66];
  std::vector<std::uint8_t> kh(registered.data.begin() + 67,
                               registered.data.begin() + 67 + static_cast<std::ptrdiff_t>(kh_len));
  std::vector<std::uint8_t> auth{0x00, 0x02, 0x03, 0x00};
  std::vector<std::uint8_t> auth_data;
  auth_data.insert(auth_data.end(), 32, 0x33);
  auth_data.insert(auth_data.end(), 32, 0x20);
  auth_data.push_back(static_cast<std::uint8_t>(kh.size()));
  auth_data.insert(auth_data.end(), kh.begin(), kh.end());
  auth.push_back(static_cast<std::uint8_t>(auth_data.size()));
  auth.insert(auth.end(), auth_data.begin(), auth_data.end());
  auto authenticated = exchange(session.hid, session.transport, session.cid, 0x03, auth);
  CHECK(authenticated.cmd == 0x03);
  CHECK(authenticated.data.size() > 7);
  CHECK(authenticated.data[0] == 0x01);
  CHECK(authenticated.data[authenticated.data.size() - 2] == 0x90);
}

std::array<std::uint8_t, 16> aaguidFromUuid(std::string_view uuid) {
  std::array<std::uint8_t, 16> out{};
  std::size_t written = 0;
  auto nibble = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < uuid.size() && written < out.size();) {
    if (uuid[i] == '-') {
      ++i;
      continue;
    }
    if (i + 1 >= uuid.size()) break;
    const int hi = nibble(uuid[i]);
    const int lo = nibble(uuid[i + 1]);
    if (hi < 0 || lo < 0) break;
    out[written++] = static_cast<std::uint8_t>((hi << 4) | lo);
    i += 2;
  }
  return out;
}

fidolizer::Json webauthnRequest(const std::string& type, const fidolizer::Json& request) {
  return fidolizer::Json::object({
      {"origin", fidolizer::Json::str("https://example.com")},
      {"request", request},
      {"type", fidolizer::Json::str(type)},
  });
}

void testWebAuthnJson() {
  auto owned = Session::open();
  Session& session = *owned;
  std::vector<std::uint8_t> raw_challenge(32, 0x11);
  const std::string challenge = fidolizer::base64UrlEncode(raw_challenge);
  const std::string user_id = fidolizer::base64UrlEncode(std::vector<std::uint8_t>{1, 2, 3, 4});
  auto created_json = fidolizer::Json::parse(fidolizer::transactWebAuthn(
      session.authenticator,
      webauthnRequest(
          "create",
          fidolizer::Json::object({
              {"attestation", fidolizer::Json::str("direct")},
              {"authenticatorSelection",
               fidolizer::Json::object({
                   {"residentKey", fidolizer::Json::str("required")},
                   {"userVerification", fidolizer::Json::str("required")},
               })},
              {"challenge", fidolizer::Json::str(challenge)},
              {"pubKeyCredParams",
               fidolizer::Json::array({fidolizer::Json::object({
                   {"alg", fidolizer::Json::integer(-7)},
                   {"type", fidolizer::Json::str("public-key")},
               })})},
              {"rp", fidolizer::Json::object({
                         {"id", fidolizer::Json::str("example.com")},
                         {"name", fidolizer::Json::str("Example")},
                     })},
              {"user", fidolizer::Json::object({
                          {"displayName", fidolizer::Json::str("Ada")},
                          {"id", fidolizer::Json::str(user_id)},
                          {"name", fidolizer::Json::str("ada")},
                      })},
          }))
          .dump()));
  if (!created_json || created_json->find("error") != nullptr || created_json->find("response") == nullptr) {
    std::cerr << "create failed " << (created_json ? created_json->dump() : std::string("unparsed")) << '\n';
    CHECK(false);
    return;
  }
  CHECK(created_json->find("type")->text() == "public-key");
  CHECK(created_json->find("id")->text() == created_json->find("rawId")->text());
  const fidolizer::Json& created_response = *created_json->find("response");
  auto client_bytes = fidolizer::base64UrlDecode(created_response.find("clientDataJSON")->text());
  CHECK(client_bytes.has_value());
  auto client = fidolizer::Json::parse(std::string(client_bytes->begin(), client_bytes->end()));
  CHECK(client.has_value());
  CHECK(client->find("type")->text() == "webauthn.create");
  CHECK(client->find("challenge")->text() == challenge);
  CHECK(client->find("origin")->text() == "https://example.com");

  auto attestation_bytes = fidolizer::base64UrlDecode(created_response.find("attestationObject")->text());
  CHECK(attestation_bytes.has_value());
  auto attestation = fidolizer::Cbor::decode(*attestation_bytes);
  CHECK(attestation.has_value());
  CHECK(attestation->find("fmt")->text() == "packed");
  const auto& auth_data = attestation->find("authData")->bytes();
  CHECK(auth_data.size() > 53);
  CHECK((auth_data[32] & 0x40) != 0);
  const auto expected_aaguid = aaguidFromUuid("7e0a6c3d-1b94-4e58-9f27-8c4d5a6b7e10");
  CHECK(std::memcmp(expected_aaguid.data(), fidolizer::kAaguid.data(), expected_aaguid.size()) == 0);
  CHECK(std::memcmp(auth_data.data() + 37, expected_aaguid.data(), expected_aaguid.size()) == 0);
  auto response_auth = fidolizer::base64UrlDecode(created_response.find("authenticatorData")->text());
  CHECK(response_auth.has_value());
  CHECK(response_auth->size() > 53);
  CHECK(std::memcmp(response_auth->data() + 37, expected_aaguid.data(), expected_aaguid.size()) == 0);
  const std::uint16_t id_len = be16(auth_data.data() + 53);
  auto cose = fidolizer::Cbor::decode(std::span<const std::uint8_t>(
      auth_data.data() + 55 + id_len, auth_data.size() - (55 + id_len)));
  CHECK(cose.has_value());
  fidolizer::P256Public pub;
  std::memcpy(pub.x.data(), cose->find(-2)->bytes().data(), 32);
  std::memcpy(pub.y.data(), cose->find(-3)->bytes().data(), 32);
  auto spki = fidolizer::base64UrlDecode(created_response.find("publicKey")->text());
  CHECK(spki.has_value());
  CHECK(spki->size() == 27 + 64);
  CHECK(std::memcmp(spki->data() + 27, pub.x.data(), 32) == 0);
  CHECK(std::memcmp(spki->data() + 59, pub.y.data(), 32) == 0);
  const auto& att_sig = attestation->find("attStmt")->find("sig")->bytes();
  const auto& cert = attestation->find("attStmt")->find("x5c")->array()[0].bytes();
  const auto client_hash = fidolizer::sha256(*client_bytes);
  std::vector<std::uint8_t> att_message = auth_data;
  att_message.insert(att_message.end(), client_hash.begin(), client_hash.end());
  CHECK(fidolizer::verifyEs256Certificate(cert, att_message, att_sig));
  auto bad_att = att_sig;
  bad_att[0] = static_cast<std::uint8_t>(bad_att[0] ^ 0xff);
  CHECK(!fidolizer::verifyEs256Certificate(cert, att_message, bad_att));

  struct stat st {};
  CHECK(::stat(session.store.path().c_str(), &st) == 0);
  CHECK((st.st_mode & 0777) == 0600);
  auto stored = fidolizer::StateStore::open(session.store.path());
  CHECK(stored.state().credentials.size() == 1);
  CHECK(stored.state().credentials[0].discoverable);
  CHECK(stored.state().credentials[0].rp_id == "example.com");
  CHECK(stored.state().credentials[0].user_name == "ada");

  std::vector<std::uint8_t> raw_login(32, 0x22);
  const std::string login = fidolizer::base64UrlEncode(raw_login);
  const std::string credential_id = created_json->find("rawId")->text();
  auto asserted_json = fidolizer::Json::parse(fidolizer::transactWebAuthn(
      session.authenticator,
      webauthnRequest(
          "get",
          fidolizer::Json::object({
              {"allowCredentials",
               fidolizer::Json::array({fidolizer::Json::object({
                   {"id", fidolizer::Json::str(credential_id)},
                   {"type", fidolizer::Json::str("public-key")},
               })})},
              {"challenge", fidolizer::Json::str(login)},
              {"rpId", fidolizer::Json::str("example.com")},
              {"userVerification", fidolizer::Json::str("required")},
          }))
          .dump()));
  if (!asserted_json || asserted_json->find("error") != nullptr ||
      asserted_json->find("response") == nullptr) {
    std::cerr << "get failed " << (asserted_json ? asserted_json->dump() : std::string("unparsed")) << '\n';
    CHECK(false);
    return;
  }
  CHECK(asserted_json->find("rawId")->text() == credential_id);
  const fidolizer::Json& asserted_response = *asserted_json->find("response");
  auto assert_client_bytes = fidolizer::base64UrlDecode(asserted_response.find("clientDataJSON")->text());
  CHECK(assert_client_bytes.has_value());
  auto assert_client =
      fidolizer::Json::parse(std::string(assert_client_bytes->begin(), assert_client_bytes->end()));
  CHECK(assert_client.has_value());
  CHECK(assert_client->find("type")->text() == "webauthn.get");
  CHECK(assert_client->find("challenge")->text() == login);
  CHECK(assert_client->find("origin")->text() == "https://example.com");
  auto assert_auth = fidolizer::base64UrlDecode(asserted_response.find("authenticatorData")->text());
  auto assert_sig = fidolizer::base64UrlDecode(asserted_response.find("signature")->text());
  CHECK(assert_auth.has_value());
  CHECK(assert_sig.has_value());
  const auto assert_hash = fidolizer::sha256(*assert_client_bytes);
  std::vector<std::uint8_t> assert_message = *assert_auth;
  assert_message.insert(assert_message.end(), assert_hash.begin(), assert_hash.end());
  CHECK(fidolizer::verifyEs256(pub, assert_message, *assert_sig));
  auto bad_sig = *assert_sig;
  bad_sig[0] = static_cast<std::uint8_t>(bad_sig[0] ^ 0xff);
  CHECK(!fidolizer::verifyEs256(pub, assert_message, bad_sig));
  CHECK(((*assert_auth)[32] & 0x01) != 0);
  const fidolizer::Json* user_handle = asserted_response.find("userHandle");
  CHECK(user_handle != nullptr);
  CHECK(user_handle->kind() == fidolizer::Json::Kind::String);
  CHECK(user_handle->text() == user_id);
}

void testWebAuthnNonResident() {
  auto owned = Session::open();
  Session& session = *owned;
  std::vector<std::uint8_t> raw_challenge(32, 0x33);
  const std::string challenge = fidolizer::base64UrlEncode(raw_challenge);
  const std::string user_id = fidolizer::base64UrlEncode(std::vector<std::uint8_t>{5, 6, 7, 8});
  auto created_json = fidolizer::Json::parse(fidolizer::transactWebAuthn(
      session.authenticator,
      webauthnRequest(
          "create",
          fidolizer::Json::object({
              {"attestation", fidolizer::Json::str("direct")},
              {"authenticatorSelection",
               fidolizer::Json::object({
                   {"residentKey", fidolizer::Json::str("discouraged")},
                   {"userVerification", fidolizer::Json::str("preferred")},
               })},
              {"challenge", fidolizer::Json::str(challenge)},
              {"pubKeyCredParams",
               fidolizer::Json::array({fidolizer::Json::object({
                   {"alg", fidolizer::Json::integer(-7)},
                   {"type", fidolizer::Json::str("public-key")},
               })})},
              {"rp", fidolizer::Json::object({
                         {"id", fidolizer::Json::str("example.com")},
                         {"name", fidolizer::Json::str("Example")},
                     })},
              {"user", fidolizer::Json::object({
                          {"displayName", fidolizer::Json::str("Bea")},
                          {"id", fidolizer::Json::str(user_id)},
                          {"name", fidolizer::Json::str("bea")},
                      })},
          }))
          .dump()));
  if (!created_json || created_json->find("error") != nullptr || created_json->find("response") == nullptr) {
    std::cerr << "non-resident create failed "
              << (created_json ? created_json->dump() : std::string("unparsed")) << '\n';
    CHECK(false);
    return;
  }
  const fidolizer::Json& created_response = *created_json->find("response");
  auto attestation_bytes = fidolizer::base64UrlDecode(created_response.find("attestationObject")->text());
  CHECK(attestation_bytes.has_value());
  auto attestation = fidolizer::Cbor::decode(*attestation_bytes);
  CHECK(attestation.has_value());
  const auto& auth_data = attestation->find("authData")->bytes();
  CHECK(auth_data.size() > 53);
  const auto expected_aaguid = aaguidFromUuid("7e0a6c3d-1b94-4e58-9f27-8c4d5a6b7e10");
  CHECK(std::memcmp(auth_data.data() + 37, expected_aaguid.data(), expected_aaguid.size()) == 0);
  const std::uint16_t id_len = be16(auth_data.data() + 53);
  auto cose = fidolizer::Cbor::decode(std::span<const std::uint8_t>(
      auth_data.data() + 55 + id_len, auth_data.size() - (55 + id_len)));
  CHECK(cose.has_value());
  fidolizer::P256Public pub;
  std::memcpy(pub.x.data(), cose->find(-2)->bytes().data(), 32);
  std::memcpy(pub.y.data(), cose->find(-3)->bytes().data(), 32);

  std::vector<std::uint8_t> raw_login(32, 0x44);
  const std::string login = fidolizer::base64UrlEncode(raw_login);
  const std::string credential_id = created_json->find("rawId")->text();
  auto asserted_json = fidolizer::Json::parse(fidolizer::transactWebAuthn(
      session.authenticator,
      webauthnRequest(
          "get",
          fidolizer::Json::object({
              {"allowCredentials",
               fidolizer::Json::array({fidolizer::Json::object({
                   {"id", fidolizer::Json::str(credential_id)},
                   {"type", fidolizer::Json::str("public-key")},
               })})},
              {"challenge", fidolizer::Json::str(login)},
              {"rpId", fidolizer::Json::str("example.com")},
              {"userVerification", fidolizer::Json::str("preferred")},
          }))
          .dump()));
  if (!asserted_json || asserted_json->find("error") != nullptr ||
      asserted_json->find("response") == nullptr) {
    std::cerr << "non-resident get failed "
              << (asserted_json ? asserted_json->dump() : std::string("unparsed")) << '\n';
    CHECK(false);
    return;
  }
  const fidolizer::Json& asserted_response = *asserted_json->find("response");
  CHECK(asserted_response.find("userHandle") == nullptr);
  CHECK(asserted_json->dump().find("userHandle") == std::string::npos);
  auto assert_client_bytes = fidolizer::base64UrlDecode(asserted_response.find("clientDataJSON")->text());
  auto assert_auth = fidolizer::base64UrlDecode(asserted_response.find("authenticatorData")->text());
  auto assert_sig = fidolizer::base64UrlDecode(asserted_response.find("signature")->text());
  CHECK(assert_client_bytes.has_value());
  CHECK(assert_auth.has_value());
  CHECK(assert_sig.has_value());
  const auto assert_hash = fidolizer::sha256(*assert_client_bytes);
  std::vector<std::uint8_t> assert_message = *assert_auth;
  assert_message.insert(assert_message.end(), assert_hash.begin(), assert_hash.end());
  CHECK(fidolizer::verifyEs256(pub, assert_message, *assert_sig));
}

}  // namespace

int main() {
  testCbor();
  testCrypto();
  testMakeAndGet();
  testPinAndResident();
  testU2fAndPing();
  testWebAuthnJson();
  testWebAuthnNonResident();
  if (g_failed != 0) {
    std::cerr << g_failed << " checks failed\n";
    return 1;
  }
  std::cout << "fidolizer tests passed\n";
  return 0;
}
