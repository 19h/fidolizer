#include "fidolizer/ctaphid.hpp"

#include "fidolizer/crypto.hpp"
#include "fidolizer/identity.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <iostream>
#include <mutex>
#include <thread>

namespace fidolizer {
namespace {

constexpr std::uint8_t kCmdPing = 0x01;
constexpr std::uint8_t kCmdMsg = 0x03;
constexpr std::uint8_t kCmdLock = 0x04;
constexpr std::uint8_t kCmdInit = 0x06;
constexpr std::uint8_t kCmdWink = 0x08;
constexpr std::uint8_t kCmdCbor = 0x10;
constexpr std::uint8_t kCmdCancel = 0x11;
constexpr std::uint8_t kCmdKeepalive = 0x3b;
constexpr std::uint8_t kCmdError = 0x3f;
constexpr std::uint8_t kCapWink = 0x01;
constexpr std::uint8_t kCapCbor = 0x04;
constexpr std::uint32_t kBroadcast = 0xffffffffu;

std::uint32_t readBe32(const std::uint8_t* p) {
  return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | p[3];
}

std::uint16_t readBe16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

void writeBe32(std::uint8_t* p, std::uint32_t value) {
  p[0] = static_cast<std::uint8_t>(value >> 24);
  p[1] = static_cast<std::uint8_t>(value >> 16);
  p[2] = static_cast<std::uint8_t>(value >> 8);
  p[3] = static_cast<std::uint8_t>(value);
}

}  // namespace

Ctaphid::Ctaphid(Authenticator& authenticator, ReportTransport& transport)
    : authenticator_(authenticator), transport_(transport) {}

Ctaphid::~Ctaphid() { requestStop(); }

void Ctaphid::Sink::keepalive(std::uint8_t status) {
  const std::uint8_t byte = status;
  owner_.send(cid_, kCmdKeepalive, std::span<const std::uint8_t>(&byte, 1));
}

void Ctaphid::requestCancel() { cancel_.store(true); }

void Ctaphid::requestStop() { stop_.store(true); }

void Ctaphid::send(std::uint32_t cid, std::uint8_t cmd, std::span<const std::uint8_t> payload) {
  std::lock_guard lock(send_mu_);
  if (payload.size() > kMaxMessage) return;
  std::array<std::uint8_t, kReportSize> packet{};
  writeBe32(packet.data(), cid);
  packet[4] = static_cast<std::uint8_t>(cmd | 0x80);
  packet[5] = static_cast<std::uint8_t>(payload.size() >> 8);
  packet[6] = static_cast<std::uint8_t>(payload.size());
  const std::size_t first = std::min<std::size_t>(payload.size(), 57);
  if (first > 0) std::memcpy(packet.data() + 7, payload.data(), first);
  transport_.sendInput(packet);
  std::size_t offset = first;
  std::uint8_t seq = 0;
  while (offset < payload.size()) {
    std::array<std::uint8_t, kReportSize> cont{};
    writeBe32(cont.data(), cid);
    cont[4] = seq++;
    const std::size_t n = std::min<std::size_t>(payload.size() - offset, 59);
    std::memcpy(cont.data() + 5, payload.data() + offset, n);
    offset += n;
    transport_.sendInput(cont);
  }
}

void Ctaphid::sendError(std::uint32_t cid, std::uint8_t error) {
  const std::uint8_t byte = error;
  send(cid, kCmdError, std::span<const std::uint8_t>(&byte, 1));
}

std::uint32_t Ctaphid::allocateChannel() {
  for (;;) {
    auto bytes = randomBytes(4);
    const std::uint32_t cid = readBe32(bytes.data());
    if (cid == 0 || cid == kBroadcast) continue;
    if (std::find(channels_.begin(), channels_.end(), cid) == channels_.end()) return cid;
  }
}

void Ctaphid::handleInit(std::uint32_t cid, std::span<const std::uint8_t> nonce) {
  std::uint32_t assigned = cid;
  const bool known = std::find(channels_.begin(), channels_.end(), cid) != channels_.end();
  if (cid == kBroadcast || !known) {
    assigned = allocateChannel();
    channels_.push_back(assigned);
  }
  std::uint8_t response[17];
  std::memcpy(response, nonce.data(), 8);
  writeBe32(response + 8, assigned);
  response[12] = 2;
  response[13] = 1;
  response[14] = 0;
  response[15] = 0;
  response[16] = static_cast<std::uint8_t>(kCapWink | kCapCbor);
  send(assigned, kCmdInit, response);
}

void Ctaphid::dispatch(std::uint32_t cid, std::uint8_t cmd, std::span<const std::uint8_t> payload) {
  cancel_.store(false);
  if (locked_cid_ != 0 && locked_cid_ != cid && std::chrono::steady_clock::now() < lock_until_) {
    sendError(cid, 0x06);
    return;
  }
  Sink sink(*this, cid);
  switch (cmd) {
    case kCmdPing:
      send(cid, kCmdPing, payload);
      return;
    case kCmdWink:
      std::cerr << "\a[fidolizer] wink\n";
      send(cid, kCmdWink, {});
      return;
    case kCmdLock:
      if (payload.size() != 1) {
        sendError(cid, 0x03);
        return;
      }
      locked_cid_ = cid;
      lock_until_ = std::chrono::steady_clock::now() + std::chrono::seconds(std::min<int>(payload[0], 10));
      send(cid, kCmdLock, {});
      return;
    case kCmdCbor:
      send(cid, kCmdCbor, authenticator_.cbor(payload, sink));
      return;
    case kCmdMsg:
      send(cid, kCmdMsg, authenticator_.u2f(payload, sink));
      return;
    default:
      sendError(cid, 0x01);
  }
}

void Ctaphid::handleReport(std::span<const std::uint8_t> report) {
  std::array<std::uint8_t, kReportSize> packet{};
  const std::size_t n = std::min(report.size(), packet.size());
  if (n > 0) std::memcpy(packet.data(), report.data(), n);
  const std::uint32_t cid = readBe32(packet.data());
  const std::uint8_t marker = packet[4];
  if ((marker & 0x80) != 0) {
    const std::uint8_t cmd = static_cast<std::uint8_t>(marker & 0x7f);
    const std::uint16_t len = readBe16(packet.data() + 5);
    if (cmd == kCmdCancel) {
      cancel_.store(true);
      return;
    }
    if (len > kMaxMessage) {
      sendError(cid == kBroadcast ? 0xffffffffu : cid, 0x03);
      return;
    }
    if (cmd == kCmdInit) {
      if (len != 8) {
        sendError(cid == kBroadcast ? cid : cid, 0x03);
        return;
      }
      handleInit(cid, std::span<const std::uint8_t>(packet.data() + 7, 8));
      assembly_.active = false;
      return;
    }
    const bool known = std::find(channels_.begin(), channels_.end(), cid) != channels_.end();
    if (cid == kBroadcast || cid == 0 || !known) {
      sendError(cid, 0x0b);
      return;
    }
    assembly_ = {};
    assembly_.active = true;
    assembly_.cid = cid;
    assembly_.cmd = cmd;
    assembly_.total = len;
    const std::size_t take = std::min<std::size_t>(len, 57);
    assembly_.data.assign(packet.data() + 7, packet.data() + 7 + take);
    if (assembly_.data.size() >= len) {
      auto payload = std::move(assembly_.data);
      assembly_.active = false;
      dispatch(cid, cmd, payload);
    }
    return;
  }
  if (!assembly_.active || assembly_.cid != cid || marker != assembly_.next_seq) {
    sendError(cid, 0x04);
    assembly_.active = false;
    return;
  }
  ++assembly_.next_seq;
  const std::size_t need = assembly_.total - assembly_.data.size();
  const std::size_t take = std::min<std::size_t>(need, 59);
  assembly_.data.insert(assembly_.data.end(), packet.data() + 5, packet.data() + 5 + take);
  if (assembly_.data.size() >= assembly_.total) {
    auto payload = std::move(assembly_.data);
    payload.resize(assembly_.total);
    const auto cmd = assembly_.cmd;
    assembly_.active = false;
    dispatch(cid, cmd, payload);
  }
}

void Ctaphid::run() {
  std::mutex mu;
  std::condition_variable cv;
  std::deque<std::vector<std::uint8_t>> queue;
  transport_.start([&](std::span<const std::uint8_t> report) {
    if (report.size() >= 5 && (report[4] & 0x80) != 0 && (report[4] & 0x7f) == kCmdCancel) {
      cancel_.store(true);
    }
    {
      std::lock_guard lock(mu);
      queue.emplace_back(report.begin(), report.end());
    }
    cv.notify_one();
  });
  while (!stop_.load()) {
    std::vector<std::uint8_t> report;
    {
      std::unique_lock lock(mu);
      cv.wait_for(lock, std::chrono::milliseconds(200), [&] { return stop_.load() || !queue.empty(); });
      if (queue.empty()) continue;
      report = std::move(queue.front());
      queue.pop_front();
    }
    handleReport(report);
  }
  transport_.stop();
}

}  // namespace fidolizer
