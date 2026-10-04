#pragma once

#include "fidolizer/authenticator.hpp"
#include "fidolizer/transport.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <span>
#include <vector>

namespace fidolizer {

// CTAPHID framing, channels, and keepalive around one authenticator.
class Ctaphid {
 public:
  Ctaphid(Authenticator& authenticator, ReportTransport& transport);
  ~Ctaphid();

  Ctaphid(const Ctaphid&) = delete;
  Ctaphid& operator=(const Ctaphid&) = delete;

  void handleReport(std::span<const std::uint8_t> report);
  void requestCancel();
  void run();
  void requestStop();

 private:
  class Sink final : public Keepalive {
   public:
    Sink(Ctaphid& owner, std::uint32_t cid) : owner_(owner), cid_(cid) {}
    void keepalive(std::uint8_t status) override;
    bool cancelled() const override { return owner_.cancel_.load(); }

   private:
    Ctaphid& owner_;
    std::uint32_t cid_;
  };

  void send(std::uint32_t cid, std::uint8_t cmd, std::span<const std::uint8_t> payload);
  void sendError(std::uint32_t cid, std::uint8_t error);
  std::uint32_t allocateChannel();
  void handleInit(std::uint32_t cid, std::span<const std::uint8_t> nonce);
  void dispatch(std::uint32_t cid, std::uint8_t cmd, std::span<const std::uint8_t> payload);

  Authenticator& authenticator_;
  ReportTransport& transport_;
  std::atomic<bool> cancel_{false};
  std::atomic<bool> stop_{false};
  std::uint32_t locked_cid_{0};
  std::chrono::steady_clock::time_point lock_until_{};
  std::vector<std::uint32_t> channels_;

  struct Assembly {
    bool active{false};
    std::uint32_t cid{0};
    std::uint8_t cmd{0};
    std::uint16_t total{0};
    std::uint8_t next_seq{0};
    std::vector<std::uint8_t> data;
  };
  Assembly assembly_;
  std::mutex send_mu_;
};

}  // namespace fidolizer
