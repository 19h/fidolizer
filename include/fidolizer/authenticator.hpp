#pragma once

#include "fidolizer/presence.hpp"
#include "fidolizer/store.hpp"

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace fidolizer {

class Keepalive {
 public:
  virtual ~Keepalive() = default;
  virtual void keepalive(std::uint8_t status) = 0;
  virtual bool cancelled() const = 0;
};

class NullKeepalive final : public Keepalive {
 public:
  void keepalive(std::uint8_t) override {}
  bool cancelled() const override { return cancelled_; }
  void cancel() { cancelled_ = true; }

 private:
  bool cancelled_{false};
};

// CTAP 2.1 / U2F authenticator. CBOR responses are status byte || payload.
class Authenticator {
 public:
  Authenticator(StateStore& store, Presence& presence);

  std::vector<std::uint8_t> cbor(std::span<const std::uint8_t> payload, Keepalive& io);
  std::vector<std::uint8_t> u2f(std::span<const std::uint8_t> apdu, Keepalive& io);

  // Local management, outside CTAP.
  void setPin(std::string_view pin);
  void changePin(std::string_view old_pin, std::string_view new_pin);
  void resetState();

 private:
  StateStore& store_;
  Presence& presence_;
  std::chrono::steady_clock::time_point booted_{std::chrono::steady_clock::now()};

  struct PinUvToken {
    bool valid{false};
    int protocol{0};
    std::vector<std::uint8_t> token;
    std::uint8_t permissions{0};
    std::string rp_id;
    bool rp_bound{false};
  };
  PinUvToken token_;
  int pin_auth_failures_{0};
  bool pin_auth_blocked_{false};
  int boot_pin_attempts_{0};
  bool pin_power_cycle_{false};

  // Outstanding PIN/hmac-secret ECDH private key.
  std::vector<std::uint8_t> agreement_priv_;

  struct PendingAssertion {
    std::vector<std::uint8_t> client_data_hash;
    std::vector<Credential> credentials;
    std::size_t index{0};
    bool uv{false};
    bool up{false};
    std::vector<std::uint8_t> hmac_salts;
    bool have_hmac{false};
    int hmac_protocol{1};
    std::vector<std::uint8_t> hmac_shared_mac;
    std::vector<std::uint8_t> hmac_shared_aes;
  };
  PendingAssertion pending_;
  bool have_pending_{false};

  struct CredEnum {
    bool rp_active{false};
    std::vector<std::string> rps;
    std::size_t rp_next{0};
    bool cred_active{false};
    std::string cred_rp;
    std::vector<std::size_t> creds;
    std::size_t cred_next{0};
  };
  CredEnum cred_enum_;

  std::vector<std::uint8_t> makeCredential(std::span<const std::uint8_t> body, Keepalive& io);
  std::vector<std::uint8_t> getAssertion(std::span<const std::uint8_t> body, Keepalive& io);
  std::vector<std::uint8_t> getNextAssertion(Keepalive& io);
  std::vector<std::uint8_t> getInfo() const;
  std::vector<std::uint8_t> clientPin(std::span<const std::uint8_t> body, Keepalive& io);
  std::vector<std::uint8_t> reset(Keepalive& io);
  std::vector<std::uint8_t> selection(Keepalive& io);
  std::vector<std::uint8_t> credMgmt(std::uint8_t cmd, std::span<const std::uint8_t> body);
};

}  // namespace fidolizer
