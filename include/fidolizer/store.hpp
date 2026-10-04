#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace fidolizer {

struct Credential {
  std::vector<std::uint8_t> id;
  std::string rp_id;
  std::string rp_name;
  std::vector<std::uint8_t> user_id;
  std::string user_name;
  std::string user_display_name;
  std::array<std::uint8_t, 32> priv{};
  std::int64_t alg{-7};
  std::uint32_t sign_count{0};
  bool discoverable{false};
  std::uint8_t cred_protect{0};
  std::vector<std::uint8_t> hmac_secret;
  std::vector<std::uint8_t> cred_blob;
  // True for credentials reconstructed from a wrapped id. Not persisted.
  bool wrapped{false};
};

struct State {
  std::array<std::uint8_t, 16> aaguid{};
  std::array<std::uint8_t, 32> wrap_key{};
  std::array<std::uint8_t, 32> attestation_priv{};
  std::vector<std::uint8_t> attestation_cert;
  std::vector<std::uint8_t> pin_hash;
  std::uint8_t pin_retries{8};
  std::uint8_t min_pin_length{4};
  std::uint32_t global_counter{0};
  std::string serial;
  std::vector<Credential> credentials;
};

class StateStore {
 public:
  static StateStore open(const std::filesystem::path& path);

  State& state() noexcept { return state_; }
  const State& state() const noexcept { return state_; }
  const std::filesystem::path& path() const noexcept { return path_; }

  void save();

 private:
  explicit StateStore(std::filesystem::path path) : path_(std::move(path)) {}
  std::filesystem::path path_;
  State state_;
};

}  // namespace fidolizer
