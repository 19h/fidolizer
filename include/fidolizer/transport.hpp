#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>

namespace fidolizer {

struct HidConfig {
  std::uint16_t vendor_id{0x1209};
  std::uint16_t product_id{0xF1D2};
  std::string manufacturer{"Fidolizer"};
  std::string product{"Fidolizer FIDO2"};
  std::string serial{"fidolizer"};
};

// 64-byte FIDO HID reports. sendInput is safe to call from any thread.
class ReportTransport {
 public:
  virtual ~ReportTransport() = default;
  virtual void start(std::function<void(std::span<const std::uint8_t>)> on_output) = 0;
  virtual void sendInput(std::span<const std::uint8_t> report) = 0;
  virtual void stop() = 0;
};

std::unique_ptr<ReportTransport> openHidTransport(const HidConfig& config);

}  // namespace fidolizer
