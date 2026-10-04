#include "fidolizer/transport.hpp"

#include "fidolizer/identity.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <IOKit/hidsystem/IOHIDUserDevice.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>

#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace fidolizer {
namespace {

void putData(CFMutableDictionaryRef dict, const char* key, const void* bytes, CFIndex length) {
  CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
  CFDataRef data = CFDataCreate(kCFAllocatorDefault, static_cast<const UInt8*>(bytes), length);
  CFDictionarySetValue(dict, name, data);
  CFRelease(name);
  CFRelease(data);
}

void putString(CFMutableDictionaryRef dict, const char* key, const std::string& value) {
  CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
  CFStringRef text = CFStringCreateWithCString(kCFAllocatorDefault, value.c_str(), kCFStringEncodingUTF8);
  CFDictionarySetValue(dict, name, text);
  CFRelease(name);
  CFRelease(text);
}

void putInt(CFMutableDictionaryRef dict, const char* key, int value) {
  CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8);
  CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &value);
  CFDictionarySetValue(dict, name, number);
  CFRelease(name);
  CFRelease(number);
}

class MacTransport final : public ReportTransport {
 public:
  explicit MacTransport(HidConfig config) : config_(std::move(config)) {}
  ~MacTransport() override { stop(); }

  void start(std::function<void(std::span<const std::uint8_t>)> on_output) override {
    on_output_ = std::move(on_output);
    CFMutableDictionaryRef properties = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (properties == nullptr) throw std::runtime_error("HID property dictionary");
    putData(properties, kIOHIDReportDescriptorKey, kFidoReportDescriptor, sizeof(kFidoReportDescriptor));
    putInt(properties, kIOHIDVendorIDKey, config_.vendor_id);
    putInt(properties, kIOHIDProductIDKey, config_.product_id);
    putString(properties, kIOHIDProductKey, config_.product);
    putString(properties, kIOHIDManufacturerKey, config_.manufacturer);
    putString(properties, kIOHIDSerialNumberKey, config_.serial);
    // libfido2 on macOS ignores HID devices whose transport is not USB.
    putString(properties, kIOHIDTransportKey, kIOHIDTransportUSBValue);
    putInt(properties, kIOHIDPrimaryUsagePageKey, 0xf1d0);
    putInt(properties, kIOHIDPrimaryUsageKey, 0x01);
    putInt(properties, kIOHIDMaxInputReportSizeKey, static_cast<int>(kReportSize));
    putInt(properties, kIOHIDMaxOutputReportSizeKey, static_cast<int>(kReportSize));
    putInt(properties, kIOHIDVersionNumberKey, 1);

    device_ = IOHIDUserDeviceCreateWithProperties(kCFAllocatorDefault, properties,
                                                  IOHIDUserDeviceOptionsCreateOnActivate);
    CFRelease(properties);
    if (device_ == nullptr) {
      throw std::runtime_error(
          "macOS refused to create a virtual FIDO HID device. IOHIDUserDevice requires the "
          "restricted entitlement com.apple.developer.hid.virtual.device. Enable Virtual HID for "
          "the app identifier in the Apple Developer portal, then codesign this binary with "
          "cmake/fidolizer.entitlements. The call returns NULL without the entitlement. Adding "
          "the entitlement to a signature Apple has not authorized makes macOS kill the process.");
    }

    queue_ = dispatch_queue_create("fidolizer.hid", DISPATCH_QUEUE_SERIAL);
    MacTransport* self = this;
    IOHIDUserDeviceRegisterSetReportBlock(
        device_, ^IOReturn(IOHIDReportType, uint32_t, const uint8_t* report, CFIndex length) {
          if (self->alive_.load()) self->accept(report, length);
          return kIOReturnSuccess;
        });
    IOHIDUserDeviceRegisterGetReportBlock(
        device_, ^IOReturn(IOHIDReportType, uint32_t, uint8_t* report, CFIndex* length) {
          if (!self->alive_.load()) return kIOReturnNotOpen;
          std::lock_guard lock(self->mu_);
          const CFIndex n = *length < static_cast<CFIndex>(kReportSize) ? *length
                                                                        : static_cast<CFIndex>(kReportSize);
          std::memcpy(report, self->last_input_.data(), static_cast<std::size_t>(n));
          *length = n;
          return kIOReturnSuccess;
        });
    IOHIDUserDeviceSetDispatchQueue(device_, queue_);
    IOHIDUserDeviceActivate(device_);
  }

  void sendInput(std::span<const std::uint8_t> report) override {
    std::array<std::uint8_t, kReportSize> packet{};
    const std::size_t n = report.size() < packet.size() ? report.size() : packet.size();
    if (n > 0) std::memcpy(packet.data(), report.data(), n);
    {
      std::lock_guard lock(mu_);
      last_input_ = packet;
    }
    if (device_ != nullptr) {
      IOHIDUserDeviceHandleReportWithTimeStamp(device_, mach_absolute_time(), packet.data(),
                                               static_cast<CFIndex>(packet.size()));
    }
  }

  void stop() override {
    alive_.store(false);
    if (device_ != nullptr) {
      IOHIDUserDeviceCancel(device_);
      CFRelease(device_);
      device_ = nullptr;
    }
    if (queue_ != nullptr) {
      dispatch_release(queue_);
      queue_ = nullptr;
    }
  }

 private:
  void accept(const std::uint8_t* report, CFIndex length) {
    if (!on_output_ || report == nullptr || length <= 0) return;
    std::vector<std::uint8_t> copy(static_cast<std::size_t>(length));
    std::memcpy(copy.data(), report, copy.size());
    on_output_(copy);
  }

  HidConfig config_;
  std::function<void(std::span<const std::uint8_t>)> on_output_;
  IOHIDUserDeviceRef device_{nullptr};
  dispatch_queue_t queue_{nullptr};
  std::mutex mu_;
  std::array<std::uint8_t, kReportSize> last_input_{};
  std::atomic<bool> alive_{true};
};

}  // namespace

std::unique_ptr<ReportTransport> makeMacTransport(const HidConfig& config) {
  return std::make_unique<MacTransport>(config);
}

}  // namespace fidolizer
