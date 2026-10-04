#include "fidolizer/transport.hpp"

#include "fidolizer/identity.hpp"

#include <linux/uhid.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace fidolizer {
namespace {

class LinuxTransport final : public ReportTransport {
 public:
  explicit LinuxTransport(HidConfig config) : config_(std::move(config)) {}
  ~LinuxTransport() override { stop(); }

  void start(std::function<void(std::span<const std::uint8_t>)> on_output) override {
    on_output_ = std::move(on_output);
    fd_ = ::open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (fd_ < 0) {
      throw std::runtime_error(
          "cannot open /dev/uhid. Load the uhid module and grant this user access "
          "(root, or the uhid group) so Fidolizer can register a HID FIDO device.");
    }
    uhid_event event{};
    event.type = UHID_CREATE2;
    std::snprintf(reinterpret_cast<char*>(event.u.create2.name), sizeof(event.u.create2.name), "%s",
                  config_.product.c_str());
    std::snprintf(reinterpret_cast<char*>(event.u.create2.phys), sizeof(event.u.create2.phys),
                  "fidolizer/hid");
    std::snprintf(reinterpret_cast<char*>(event.u.create2.uniq), sizeof(event.u.create2.uniq), "%s",
                  config_.serial.c_str());
    event.u.create2.rd_size = sizeof(kFidoReportDescriptor);
    event.u.create2.bus = BUS_USB;
    event.u.create2.vendor = config_.vendor_id;
    event.u.create2.product = config_.product_id;
    event.u.create2.version = 1;
    std::memcpy(event.u.create2.rd_data, kFidoReportDescriptor, sizeof(kFidoReportDescriptor));
    if (!writeEvent(event)) {
      ::close(fd_);
      fd_ = -1;
      throw std::runtime_error("UHID_CREATE2 failed");
    }
    stop_.store(false);
    reader_ = std::thread([this] { readLoop(); });
  }

  void sendInput(std::span<const std::uint8_t> report) override {
    uhid_event event{};
    event.type = UHID_INPUT2;
    const std::size_t n = report.size() < kReportSize ? report.size() : kReportSize;
    event.u.input2.size = static_cast<__u16>(kReportSize);
    if (n > 0) std::memcpy(event.u.input2.data, report.data(), n);
    std::lock_guard lock(write_mu_);
    writeEvent(event);
  }

  void stop() override {
    stop_.store(true);
    if (fd_ >= 0) {
      uhid_event event{};
      event.type = UHID_DESTROY;
      {
        std::lock_guard lock(write_mu_);
        writeEvent(event);
      }
      ::shutdown(fd_, SHUT_RDWR);
    }
    if (reader_.joinable()) reader_.join();
    if (fd_ >= 0) {
      ::close(fd_);
      fd_ = -1;
    }
  }

 private:
  bool writeEvent(const uhid_event& event) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(&event);
    std::size_t off = 0;
    while (off < sizeof(event)) {
      const ssize_t n = ::write(fd_, bytes + off, sizeof(event) - off);
      if (n < 0) {
        if (errno == EINTR) continue;
        return false;
      }
      off += static_cast<std::size_t>(n);
    }
    return true;
  }

  void readLoop() {
    while (!stop_.load()) {
      pollfd pfd{};
      pfd.fd = fd_;
      pfd.events = POLLIN;
      const int ready = ::poll(&pfd, 1, 200);
      if (ready < 0) {
        if (errno == EINTR) continue;
        break;
      }
      if (ready == 0) continue;
      uhid_event event{};
      const ssize_t n = ::read(fd_, &event, sizeof(event));
      if (n <= 0) break;
      if (event.type == UHID_OUTPUT || event.type == UHID_SET_REPORT) {
        const std::uint8_t* data = nullptr;
        std::size_t size = 0;
        if (event.type == UHID_OUTPUT) {
          data = event.u.output.data;
          size = event.u.output.size;
        } else {
          data = event.u.set_report.data;
          size = event.u.set_report.size;
          uhid_event reply{};
          reply.type = UHID_SET_REPORT_REPLY;
          reply.u.set_report_reply.id = event.u.set_report.id;
          reply.u.set_report_reply.err = 0;
          std::lock_guard lock(write_mu_);
          writeEvent(reply);
        }
        if (on_output_ && data != nullptr && size > 0) {
          std::vector<std::uint8_t> copy(data, data + size);
          on_output_(copy);
        }
      } else if (event.type == UHID_GET_REPORT) {
        uhid_event reply{};
        reply.type = UHID_GET_REPORT_REPLY;
        reply.u.get_report_reply.id = event.u.get_report.id;
        reply.u.get_report_reply.err = 0;
        reply.u.get_report_reply.size = static_cast<__u16>(kReportSize);
        std::lock_guard lock(write_mu_);
        writeEvent(reply);
      }
    }
  }

  HidConfig config_;
  std::function<void(std::span<const std::uint8_t>)> on_output_;
  int fd_{-1};
  std::mutex write_mu_;
  std::atomic<bool> stop_{false};
  std::thread reader_;
};

}  // namespace

std::unique_ptr<ReportTransport> makeLinuxTransport(const HidConfig& config) {
  return std::make_unique<LinuxTransport>(config);
}

}  // namespace fidolizer
