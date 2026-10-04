#include "fidolizer/transport.hpp"

#include <stdexcept>

namespace fidolizer {

#if defined(__APPLE__)
std::unique_ptr<ReportTransport> makeMacTransport(const HidConfig& config);
#elif defined(__linux__)
std::unique_ptr<ReportTransport> makeLinuxTransport(const HidConfig& config);
#endif

std::unique_ptr<ReportTransport> openHidTransport(const HidConfig& config) {
#if defined(__APPLE__)
  return makeMacTransport(config);
#elif defined(__linux__)
  return makeLinuxTransport(config);
#else
  (void)config;
  throw std::runtime_error("this operating system has no FIDO HID backend");
#endif
}

}  // namespace fidolizer
