#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace fidolizer {

// Fidolizer's own AAGUID. This identifies this software authenticator in
// authenticator data. It is not registered to another vendor and must not be
// swapped for a metadata-service AAGUID (that would impersonate that product).
// UUID: 7e0a6c3d-1b94-4e58-9f27-8c4d5a6b7e10
inline constexpr std::array<std::uint8_t, 16> kAaguid = {
    0x7e, 0x0a, 0x6c, 0x3d, 0x1b, 0x94, 0x4e, 0x58,
    0x9f, 0x27, 0x8c, 0x4d, 0x5a, 0x6b, 0x7e, 0x10,
};

// pid.codes open-source vendor id, with a Fidolizer product id.
inline constexpr std::uint16_t kDefaultVendorId = 0x1209;
inline constexpr std::uint16_t kDefaultProductId = 0xF1D2;
inline constexpr std::string_view kManufacturer = "Fidolizer";
inline constexpr std::string_view kProductName = "Fidolizer FIDO2";
inline constexpr std::uint32_t kFirmwareVersion = 1;

// CTAP HID report descriptor: usage page 0xF1D0, usage 0x01, 64-byte in/out.
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb
inline constexpr std::uint8_t kFidoReportDescriptor[] = {
    0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00,
    0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21,
    0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
};

inline constexpr std::size_t kReportSize = 64;
inline constexpr std::size_t kMaxMessage = 7609;
inline constexpr std::size_t kMaxResidentCredentials = 128;

}  // namespace fidolizer
