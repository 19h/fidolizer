#pragma once

#include <cstdint>
#include <vector>

namespace fidolizer {

enum class Status : std::uint8_t {
  Ok = 0x00,
  InvalidCommand = 0x01,
  InvalidParameter = 0x02,
  InvalidLength = 0x03,
  InvalidSeq = 0x04,
  Timeout = 0x05,
  ChannelBusy = 0x06,
  LockRequired = 0x0a,
  InvalidChannel = 0x0b,
  CborUnexpectedType = 0x11,
  InvalidCbor = 0x12,
  MissingParameter = 0x14,
  LimitExceeded = 0x15,
  CredentialExcluded = 0x19,
  Processing = 0x21,
  InvalidCredential = 0x22,
  NoOperations = 0x25,
  UnsupportedAlgorithm = 0x26,
  OperationDenied = 0x27,
  KeyStoreFull = 0x28,
  UnsupportedOption = 0x2b,
  InvalidOption = 0x2c,
  KeepaliveCancel = 0x2d,
  NoCredentials = 0x2e,
  UserActionTimeout = 0x2f,
  NotAllowed = 0x30,
  PinInvalid = 0x31,
  PinBlocked = 0x32,
  PinAuthInvalid = 0x33,
  PinAuthBlocked = 0x34,
  PinNotSet = 0x35,
  PuatRequired = 0x36,
  PinPolicyViolation = 0x37,
  RequestTooLarge = 0x39,
  ActionTimeout = 0x3a,
  UpRequired = 0x3b,
  UnauthorizedPermission = 0x40,
  Other = 0x7f,
};

inline std::vector<std::uint8_t> statusOnly(Status status) {
  return {static_cast<std::uint8_t>(status)};
}

}  // namespace fidolizer
