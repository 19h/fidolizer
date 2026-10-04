#include "fidolizer/authenticator.hpp"
#include "fidolizer/ctaphid.hpp"
#include "fidolizer/identity.hpp"
#include "fidolizer/presence.hpp"
#include "fidolizer/store.hpp"
#include "fidolizer/transport.hpp"
#include "fidolizer/webauthn.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <span>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <cerrno>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace {

std::atomic<fidolizer::Ctaphid*> g_session{nullptr};

void onSignal(int) {
  if (auto* session = g_session.load()) session->requestStop();
}

void usage() {
  std::cerr << R"(fidolizer — software FIDO2 authenticator

Usage:
  fidolizer [serve] [options]
  fidolizer webauthn [options]
  fidolizer info [options]
  fidolizer set-pin [options]
  fidolizer change-pin [options]
  fidolizer reset --yes [options]
  fidolizer credentials [options]
  fidolizer delete <credential-id-hex> [options]

Options:
  --state PATH     State file (default: ~/.fidolizer/authenticator.cbor)
  --up MODE        prompt, auto, or deny (default: prompt)
  --vid 0xNNNN     USB vendor id (default: 0x1209)
  --pid 0xNNNN     USB product id (default: 0xF1D2)
  --pin PIN        PIN for set-pin / change-pin
  --old-pin PIN    Current PIN for change-pin
  -h, --help

`serve` registers a HID FIDO2 device and handles CTAP until interrupted.
On macOS that requires the entitlement com.apple.developer.hid.virtual.device.
On Linux it uses /dev/uhid.

`webauthn` speaks Chrome native messaging on stdin/stdout: a 4-byte
little-endian length and one JSON object
{"type":"create"|"get","origin":"https://…","request":{…}}.
The reply is PublicKeyCredential.toJSON(). This is the macOS path while
SIP stays on and the virtual HID entitlement is not authorized.

The authenticator's AAGUID is 7e0a6c3d-1b94-4e58-9f27-8c4d5a6b7e10.
)";
}

std::filesystem::path defaultState() {
  if (const char* env = std::getenv("FIDOLIZER_STATE")) return env;
  const char* home = std::getenv("HOME");
  if (home == nullptr) home = "/tmp";
  return std::filesystem::path(home) / ".fidolizer" / "authenticator.cbor";
}

std::optional<unsigned long> parseHex(std::string_view text) {
  if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text.remove_prefix(2);
  if (text.empty()) return std::nullopt;
  unsigned long value = 0;
  for (char ch : text) {
    value <<= 4;
    if (ch >= '0' && ch <= '9') value |= static_cast<unsigned long>(ch - '0');
    else if (ch >= 'a' && ch <= 'f') value |= static_cast<unsigned long>(ch - 'a' + 10);
    else if (ch >= 'A' && ch <= 'F') value |= static_cast<unsigned long>(ch - 'A' + 10);
    else return std::nullopt;
  }
  return value;
}

std::vector<std::uint8_t> parseHexBytes(std::string_view text) {
  if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text.remove_prefix(2);
  if (text.size() % 2 != 0) throw std::runtime_error("credential id hex must have an even length");
  std::vector<std::uint8_t> out;
  out.reserve(text.size() / 2);
  auto nibble = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < text.size(); i += 2) {
    const int hi = nibble(text[i]);
    const int lo = nibble(text[i + 1]);
    if (hi < 0 || lo < 0) throw std::runtime_error("credential id is not hex");
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::string toHex(std::span<const std::uint8_t> bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out(bytes.size() * 2, '0');
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = kHex[bytes[i] >> 4];
    out[i * 2 + 1] = kHex[bytes[i] & 0x0f];
  }
  return out;
}

std::string readSecret(const char* prompt) {
  std::cerr << prompt << std::flush;
  const int tty = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
  const int fd = tty >= 0 ? tty : STDIN_FILENO;
  termios saved{};
  const bool have_tty = ::tcgetattr(fd, &saved) == 0;
  if (have_tty) {
    termios hidden = saved;
    hidden.c_lflag = static_cast<tcflag_t>(hidden.c_lflag & ~static_cast<tcflag_t>(ECHO));
    ::tcsetattr(fd, TCSAFLUSH, &hidden);
  }
  std::string pin;
  char byte = 0;
  while (::read(fd, &byte, 1) == 1 && byte != '\n') pin.push_back(byte);
  if (have_tty) ::tcsetattr(fd, TCSAFLUSH, &saved);
  if (tty >= 0) ::close(tty);
  std::cerr << '\n';
  return pin;
}

fidolizer::PresenceMode parseMode(std::string_view text) {
  if (text == "auto") return fidolizer::PresenceMode::Auto;
  if (text == "deny") return fidolizer::PresenceMode::Deny;
  if (text == "prompt") return fidolizer::PresenceMode::Prompt;
  throw std::runtime_error("unknown --up mode");
}

struct Options {
  std::string command{"serve"};
  std::filesystem::path state{defaultState()};
  fidolizer::PresenceMode up{fidolizer::PresenceMode::Prompt};
  std::uint16_t vid{fidolizer::kDefaultVendorId};
  std::uint16_t pid{fidolizer::kDefaultProductId};
  std::string pin;
  std::string old_pin;
  std::string delete_id;
  bool yes{false};
};

Options parseArgs(int argc, char** argv) {
  Options options;
  if (const char* env = std::getenv("FIDOLIZER_UP")) options.up = parseMode(env);
  std::vector<std::string> positionals;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg = argv[i];
    auto need = [&](const char* name) {
      if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + name);
      return std::string(argv[++i]);
    };
    if (arg == "-h" || arg == "--help") {
      usage();
      std::exit(0);
    } else if (arg == "--state") {
      options.state = need("--state");
    } else if (arg == "--up") {
      options.up = parseMode(need("--up"));
    } else if (arg == "--vid") {
      auto value = parseHex(need("--vid"));
      if (!value || *value > 0xffff) throw std::runtime_error("bad --vid");
      options.vid = static_cast<std::uint16_t>(*value);
    } else if (arg == "--pid") {
      auto value = parseHex(need("--pid"));
      if (!value || *value > 0xffff) throw std::runtime_error("bad --pid");
      options.pid = static_cast<std::uint16_t>(*value);
    } else if (arg == "--pin") {
      options.pin = need("--pin");
    } else if (arg == "--old-pin") {
      options.old_pin = need("--old-pin");
    } else if (arg == "--yes") {
      options.yes = true;
    } else if (arg.starts_with('-')) {
      throw std::runtime_error("unknown option " + std::string(arg));
    } else {
      positionals.emplace_back(arg);
    }
  }
  if (!positionals.empty()) {
    options.command = positionals[0];
    if (options.command == "delete") {
      if (positionals.size() != 2) throw std::runtime_error("delete requires a credential id");
      options.delete_id = positionals[1];
    } else if (positionals.size() != 1) {
      throw std::runtime_error("unexpected argument");
    }
  }
  return options;
}

std::string aaguidText(std::span<const std::uint8_t, 16> aaguid) {
  const auto hex = toHex(aaguid);
  return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" +
         hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

bool readExact(int fd, void* data, std::size_t size) {
  auto* bytes = static_cast<std::uint8_t*>(data);
  std::size_t off = 0;
  while (off < size) {
    const ssize_t n = ::read(fd, bytes + off, size - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

bool writeExact(int fd, const void* data, std::size_t size) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::size_t off = 0;
  while (off < size) {
    const ssize_t n = ::write(fd, bytes + off, size - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

std::uint32_t loadLe32(const std::uint8_t* bytes) {
  return std::uint32_t{bytes[0]} | (std::uint32_t{bytes[1]} << 8) | (std::uint32_t{bytes[2]} << 16) |
         (std::uint32_t{bytes[3]} << 24);
}

void storeLe32(std::uint8_t* bytes, std::uint32_t value) {
  bytes[0] = static_cast<std::uint8_t>(value);
  bytes[1] = static_cast<std::uint8_t>(value >> 8);
  bytes[2] = static_cast<std::uint8_t>(value >> 16);
  bytes[3] = static_cast<std::uint8_t>(value >> 24);
}

int runWebAuthn(const Options& options) {
  std::signal(SIGPIPE, SIG_IGN);
  auto store = fidolizer::StateStore::open(options.state);
  fidolizer::Presence presence(options.up);
  fidolizer::Authenticator authenticator(store, presence);
  while (true) {
    std::uint8_t header[4];
    if (!readExact(STDIN_FILENO, header, sizeof(header))) return 0;
    const std::uint32_t length = loadLe32(header);
    if (length > 1024u * 1024u) {
      std::cerr << "fidolizer: native message is too large\n";
      return 1;
    }
    std::string body(length, '\0');
    if (!readExact(STDIN_FILENO, body.data(), body.size())) {
      std::cerr << "fidolizer: truncated native message\n";
      return 1;
    }
    const std::string response = fidolizer::transactWebAuthn(authenticator, body);
    if (response.size() > 0xffffffffu) return 1;
    std::uint8_t out_header[4];
    storeLe32(out_header, static_cast<std::uint32_t>(response.size()));
    if (!writeExact(STDOUT_FILENO, out_header, sizeof(out_header)) ||
        !writeExact(STDOUT_FILENO, response.data(), response.size())) {
      return 1;
    }
  }
}

void printInfo(const fidolizer::StateStore& store) {
  const auto& state = store.state();
  std::size_t residents = 0;
  for (const auto& cred : state.credentials) {
    if (cred.discoverable) ++residents;
  }
  std::cout << "state:        " << store.path() << '\n'
            << "aaguid:       " << aaguidText(state.aaguid) << '\n'
            << "serial:       " << state.serial << '\n'
            << "pin:          " << (state.pin_hash.empty() ? "not set" : "set") << '\n'
            << "pin retries:  " << static_cast<int>(state.pin_retries) << '\n'
            << "min pin:      " << static_cast<int>(state.min_pin_length) << '\n'
            << "resident:     " << residents << '\n'
            << "counter:      " << state.global_counter << '\n'
            << "vid:pid:      0x" << std::hex << fidolizer::kDefaultVendorId << ":0x"
            << fidolizer::kDefaultProductId << std::dec << '\n';
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const Options options = parseArgs(argc, argv);
    auto store = fidolizer::StateStore::open(options.state);
    fidolizer::Presence presence(options.up);
    fidolizer::Authenticator authenticator(store, presence);

    if (options.command == "info") {
      printInfo(store);
      return 0;
    }
    if (options.command == "credentials") {
      for (const auto& cred : store.state().credentials) {
        if (!cred.discoverable) continue;
        std::cout << toHex(cred.id) << "  " << cred.rp_id << "  " << cred.user_name << "  count "
                  << cred.sign_count << '\n';
      }
      return 0;
    }
    if (options.command == "set-pin") {
      std::string pin = options.pin.empty() ? readSecret("New PIN: ") : options.pin;
      std::string again = options.pin.empty() ? readSecret("Repeat PIN: ") : options.pin;
      if (pin != again) {
        std::cerr << "PINs do not match\n";
        return 1;
      }
      authenticator.setPin(pin);
      OPENSSL_cleanse(pin.data(), pin.size());
      std::cout << "PIN set\n";
      return 0;
    }
    if (options.command == "change-pin") {
      std::string old_pin = options.old_pin.empty() ? readSecret("Current PIN: ") : options.old_pin;
      std::string pin = options.pin.empty() ? readSecret("New PIN: ") : options.pin;
      authenticator.changePin(old_pin, pin);
      OPENSSL_cleanse(old_pin.data(), old_pin.size());
      OPENSSL_cleanse(pin.data(), pin.size());
      std::cout << "PIN changed\n";
      return 0;
    }
    if (options.command == "reset") {
      if (!options.yes) {
        std::cerr << "reset deletes every credential and the PIN. Pass --yes.\n";
        return 1;
      }
      authenticator.resetState();
      std::cout << "authenticator reset\n";
      return 0;
    }
    if (options.command == "delete") {
      const auto id = parseHexBytes(options.delete_id);
      auto& creds = store.state().credentials;
      const auto it = std::find_if(creds.begin(), creds.end(), [&](const fidolizer::Credential& cred) {
        return cred.discoverable && cred.id == id;
      });
      if (it == creds.end()) {
        std::cerr << "credential not found\n";
        return 1;
      }
      creds.erase(it);
      store.save();
      std::cout << "deleted\n";
      return 0;
    }
    if (options.command == "webauthn") return runWebAuthn(options);
    if (options.command != "serve") {
      usage();
      return 2;
    }

    fidolizer::HidConfig hid;
    hid.vendor_id = options.vid;
    hid.product_id = options.pid;
    hid.manufacturer = std::string(fidolizer::kManufacturer);
    hid.product = std::string(fidolizer::kProductName);
    hid.serial = store.state().serial;
    auto transport = fidolizer::openHidTransport(hid);
    fidolizer::Ctaphid session(authenticator, *transport);
    g_session.store(&session);
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    std::cerr << "fidolizer " << hid.product << " serial " << hid.serial << "\n"
              << "AAGUID " << aaguidText(store.state().aaguid) << "\n"
              << "state " << store.path() << "\n"
              << "waiting for CTAP HID reports\n";
    session.run();
    g_session.store(nullptr);
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "fidolizer: " << ex.what() << '\n';
    return 1;
  }
}
