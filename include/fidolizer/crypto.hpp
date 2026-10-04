#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace fidolizer {

inline constexpr std::size_t kSha256Len = 32;
inline constexpr std::size_t kP256Len = 32;

struct P256Public {
  std::array<std::uint8_t, kP256Len> x{};
  std::array<std::uint8_t, kP256Len> y{};
};

class P256Key {
 public:
  P256Key() = default;
  static P256Key generate();
  static P256Key fromPrivate(std::span<const std::uint8_t, kP256Len> priv);

  std::span<const std::uint8_t, kP256Len> privateKey() const { return priv_; }
  const P256Public& publicKey() const { return pub_; }

  // SHA-256 then ECDSA, ASN.1 DER signature (WebAuthn ES256).
  std::vector<std::uint8_t> sign(std::span<const std::uint8_t> message) const;

  // X coordinate of ECDH with a peer public key, left-padded to 32 bytes.
  std::array<std::uint8_t, kP256Len> ecdhX(const P256Public& peer) const;

  ~P256Key();
  P256Key(const P256Key&);
  P256Key& operator=(const P256Key&);
  P256Key(P256Key&&) noexcept;
  P256Key& operator=(P256Key&&) noexcept;

 private:
  std::array<std::uint8_t, kP256Len> priv_{};
  P256Public pub_{};
  bool live_{false};
  void wipe();
};

bool verifyEs256(const P256Public& pub, std::span<const std::uint8_t> message,
                 std::span<const std::uint8_t> der_signature);
bool verifyEs256Certificate(std::span<const std::uint8_t> cert_der,
                            std::span<const std::uint8_t> message,
                            std::span<const std::uint8_t> der_signature);

std::array<std::uint8_t, kSha256Len> sha256(std::span<const std::uint8_t> data);
std::array<std::uint8_t, kSha256Len> hmacSha256(std::span<const std::uint8_t> key,
                                                std::span<const std::uint8_t> data);

// AES-256-CBC. Plaintext must be a multiple of 16. No padding is added.
// IV is 16 bytes. Returns empty on failure.
std::vector<std::uint8_t> aes256Cbc(std::span<const std::uint8_t, 32> key,
                                    std::span<const std::uint8_t, 16> iv,
                                    std::span<const std::uint8_t> data, bool encrypt);

std::array<std::uint8_t, 32> hkdfSha256(std::span<const std::uint8_t> ikm,
                                        std::span<const std::uint8_t> salt,
                                        std::span<const std::uint8_t> info);

std::vector<std::uint8_t> randomBytes(std::size_t n);
bool constantTimeEqual(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b);

// AES-256-GCM. Nonce is 12 bytes. Output is ciphertext || 16-byte tag.
std::vector<std::uint8_t> aes256GcmEncrypt(std::span<const std::uint8_t, 32> key,
                                           std::span<const std::uint8_t, 12> nonce,
                                           std::span<const std::uint8_t> aad,
                                           std::span<const std::uint8_t> plain);
// Empty on authentication failure.
std::vector<std::uint8_t> aes256GcmDecrypt(std::span<const std::uint8_t, 32> key,
                                           std::span<const std::uint8_t, 12> nonce,
                                           std::span<const std::uint8_t> aad,
                                           std::span<const std::uint8_t> cipher_and_tag);

struct AttestationIdentity {
  P256Key key;
  std::vector<std::uint8_t> certificate;
};

AttestationIdentity makeAttestationIdentity(std::span<const std::uint8_t, 16> aaguid);

// CTAP PIN/UV auth protocol shared-secret material.
struct PinKeys {
  int version{1};
  std::array<std::uint8_t, 32> hmac{};
  std::array<std::uint8_t, 32> aes{};
};

PinKeys derivePinKeys(int version, std::span<const std::uint8_t, 32> x_coordinate);
// Protocol 2 prepends a random IV. Plaintext must be block-aligned.
std::vector<std::uint8_t> pinEncrypt(const PinKeys& keys, std::span<const std::uint8_t> plain);
std::vector<std::uint8_t> pinDecrypt(const PinKeys& keys, std::span<const std::uint8_t> cipher);
// Protocol 1: 16-byte HMAC. Protocol 2: 32-byte HMAC. Key is the shared secret.
std::vector<std::uint8_t> pinMac(const PinKeys& keys, std::span<const std::uint8_t> message);
// HMAC using the pinUvAuthToken itself as the key.
std::vector<std::uint8_t> tokenMac(int protocol, std::span<const std::uint8_t> token,
                                   std::span<const std::uint8_t> message);

}  // namespace fidolizer
