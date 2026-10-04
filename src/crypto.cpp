#include "fidolizer/crypto.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstring>
#include <memory>
#include <stdexcept>
#include <utility>

namespace fidolizer {
namespace {

struct EvpPkeyFree {
  void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
struct EvpPkeyCtxFree {
  void operator()(EVP_PKEY_CTX* ctx) const { EVP_PKEY_CTX_free(ctx); }
};
struct EvpMdCtxFree {
  void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
};
struct EvpCipherCtxFree {
  void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
struct BnFree {
  void operator()(BIGNUM* bn) const { BN_free(bn); }
};
struct ParamFree {
  void operator()(OSSL_PARAM* params) const { OSSL_PARAM_free(params); }
};
struct ParamBldFree {
  void operator()(OSSL_PARAM_BLD* bld) const { OSSL_PARAM_BLD_free(bld); }
};
struct X509Free {
  void operator()(X509* cert) const { X509_free(cert); }
};

using PKey = std::unique_ptr<EVP_PKEY, EvpPkeyFree>;
using PKeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxFree>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxFree>;
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxFree>;

[[noreturn]] void cryptoFail(const char* what) { throw std::runtime_error(what); }

PKey makeP256(std::span<const std::uint8_t> priv, const P256Public* pub_or_null) {
  std::unique_ptr<BIGNUM, BnFree> priv_bn(BN_bin2bn(priv.data(), static_cast<int>(priv.size()), nullptr));
  if (!priv_bn) cryptoFail("BN_bin2bn");

  std::unique_ptr<OSSL_PARAM_BLD, ParamBldFree> bld(OSSL_PARAM_BLD_new());
  if (!bld) cryptoFail("OSSL_PARAM_BLD_new");
  if (OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0) != 1) {
    cryptoFail("group");
  }
  if (OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv_bn.get()) != 1) {
    cryptoFail("priv");
  }
  std::uint8_t uncompressed[65];
  if (pub_or_null != nullptr) {
    uncompressed[0] = 0x04;
    std::memcpy(uncompressed + 1, pub_or_null->x.data(), 32);
    std::memcpy(uncompressed + 33, pub_or_null->y.data(), 32);
    if (OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, uncompressed,
                                         sizeof(uncompressed)) != 1) {
      cryptoFail("pub");
    }
  }
  std::unique_ptr<OSSL_PARAM, ParamFree> params(OSSL_PARAM_BLD_to_param(bld.get()));
  PKeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) cryptoFail("fromdata_init");
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_KEYPAIR, params.get()) != 1) {
    cryptoFail("EVP_PKEY_fromdata");
  }
  return PKey(raw);
}

PKey generateP256() {
  PKeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1) cryptoFail("keygen_init");
  char group[] = "P-256";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0),
      OSSL_PARAM_construct_end(),
  };
  if (EVP_PKEY_CTX_set_params(ctx.get(), params) != 1) cryptoFail("set group");
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_generate(ctx.get(), &raw) != 1) cryptoFail("EVP_PKEY_generate");
  return PKey(raw);
}

bool readCoord(const EVP_PKEY* key, const char* name, std::uint8_t out[32]) {
  std::size_t len = 32;
  if (EVP_PKEY_get_octet_string_param(key, name, out, 32, &len) == 1) {
    if (len == 32) return true;
    if (len < 32) {
      std::memmove(out + (32 - len), out, len);
      std::memset(out, 0, 32 - len);
      return true;
    }
  }
  BIGNUM* raw = nullptr;
  if (EVP_PKEY_get_bn_param(key, name, &raw) == 1 && raw != nullptr) {
    std::unique_ptr<BIGNUM, BnFree> bn(raw);
    return BN_bn2binpad(bn.get(), out, 32) == 32;
  }
  return false;
}

bool extractKey(const EVP_PKEY* key, std::array<std::uint8_t, 32>& priv, P256Public& pub) {
  if (!readCoord(key, OSSL_PKEY_PARAM_PRIV_KEY, priv.data())) return false;
  if (readCoord(key, OSSL_PKEY_PARAM_EC_PUB_X, pub.x.data()) &&
      readCoord(key, OSSL_PKEY_PARAM_EC_PUB_Y, pub.y.data())) {
    return true;
  }
  std::uint8_t point[133];
  std::size_t len = sizeof(point);
  if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point), &len) == 1 &&
      len == 65 && point[0] == 0x04) {
    std::memcpy(pub.x.data(), point + 1, 32);
    std::memcpy(pub.y.data(), point + 33, 32);
    return true;
  }
  return false;
}

P256Public derivePublic(std::span<const std::uint8_t, 32> priv) {
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
  std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1),
                                                           EC_GROUP_free);
  std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(EC_POINT_new(group.get()), EC_POINT_free);
  std::unique_ptr<BIGNUM, BnFree> scalar(BN_bin2bn(priv.data(), 32, nullptr));
  std::unique_ptr<BIGNUM, BnFree> x(BN_new());
  std::unique_ptr<BIGNUM, BnFree> y(BN_new());
  if (!group || !point || !scalar || !x || !y ||
      EC_POINT_mul(group.get(), point.get(), scalar.get(), nullptr, nullptr, nullptr) != 1 ||
      EC_POINT_get_affine_coordinates(group.get(), point.get(), x.get(), y.get(), nullptr) != 1) {
    cryptoFail("derive P-256 public key");
  }
  P256Public pub;
  if (BN_bn2binpad(x.get(), pub.x.data(), 32) != 32 || BN_bn2binpad(y.get(), pub.y.data(), 32) != 32) {
    cryptoFail("derive P-256 public key");
  }
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
  return pub;
}

PKey publicOnly(const P256Public& pub) {
  // A private scalar of 1 is replaced: build a public-only key.
  std::uint8_t uncompressed[65];
  uncompressed[0] = 0x04;
  std::memcpy(uncompressed + 1, pub.x.data(), 32);
  std::memcpy(uncompressed + 33, pub.y.data(), 32);
  std::unique_ptr<OSSL_PARAM_BLD, ParamBldFree> bld(OSSL_PARAM_BLD_new());
  if (!bld) cryptoFail("bld");
  if (OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0) != 1 ||
      OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, uncompressed,
                                       sizeof(uncompressed)) != 1) {
    cryptoFail("pub params");
  }
  std::unique_ptr<OSSL_PARAM, ParamFree> params(OSSL_PARAM_BLD_to_param(bld.get()));
  PKeyCtx ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) cryptoFail("pub fromdata_init");
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
    cryptoFail("public fromdata");
  }
  return PKey(raw);
}

std::array<std::uint8_t, 16> zeroIv() { return {}; }

}  // namespace

void P256Key::wipe() {
  if (live_) OPENSSL_cleanse(priv_.data(), priv_.size());
  live_ = false;
}

P256Key::~P256Key() { wipe(); }

P256Key::P256Key(const P256Key& other) : priv_(other.priv_), pub_(other.pub_), live_(other.live_) {}

P256Key& P256Key::operator=(const P256Key& other) {
  if (this != &other) {
    wipe();
    priv_ = other.priv_;
    pub_ = other.pub_;
    live_ = other.live_;
  }
  return *this;
}

P256Key::P256Key(P256Key&& other) noexcept : priv_(other.priv_), pub_(other.pub_), live_(other.live_) {
  other.wipe();
}

P256Key& P256Key::operator=(P256Key&& other) noexcept {
  if (this != &other) {
    wipe();
    priv_ = other.priv_;
    pub_ = other.pub_;
    live_ = other.live_;
    other.wipe();
  }
  return *this;
}

P256Key P256Key::generate() {
  PKey key = generateP256();
  P256Key out;
  if (!extractKey(key.get(), out.priv_, out.pub_)) cryptoFail("extract generated key");
  out.live_ = true;
  return out;
}

P256Key P256Key::fromPrivate(std::span<const std::uint8_t, kP256Len> priv) {
  P256Key out;
  std::memcpy(out.priv_.data(), priv.data(), priv.size());
  try {
    PKey key = makeP256(priv, nullptr);
    if (!extractKey(key.get(), out.priv_, out.pub_)) out.pub_ = derivePublic(out.priv_);
  } catch (...) {
    out.pub_ = derivePublic(out.priv_);
  }
  out.live_ = true;
  return out;
}

std::vector<std::uint8_t> P256Key::sign(std::span<const std::uint8_t> message) const {
  if (!live_) cryptoFail("sign empty key");
  PKey key = makeP256(priv_, &pub_);
  MdCtx ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
    cryptoFail("DigestSignInit");
  }
  if (EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) != 1) cryptoFail("SignUpdate");
  std::size_t len = 0;
  if (EVP_DigestSignFinal(ctx.get(), nullptr, &len) != 1) cryptoFail("SignFinal size");
  std::vector<std::uint8_t> sig(len);
  if (EVP_DigestSignFinal(ctx.get(), sig.data(), &len) != 1) cryptoFail("SignFinal");
  sig.resize(len);
  return sig;
}

std::array<std::uint8_t, kP256Len> P256Key::ecdhX(const P256Public& peer) const {
  if (!live_) cryptoFail("ecdh empty key");
  PKey local = makeP256(priv_, &pub_);
  PKey remote = publicOnly(peer);
  PKeyCtx ctx(EVP_PKEY_CTX_new(local.get(), nullptr));
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 ||
      EVP_PKEY_derive_set_peer(ctx.get(), remote.get()) != 1) {
    cryptoFail("derive_init");
  }
  std::size_t len = 0;
  if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1) cryptoFail("derive size");
  std::vector<std::uint8_t> secret(len);
  if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) != 1) cryptoFail("derive");
  secret.resize(len);
  std::array<std::uint8_t, kP256Len> x{};
  if (secret.size() > 32) cryptoFail("ecdh width");
  std::memcpy(x.data() + (32 - secret.size()), secret.data(), secret.size());
  OPENSSL_cleanse(secret.data(), secret.size());
  return x;
}

bool verifyEs256(const P256Public& pub, std::span<const std::uint8_t> message,
                 std::span<const std::uint8_t> der_signature) {
  try {
    PKey key = publicOnly(pub);
    MdCtx ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
      return false;
    }
    if (EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) != 1) return false;
    return EVP_DigestVerifyFinal(ctx.get(), der_signature.data(), der_signature.size()) == 1;
  } catch (...) {
    return false;
  }
}

bool verifyEs256Certificate(std::span<const std::uint8_t> cert_der,
                            std::span<const std::uint8_t> message,
                            std::span<const std::uint8_t> der_signature) {
  const std::uint8_t* ptr = cert_der.data();
  std::unique_ptr<X509, X509Free> cert(d2i_X509(nullptr, &ptr, static_cast<long>(cert_der.size())));
  if (!cert) return false;
  PKey key(X509_get_pubkey(cert.get()));
  if (!key) return false;
  MdCtx ctx(EVP_MD_CTX_new());
  if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
    return false;
  }
  if (EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) != 1) return false;
  return EVP_DigestVerifyFinal(ctx.get(), der_signature.data(), der_signature.size()) == 1;
}

std::array<std::uint8_t, kSha256Len> sha256(std::span<const std::uint8_t> data) {
  std::array<std::uint8_t, kSha256Len> out{};
  if (EVP_Digest(data.data(), data.size(), out.data(), nullptr, EVP_sha256(), nullptr) != 1) {
    cryptoFail("sha256");
  }
  return out;
}

std::array<std::uint8_t, kSha256Len> hmacSha256(std::span<const std::uint8_t> key,
                                                std::span<const std::uint8_t> data) {
  std::array<std::uint8_t, kSha256Len> out{};
  unsigned int len = 0;
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
           out.data(), &len) == nullptr ||
      len != 32) {
    cryptoFail("hmac");
  }
  return out;
}

std::vector<std::uint8_t> aes256Cbc(std::span<const std::uint8_t, 32> key,
                                    std::span<const std::uint8_t, 16> iv,
                                    std::span<const std::uint8_t> data, bool encrypt) {
  if (data.size() % 16 != 0) return {};
  CipherCtx ctx(EVP_CIPHER_CTX_new());
  if (!ctx) return {};
  const EVP_CIPHER* cipher = EVP_aes_256_cbc();
  int ok = encrypt ? EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data())
                   : EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(), iv.data());
  if (ok != 1) return {};
  // Callers pass block-aligned CTAP payloads. PKCS#7 is not used.
  if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) return {};
  std::vector<std::uint8_t> out(data.size() + 16);
  int written = 0;
  if (encrypt) {
    if (EVP_EncryptUpdate(ctx.get(), out.data(), &written, data.data(),
                          static_cast<int>(data.size())) != 1) {
      return {};
    }
  } else if (EVP_DecryptUpdate(ctx.get(), out.data(), &written, data.data(),
                               static_cast<int>(data.size())) != 1) {
    return {};
  }
  int final_written = 0;
  int final_ok = encrypt ? EVP_EncryptFinal_ex(ctx.get(), out.data() + written, &final_written)
                         : EVP_DecryptFinal_ex(ctx.get(), out.data() + written, &final_written);
  if (final_ok != 1) return {};
  out.resize(static_cast<std::size_t>(written + final_written));
  return out;
}

std::array<std::uint8_t, 32> hkdfSha256(std::span<const std::uint8_t> ikm,
                                        std::span<const std::uint8_t> salt,
                                        std::span<const std::uint8_t> info) {
  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  if (kdf == nullptr) cryptoFail("HKDF fetch");
  EVP_KDF_CTX* raw_ctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (raw_ctx == nullptr) cryptoFail("HKDF ctx");
  std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> ctx(raw_ctx, EVP_KDF_CTX_free);

  char digest[] = "SHA256";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string("digest", digest, 0),
      OSSL_PARAM_construct_octet_string("key", const_cast<std::uint8_t*>(ikm.data()), ikm.size()),
      OSSL_PARAM_construct_octet_string("salt", const_cast<std::uint8_t*>(salt.data()), salt.size()),
      OSSL_PARAM_construct_octet_string("info", const_cast<std::uint8_t*>(info.data()), info.size()),
      OSSL_PARAM_construct_end(),
  };
  std::array<std::uint8_t, 32> out{};
  if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1) cryptoFail("HKDF derive");
  return out;
}

std::vector<std::uint8_t> randomBytes(std::size_t n) {
  std::vector<std::uint8_t> out(n);
  if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1) cryptoFail("RAND_bytes");
  return out;
}

bool constantTimeEqual(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
  if (a.size() != b.size()) return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::vector<std::uint8_t> aes256GcmEncrypt(std::span<const std::uint8_t, 32> key,
                                           std::span<const std::uint8_t, 12> nonce,
                                           std::span<const std::uint8_t> aad,
                                           std::span<const std::uint8_t> plain) {
  CipherCtx ctx(EVP_CIPHER_CTX_new());
  if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    return {};
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return {};
  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) return {};
  int written = 0;
  if (!aad.empty() &&
      EVP_EncryptUpdate(ctx.get(), nullptr, &written, aad.data(), static_cast<int>(aad.size())) !=
          1) {
    return {};
  }
  std::vector<std::uint8_t> out(plain.size() + 16);
  if (EVP_EncryptUpdate(ctx.get(), out.data(), &written, plain.data(),
                        static_cast<int>(plain.size())) != 1) {
    return {};
  }
  int final_written = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), out.data() + written, &final_written) != 1) return {};
  const int body = written + final_written;
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, out.data() + body) != 1) return {};
  out.resize(static_cast<std::size_t>(body + 16));
  return out;
}

std::vector<std::uint8_t> aes256GcmDecrypt(std::span<const std::uint8_t, 32> key,
                                           std::span<const std::uint8_t, 12> nonce,
                                           std::span<const std::uint8_t> aad,
                                           std::span<const std::uint8_t> cipher_and_tag) {
  if (cipher_and_tag.size() < 16) return {};
  const std::size_t body = cipher_and_tag.size() - 16;
  CipherCtx ctx(EVP_CIPHER_CTX_new());
  if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    return {};
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return {};
  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) return {};
  int written = 0;
  if (!aad.empty() &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &written, aad.data(), static_cast<int>(aad.size())) !=
          1) {
    return {};
  }
  std::vector<std::uint8_t> out(body);
  if (body > 0 && EVP_DecryptUpdate(ctx.get(), out.data(), &written, cipher_and_tag.data(),
                                    static_cast<int>(body)) != 1) {
    return {};
  }
  std::uint8_t tag[16];
  std::memcpy(tag, cipher_and_tag.data() + body, 16);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1) return {};
  int final_written = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), out.data() + written, &final_written) != 1) return {};
  out.resize(static_cast<std::size_t>(written + final_written));
  return out;
}

AttestationIdentity makeAttestationIdentity(std::span<const std::uint8_t, 16> aaguid) {
  AttestationIdentity identity;
  identity.key = P256Key::generate();
  PKey key = makeP256(identity.key.privateKey(), &identity.key.publicKey());

  std::unique_ptr<X509, X509Free> cert(X509_new());
  if (!cert) cryptoFail("X509_new");
  if (X509_set_version(cert.get(), 2) != 1) cryptoFail("version");
  if (ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) != 1) cryptoFail("serial");
  const auto serial = randomBytes(8);
  std::unique_ptr<BIGNUM, BnFree> serial_bn(BN_bin2bn(serial.data(), 8, nullptr));
  if (!serial_bn || BN_to_ASN1_INTEGER(serial_bn.get(), X509_get_serialNumber(cert.get())) == nullptr) {
    cryptoFail("serial bn");
  }
  if (X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) == nullptr) cryptoFail("notBefore");
  if (X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24 * 365 * 20) == nullptr) {
    cryptoFail("notAfter");
  }
  X509_NAME* name = X509_get_subject_name(cert.get());
  auto add = [&](const char* field, const char* value) {
    if (X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(value), -1, -1, 0) != 1) {
      cryptoFail(field);
    }
  };
  add("C", "US");
  add("O", "Fidolizer");
  add("OU", "Authenticator Attestation");
  add("CN", "Fidolizer FIDO2 Authenticator");
  if (X509_set_issuer_name(cert.get(), name) != 1) cryptoFail("issuer");
  if (X509_set_pubkey(cert.get(), key.get()) != 1) cryptoFail("set pubkey");

  X509V3_CTX v3;
  X509V3_set_ctx_nodb(&v3);
  X509V3_set_ctx(&v3, cert.get(), cert.get(), nullptr, nullptr, 0);
  X509_EXTENSION* basic = X509V3_EXT_conf_nid(nullptr, &v3, NID_basic_constraints, "critical,CA:FALSE");
  X509_EXTENSION* usage =
      X509V3_EXT_conf_nid(nullptr, &v3, NID_key_usage, "critical,digitalSignature");
  if (basic == nullptr || usage == nullptr) cryptoFail("extensions");
  X509_add_ext(cert.get(), basic, -1);
  X509_add_ext(cert.get(), usage, -1);
  X509_EXTENSION_free(basic);
  X509_EXTENSION_free(usage);

  // id-fido-gen-ce-aaguid: extnValue is the DER encoding of OCTET STRING(aaguid).
  std::uint8_t der[18];
  der[0] = 0x04;
  der[1] = 0x10;
  std::memcpy(der + 2, aaguid.data(), 16);
  ASN1_OBJECT* oid = OBJ_txt2obj("1.3.6.1.4.1.45724.1.1.4", 1);
  if (oid == nullptr) cryptoFail("aaguid oid");
  ASN1_OCTET_STRING* octet = ASN1_OCTET_STRING_new();
  ASN1_OCTET_STRING_set(octet, der, static_cast<int>(sizeof(der)));
  X509_EXTENSION* aaguid_ext = X509_EXTENSION_create_by_OBJ(nullptr, oid, 0, octet);
  ASN1_OCTET_STRING_free(octet);
  ASN1_OBJECT_free(oid);
  if (aaguid_ext == nullptr) cryptoFail("aaguid ext");
  X509_add_ext(cert.get(), aaguid_ext, -1);
  X509_EXTENSION_free(aaguid_ext);

  if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) cryptoFail("X509_sign");
  int len = i2d_X509(cert.get(), nullptr);
  if (len <= 0) cryptoFail("i2d size");
  identity.certificate.resize(static_cast<std::size_t>(len));
  std::uint8_t* out = identity.certificate.data();
  if (i2d_X509(cert.get(), &out) != len) cryptoFail("i2d");
  return identity;
}

PinKeys derivePinKeys(int version, std::span<const std::uint8_t, 32> x_coordinate) {
  PinKeys keys;
  keys.version = version;
  if (version == 1) {
    keys.hmac = sha256(x_coordinate);
    keys.aes = keys.hmac;
    return keys;
  }
  if (version != 2) cryptoFail("PIN protocol");
  const std::array<std::uint8_t, 32> salt{};
  const std::string_view hmac_info = "CTAP2 HMAC key";
  const std::string_view aes_info = "CTAP2 AES key";
  keys.hmac = hkdfSha256(x_coordinate, salt,
                         std::span<const std::uint8_t>(
                             reinterpret_cast<const std::uint8_t*>(hmac_info.data()), hmac_info.size()));
  keys.aes = hkdfSha256(x_coordinate, salt,
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(aes_info.data()), aes_info.size()));
  return keys;
}

std::vector<std::uint8_t> pinEncrypt(const PinKeys& keys, std::span<const std::uint8_t> plain) {
  if (keys.version == 1) {
    return aes256Cbc(keys.aes, zeroIv(), plain, true);
  }
  auto iv_bytes = randomBytes(16);
  std::array<std::uint8_t, 16> iv{};
  std::memcpy(iv.data(), iv_bytes.data(), 16);
  auto body = aes256Cbc(keys.aes, iv, plain, true);
  if (body.empty() && !plain.empty()) return {};
  std::vector<std::uint8_t> out;
  out.reserve(16 + body.size());
  out.insert(out.end(), iv.begin(), iv.end());
  out.insert(out.end(), body.begin(), body.end());
  return out;
}

std::vector<std::uint8_t> pinDecrypt(const PinKeys& keys, std::span<const std::uint8_t> cipher) {
  if (keys.version == 1) return aes256Cbc(keys.aes, zeroIv(), cipher, false);
  if (cipher.size() < 32) return {};
  std::array<std::uint8_t, 16> iv{};
  std::memcpy(iv.data(), cipher.data(), 16);
  return aes256Cbc(keys.aes, iv, cipher.subspan(16), false);
}

std::vector<std::uint8_t> pinMac(const PinKeys& keys, std::span<const std::uint8_t> message) {
  const auto full = hmacSha256(keys.hmac, message);
  if (keys.version == 1) return {full.begin(), full.begin() + 16};
  return {full.begin(), full.end()};
}

std::vector<std::uint8_t> tokenMac(int protocol, std::span<const std::uint8_t> token,
                                   std::span<const std::uint8_t> message) {
  const auto full = hmacSha256(token, message);
  if (protocol == 1) return {full.begin(), full.begin() + 16};
  return {full.begin(), full.end()};
}

}  // namespace fidolizer
