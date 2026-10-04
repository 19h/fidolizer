#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fidolizer {

enum class CborError { Truncated, Invalid, TooDeep, TooLarge };

// CTAP canonical CBOR value. Map encoding sorts keys by major type, then
// encoded length, then the encoded bytes.
class Cbor {
 public:
  enum class Kind { Null, Bool, Int, Bytes, Text, Array, Map };

  static Cbor null();
  static Cbor boolean(bool value);
  static Cbor integer(std::int64_t value);
  static Cbor bytes(std::vector<std::uint8_t> value);
  static Cbor bytes(std::span<const std::uint8_t> value);
  static Cbor text(std::string value);
  static Cbor array(std::vector<Cbor> value);
  static Cbor map(std::vector<std::pair<Cbor, Cbor>> value);
  static Cbor intMap(std::vector<std::pair<std::int64_t, Cbor>> fields);
  static Cbor textMap(std::vector<std::pair<std::string, Cbor>> fields);

  Kind kind() const noexcept { return kind_; }
  bool boolean() const;
  std::int64_t integer() const;
  const std::vector<std::uint8_t>& bytes() const;
  const std::string& text() const;
  const std::vector<Cbor>& array() const;
  const std::vector<std::pair<Cbor, Cbor>>& map() const;

  // Original encoded bytes when this value was decoded. Empty if constructed.
  const std::vector<std::uint8_t>& raw() const noexcept { return raw_; }
  void setRaw(std::vector<std::uint8_t> raw) { raw_ = std::move(raw); }

  const Cbor* find(std::int64_t key) const;
  const Cbor* find(std::string_view key) const;

  std::vector<std::uint8_t> encode() const;

  static std::expected<Cbor, CborError> decode(std::span<const std::uint8_t> input);
  static std::expected<Cbor, CborError> decodeOne(std::span<const std::uint8_t> input,
                                                  std::size_t& consumed);

 private:
  Kind kind_{Kind::Null};
  bool bool_{false};
  std::int64_t int_{0};
  std::vector<std::uint8_t> bytes_;
  std::string text_;
  std::vector<Cbor> array_;
  std::vector<std::pair<Cbor, Cbor>> map_;
  std::vector<std::uint8_t> raw_;
};

}  // namespace fidolizer
