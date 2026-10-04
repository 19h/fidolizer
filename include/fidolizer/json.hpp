#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fidolizer {

// Compact JSON value. Object keys keep insertion order, which clientDataJSON needs.
class Json {
 public:
  enum class Kind { Null, Bool, Int, String, Array, Object };

  static Json null();
  static Json boolean(bool value);
  static Json integer(std::int64_t value);
  static Json str(std::string value);
  static Json array(std::vector<Json> value);
  static Json object(std::vector<std::pair<std::string, Json>> value);

  Kind kind() const noexcept { return kind_; }
  bool boolean() const;
  std::int64_t integer() const;
  const std::string& text() const;
  const std::vector<Json>& array() const;
  const Json* find(std::string_view key) const;

  std::string dump() const;

  // Parses one JSON value. Trailing whitespace is allowed. Anything else fails.
  static std::optional<Json> parse(std::string_view text);

 private:
  Kind kind_{Kind::Null};
  bool bool_{false};
  std::int64_t int_{0};
  std::string text_;
  std::vector<Json> array_;
  std::vector<std::pair<std::string, Json>> object_;
};

}  // namespace fidolizer
