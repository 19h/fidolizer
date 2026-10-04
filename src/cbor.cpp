#include "fidolizer/cbor.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace fidolizer {
namespace {

constexpr int kMaxDepth = 16;
constexpr std::uint64_t kMaxItems = 4096;

[[noreturn]] void fail(const char* what) { throw std::logic_error(what); }

void appendBe(std::vector<std::uint8_t>& out, std::uint64_t value, int bytes) {
  for (int i = bytes - 1; i >= 0; --i) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xff));
  }
}

void writeHead(std::vector<std::uint8_t>& out, std::uint8_t major, std::uint64_t value) {
  const auto prefix = static_cast<std::uint8_t>(major << 5);
  if (value < 24) {
    out.push_back(static_cast<std::uint8_t>(prefix | value));
  } else if (value <= 0xff) {
    out.push_back(static_cast<std::uint8_t>(prefix | 24));
    out.push_back(static_cast<std::uint8_t>(value));
  } else if (value <= 0xffff) {
    out.push_back(static_cast<std::uint8_t>(prefix | 25));
    appendBe(out, value, 2);
  } else if (value <= 0xffffffffu) {
    out.push_back(static_cast<std::uint8_t>(prefix | 26));
    appendBe(out, value, 4);
  } else {
    out.push_back(static_cast<std::uint8_t>(prefix | 27));
    appendBe(out, value, 8);
  }
}

struct Head {
  std::uint8_t major{};
  std::uint64_t value{};
  std::size_t next{};
};

std::expected<Head, CborError> readHead(std::span<const std::uint8_t> in, std::size_t index) {
  if (index >= in.size()) return std::unexpected(CborError::Truncated);
  const std::uint8_t byte = in[index];
  const auto major = static_cast<std::uint8_t>(byte >> 5);
  const auto additional = static_cast<std::uint8_t>(byte & 0x1f);
  std::size_t next = index + 1;
  std::uint64_t value = 0;
  if (additional < 24) {
    value = additional;
  } else if (additional == 24) {
    if (next >= in.size()) return std::unexpected(CborError::Truncated);
    value = in[next++];
  } else if (additional == 25) {
    if (next + 2 > in.size()) return std::unexpected(CborError::Truncated);
    value = (std::uint64_t{in[next]} << 8) | in[next + 1];
    next += 2;
  } else if (additional == 26) {
    if (next + 4 > in.size()) return std::unexpected(CborError::Truncated);
    for (int i = 0; i < 4; ++i) value = (value << 8) | in[next++];
  } else if (additional == 27) {
    if (next + 8 > in.size()) return std::unexpected(CborError::Truncated);
    for (int i = 0; i < 8; ++i) value = (value << 8) | in[next++];
  } else {
    return std::unexpected(CborError::Invalid);
  }
  return Head{major, value, next};
}

void encodeInto(const Cbor& value, std::vector<std::uint8_t>& out);

std::uint8_t majorOf(const std::vector<std::uint8_t>& encoded) {
  return encoded.empty() ? 0 : static_cast<std::uint8_t>(encoded[0] >> 5);
}

bool keyLess(const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& b) {
  const std::uint8_t ma = majorOf(a);
  const std::uint8_t mb = majorOf(b);
  if (ma != mb) return ma < mb;
  if (a.size() != b.size()) return a.size() < b.size();
  return a < b;
}

void encodeInto(const Cbor& value, std::vector<std::uint8_t>& out) {
  switch (value.kind()) {
    case Cbor::Kind::Null:
      out.push_back(0xf6);
      return;
    case Cbor::Kind::Bool:
      out.push_back(value.boolean() ? 0xf5 : 0xf4);
      return;
    case Cbor::Kind::Int: {
      const std::int64_t n = value.integer();
      if (n >= 0) {
        writeHead(out, 0, static_cast<std::uint64_t>(n));
      } else {
        writeHead(out, 1, static_cast<std::uint64_t>(-1 - n));
      }
      return;
    }
    case Cbor::Kind::Bytes:
      writeHead(out, 2, value.bytes().size());
      out.insert(out.end(), value.bytes().begin(), value.bytes().end());
      return;
    case Cbor::Kind::Text:
      writeHead(out, 3, value.text().size());
      out.insert(out.end(), value.text().begin(), value.text().end());
      return;
    case Cbor::Kind::Array:
      writeHead(out, 4, value.array().size());
      for (const Cbor& item : value.array()) encodeInto(item, out);
      return;
    case Cbor::Kind::Map: {
      std::vector<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> entries;
      entries.reserve(value.map().size());
      for (const auto& [key, item] : value.map()) {
        std::vector<std::uint8_t> encoded_key;
        std::vector<std::uint8_t> encoded_value;
        encodeInto(key, encoded_key);
        encodeInto(item, encoded_value);
        entries.emplace_back(std::move(encoded_key), std::move(encoded_value));
      }
      std::sort(entries.begin(), entries.end(),
                [](const auto& a, const auto& b) { return keyLess(a.first, b.first); });
      writeHead(out, 5, entries.size());
      for (const auto& [key, item] : entries) {
        out.insert(out.end(), key.begin(), key.end());
        out.insert(out.end(), item.begin(), item.end());
      }
      return;
    }
  }
}

Cbor withSlice(Cbor value, std::span<const std::uint8_t> in, std::size_t start, std::size_t end) {
  value.setRaw(std::vector<std::uint8_t>(in.begin() + static_cast<std::ptrdiff_t>(start),
                                         in.begin() + static_cast<std::ptrdiff_t>(end)));
  return value;
}

std::expected<Cbor, CborError> decodeAt(std::span<const std::uint8_t> in, std::size_t& index,
                                        int depth) {
  if (depth > kMaxDepth) return std::unexpected(CborError::TooDeep);
  const std::size_t start = index;
  auto head = readHead(in, index);
  if (!head) return std::unexpected(head.error());
  index = head->next;

  switch (head->major) {
    case 0:
      if (head->value > static_cast<std::uint64_t>(INT64_MAX)) {
        return std::unexpected(CborError::Invalid);
      }
      return withSlice(Cbor::integer(static_cast<std::int64_t>(head->value)), in, start, index);
    case 1: {
      if (head->value > static_cast<std::uint64_t>(INT64_MAX)) {
        return std::unexpected(CborError::Invalid);
      }
      const auto arg = static_cast<std::int64_t>(head->value);
      return withSlice(Cbor::integer(static_cast<std::int64_t>(-1 - arg)), in, start, index);
    }
    case 2:
    case 3: {
      if (head->value > in.size() - index) return std::unexpected(CborError::Truncated);
      const auto len = static_cast<std::size_t>(head->value);
      const auto* begin = in.data() + index;
      index += len;
      if (head->major == 2) {
        return withSlice(Cbor::bytes(std::vector<std::uint8_t>(begin, begin + len)), in, start,
                         index);
      }
      return withSlice(Cbor::text(std::string(reinterpret_cast<const char*>(begin), len)), in,
                       start, index);
    }
    case 4: {
      if (head->value > kMaxItems) return std::unexpected(CborError::TooLarge);
      std::vector<Cbor> items;
      items.reserve(static_cast<std::size_t>(head->value));
      for (std::uint64_t n = 0; n < head->value; ++n) {
        auto item = decodeAt(in, index, depth + 1);
        if (!item) return std::unexpected(item.error());
        items.push_back(std::move(*item));
      }
      return withSlice(Cbor::array(std::move(items)), in, start, index);
    }
    case 5: {
      if (head->value > kMaxItems) return std::unexpected(CborError::TooLarge);
      std::vector<std::pair<Cbor, Cbor>> items;
      items.reserve(static_cast<std::size_t>(head->value));
      for (std::uint64_t n = 0; n < head->value; ++n) {
        auto key = decodeAt(in, index, depth + 1);
        if (!key) return std::unexpected(key.error());
        auto item = decodeAt(in, index, depth + 1);
        if (!item) return std::unexpected(item.error());
        items.emplace_back(std::move(*key), std::move(*item));
      }
      return withSlice(Cbor::map(std::move(items)), in, start, index);
    }
    case 7:
      if (head->value == 20) return withSlice(Cbor::boolean(false), in, start, index);
      if (head->value == 21) return withSlice(Cbor::boolean(true), in, start, index);
      if (head->value == 22) return withSlice(Cbor::null(), in, start, index);
      return std::unexpected(CborError::Invalid);
    default:
      return std::unexpected(CborError::Invalid);
  }
}

}  // namespace

Cbor Cbor::null() { return Cbor{}; }

Cbor Cbor::boolean(bool value) {
  Cbor out;
  out.kind_ = Kind::Bool;
  out.bool_ = value;
  return out;
}

Cbor Cbor::integer(std::int64_t value) {
  Cbor out;
  out.kind_ = Kind::Int;
  out.int_ = value;
  return out;
}

Cbor Cbor::bytes(std::vector<std::uint8_t> value) {
  Cbor out;
  out.kind_ = Kind::Bytes;
  out.bytes_ = std::move(value);
  return out;
}

Cbor Cbor::bytes(std::span<const std::uint8_t> value) {
  return bytes(std::vector<std::uint8_t>(value.begin(), value.end()));
}

Cbor Cbor::text(std::string value) {
  Cbor out;
  out.kind_ = Kind::Text;
  out.text_ = std::move(value);
  return out;
}

Cbor Cbor::array(std::vector<Cbor> value) {
  Cbor out;
  out.kind_ = Kind::Array;
  out.array_ = std::move(value);
  return out;
}

Cbor Cbor::map(std::vector<std::pair<Cbor, Cbor>> value) {
  Cbor out;
  out.kind_ = Kind::Map;
  out.map_ = std::move(value);
  return out;
}

Cbor Cbor::intMap(std::vector<std::pair<std::int64_t, Cbor>> fields) {
  std::vector<std::pair<Cbor, Cbor>> items;
  items.reserve(fields.size());
  for (auto& field : fields) {
    items.emplace_back(integer(field.first), std::move(field.second));
  }
  return map(std::move(items));
}

Cbor Cbor::textMap(std::vector<std::pair<std::string, Cbor>> fields) {
  std::vector<std::pair<Cbor, Cbor>> items;
  items.reserve(fields.size());
  for (auto& field : fields) {
    items.emplace_back(text(std::move(field.first)), std::move(field.second));
  }
  return map(std::move(items));
}

bool Cbor::boolean() const {
  if (kind_ != Kind::Bool) fail("CBOR value is not a boolean");
  return bool_;
}

std::int64_t Cbor::integer() const {
  if (kind_ != Kind::Int) fail("CBOR value is not an integer");
  return int_;
}

const std::vector<std::uint8_t>& Cbor::bytes() const {
  if (kind_ != Kind::Bytes) fail("CBOR value is not a byte string");
  return bytes_;
}

const std::string& Cbor::text() const {
  if (kind_ != Kind::Text) fail("CBOR value is not a text string");
  return text_;
}

const std::vector<Cbor>& Cbor::array() const {
  if (kind_ != Kind::Array) fail("CBOR value is not an array");
  return array_;
}

const std::vector<std::pair<Cbor, Cbor>>& Cbor::map() const {
  if (kind_ != Kind::Map) fail("CBOR value is not a map");
  return map_;
}

const Cbor* Cbor::find(std::int64_t key) const {
  if (kind_ != Kind::Map) return nullptr;
  for (const auto& [k, value] : map_) {
    if (k.kind_ == Kind::Int && k.int_ == key) return &value;
  }
  return nullptr;
}

const Cbor* Cbor::find(std::string_view key) const {
  if (kind_ != Kind::Map) return nullptr;
  for (const auto& [k, value] : map_) {
    if (k.kind_ == Kind::Text && k.text_ == key) return &value;
  }
  return nullptr;
}

std::vector<std::uint8_t> Cbor::encode() const {
  std::vector<std::uint8_t> out;
  encodeInto(*this, out);
  return out;
}

std::expected<Cbor, CborError> Cbor::decodeOne(std::span<const std::uint8_t> input,
                                               std::size_t& consumed) {
  std::size_t index = 0;
  auto value = decodeAt(input, index, 0);
  if (!value) return std::unexpected(value.error());
  consumed = index;
  return std::move(*value);
}

std::expected<Cbor, CborError> Cbor::decode(std::span<const std::uint8_t> input) {
  std::size_t consumed = 0;
  auto value = decodeOne(input, consumed);
  if (!value) return value;
  if (consumed != input.size()) return std::unexpected(CborError::Invalid);
  return value;
}

}  // namespace fidolizer
