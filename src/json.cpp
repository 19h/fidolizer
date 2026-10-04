#include "fidolizer/json.hpp"

#include <stdexcept>

namespace fidolizer {
namespace {

[[noreturn]] void badAccess(const char* what) { throw std::logic_error(what); }

void appendUtf8(std::string& out, char32_t cp) {
  if (cp <= 0x7f) {
    out.push_back(static_cast<char>(cp));
  } else if (cp <= 0x7ff) {
    out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else if (cp <= 0xffff) {
    out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  } else {
    out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
  }
}

class Parser {
 public:
  explicit Parser(std::string_view text) : text_(text) {}

  std::optional<Json> parse() {
    skip();
    auto value = parseValue();
    if (!value) return std::nullopt;
    skip();
    if (index_ != text_.size()) return std::nullopt;
    return value;
  }

 private:
  std::string_view text_;
  std::size_t index_{0};
  int depth_{0};

  bool have() const { return index_ < text_.size(); }
  char peek() const { return have() ? text_[index_] : '\0'; }

  void skip() {
    while (have() && (text_[index_] == ' ' || text_[index_] == '\t' || text_[index_] == '\n' ||
                      text_[index_] == '\r')) {
      ++index_;
    }
  }

  std::optional<Json> parseValue() {
    if (depth_ > 32) return std::nullopt;
    if (!have()) return std::nullopt;
    const char ch = peek();
    if (ch == '{') return parseObject();
    if (ch == '[') return parseArray();
    if (ch == '"') return parseString();
    if (ch == 't') return literal("true", Json::boolean(true));
    if (ch == 'f') return literal("false", Json::boolean(false));
    if (ch == 'n') return literal("null", Json::null());
    if (ch == '-' || (ch >= '0' && ch <= '9')) return parseNumber();
    return std::nullopt;
  }

  std::optional<Json> literal(std::string_view word, Json value) {
    if (text_.substr(index_).starts_with(word)) {
      index_ += word.size();
      return value;
    }
    return std::nullopt;
  }

  std::optional<Json> parseNumber() {
    const std::size_t start = index_;
    if (peek() == '-') ++index_;
    if (!have() || peek() < '0' || peek() > '9') return std::nullopt;
    if (peek() == '0') {
      ++index_;
    } else {
      while (have() && peek() >= '0' && peek() <= '9') ++index_;
    }
    if (have() && (peek() == '.' || peek() == 'e' || peek() == 'E')) return std::nullopt;
    const auto token = text_.substr(start, index_ - start);
    try {
      std::size_t used = 0;
      const long long value = std::stoll(std::string(token), &used, 10);
      if (used != token.size()) return std::nullopt;
      return Json::integer(static_cast<std::int64_t>(value));
    } catch (const std::exception&) {
      return std::nullopt;
    }
  }

  std::optional<std::string> parseRawString() {
    if (peek() != '"') return std::nullopt;
    ++index_;
    std::string out;
    while (have()) {
      const unsigned char ch = static_cast<unsigned char>(text_[index_++]);
      if (ch == '"') return out;
      if (ch == '\\') {
        if (!have()) return std::nullopt;
        const char esc = text_[index_++];
        switch (esc) {
          case '"':
          case '\\':
          case '/':
            out.push_back(esc);
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            auto unit = hex4();
            if (!unit) return std::nullopt;
            char32_t cp = *unit;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
              if (!(have() && text_[index_] == '\\' && index_ + 1 < text_.size() &&
                    text_[index_ + 1] == 'u')) {
                return std::nullopt;
              }
              index_ += 2;
              auto low = hex4();
              if (!low || *low < 0xDC00 || *low > 0xDFFF) return std::nullopt;
              cp = 0x10000 + (((cp - 0xD800) << 10) | (*low - 0xDC00));
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
              return std::nullopt;
            }
            appendUtf8(out, cp);
            break;
          }
          default:
            return std::nullopt;
        }
      } else if (ch < 0x20) {
        return std::nullopt;
      } else {
        out.push_back(static_cast<char>(ch));
      }
    }
    return std::nullopt;
  }

  std::optional<unsigned> hex4() {
    if (index_ + 4 > text_.size()) return std::nullopt;
    unsigned value = 0;
    for (int i = 0; i < 4; ++i) {
      const char ch = text_[index_++];
      value <<= 4;
      if (ch >= '0' && ch <= '9') value |= static_cast<unsigned>(ch - '0');
      else if (ch >= 'a' && ch <= 'f') value |= static_cast<unsigned>(ch - 'a' + 10);
      else if (ch >= 'A' && ch <= 'F') value |= static_cast<unsigned>(ch - 'A' + 10);
      else return std::nullopt;
    }
    return value;
  }

  std::optional<Json> parseString() {
    auto text = parseRawString();
    if (!text) return std::nullopt;
    return Json::str(std::move(*text));
  }

  std::optional<Json> parseArray() {
    ++index_;
    ++depth_;
    std::vector<Json> items;
    skip();
    if (peek() == ']') {
      ++index_;
      --depth_;
      return Json::array(std::move(items));
    }
    while (true) {
      skip();
      auto item = parseValue();
      if (!item) return std::nullopt;
      items.push_back(std::move(*item));
      skip();
      if (peek() == ',') {
        ++index_;
        continue;
      }
      if (peek() == ']') {
        ++index_;
        --depth_;
        return Json::array(std::move(items));
      }
      return std::nullopt;
    }
  }

  std::optional<Json> parseObject() {
    ++index_;
    ++depth_;
    std::vector<std::pair<std::string, Json>> fields;
    skip();
    if (peek() == '}') {
      ++index_;
      --depth_;
      return Json::object(std::move(fields));
    }
    while (true) {
      skip();
      auto key = parseRawString();
      if (!key) return std::nullopt;
      skip();
      if (peek() != ':') return std::nullopt;
      ++index_;
      skip();
      auto value = parseValue();
      if (!value) return std::nullopt;
      fields.emplace_back(std::move(*key), std::move(*value));
      skip();
      if (peek() == ',') {
        ++index_;
        continue;
      }
      if (peek() == '}') {
        ++index_;
        --depth_;
        return Json::object(std::move(fields));
      }
      return std::nullopt;
    }
  }
};

void dumpString(std::string& out, std::string_view text) {
  out.push_back('"');
  for (unsigned char ch : text) {
    switch (ch) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (ch < 0x20) {
          static constexpr char kHex[] = "0123456789abcdef";
          out += "\\u00";
          out.push_back(kHex[ch >> 4]);
          out.push_back(kHex[ch & 0x0f]);
        } else {
          out.push_back(static_cast<char>(ch));
        }
        break;
    }
  }
  out.push_back('"');
}

}  // namespace

Json Json::null() { return {}; }

Json Json::boolean(bool value) {
  Json json;
  json.kind_ = Kind::Bool;
  json.bool_ = value;
  return json;
}

Json Json::integer(std::int64_t value) {
  Json json;
  json.kind_ = Kind::Int;
  json.int_ = value;
  return json;
}

Json Json::str(std::string value) {
  Json json;
  json.kind_ = Kind::String;
  json.text_ = std::move(value);
  return json;
}

Json Json::array(std::vector<Json> value) {
  Json json;
  json.kind_ = Kind::Array;
  json.array_ = std::move(value);
  return json;
}

Json Json::object(std::vector<std::pair<std::string, Json>> value) {
  Json json;
  json.kind_ = Kind::Object;
  json.object_ = std::move(value);
  return json;
}

bool Json::boolean() const {
  if (kind_ != Kind::Bool) badAccess("json bool");
  return bool_;
}

std::int64_t Json::integer() const {
  if (kind_ != Kind::Int) badAccess("json int");
  return int_;
}

const std::string& Json::text() const {
  if (kind_ != Kind::String) badAccess("json string");
  return text_;
}

const std::vector<Json>& Json::array() const {
  if (kind_ != Kind::Array) badAccess("json array");
  return array_;
}

const Json* Json::find(std::string_view key) const {
  if (kind_ != Kind::Object) return nullptr;
  for (const auto& field : object_) {
    if (field.first == key) return &field.second;
  }
  return nullptr;
}

std::string Json::dump() const {
  std::string out;
  switch (kind_) {
    case Kind::Null:
      return "null";
    case Kind::Bool:
      return bool_ ? "true" : "false";
    case Kind::Int:
      return std::to_string(int_);
    case Kind::String:
      dumpString(out, text_);
      return out;
    case Kind::Array:
      out.push_back('[');
      for (std::size_t i = 0; i < array_.size(); ++i) {
        if (i != 0) out.push_back(',');
        out += array_[i].dump();
      }
      out.push_back(']');
      return out;
    case Kind::Object:
      out.push_back('{');
      for (std::size_t i = 0; i < object_.size(); ++i) {
        if (i != 0) out.push_back(',');
        dumpString(out, object_[i].first);
        out.push_back(':');
        out += object_[i].second.dump();
      }
      out.push_back('}');
      return out;
  }
  return "null";
}

std::optional<Json> Json::parse(std::string_view text) { return Parser(text).parse(); }

}  // namespace fidolizer
