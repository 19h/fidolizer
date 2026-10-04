#pragma once

#include <functional>
#include <string_view>

namespace fidolizer {

enum class PresenceMode { Prompt, Auto, Deny };

enum class Decision { Allow, Deny, Timeout, Cancelled };

class Presence {
 public:
  explicit Presence(PresenceMode mode) : mode_(mode) {}

  // `cancelled` is polled while a dialog is up. It may be empty.
  Decision confirm(std::string_view rp_id, std::string_view action, bool verification,
                   const std::function<bool()>& cancelled) const;

  PresenceMode mode() const noexcept { return mode_; }

 private:
  PresenceMode mode_;
};

}  // namespace fidolizer
