#include "fidolizer/presence.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern char** environ;

namespace fidolizer {
namespace {

Decision promptTerminal(std::string_view rp, std::string_view action, bool verification,
                        const std::function<bool()>& cancelled) {
  const int tty = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
  if (tty < 0) {
    std::cerr << "fidolizer: no terminal for user presence. Pass --up auto to approve "
                 "unattended requests.\n";
    return Decision::Deny;
  }
  const std::string text = std::string("fidolizer: ") + std::string(action) + " for " +
                           std::string(rp) + (verification ? " (user verification)" : "") +
                           "\nAllow? [y/N] ";
  if (::write(tty, text.data(), text.size()) < 0) {
    ::close(tty);
    return Decision::Deny;
  }
  const auto started = std::chrono::steady_clock::now();
  std::string line;
  while (std::chrono::steady_clock::now() - started < std::chrono::seconds(30)) {
    if (cancelled && cancelled()) {
      ::close(tty);
      return Decision::Cancelled;
    }
    pollfd pfd{};
    pfd.fd = tty;
    pfd.events = POLLIN;
    const int ready = ::poll(&pfd, 1, 100);
    if (ready <= 0) continue;
    char byte = 0;
    if (::read(tty, &byte, 1) <= 0) break;
    if (byte == '\n') break;
    if (line.size() < 16) line.push_back(byte);
  }
  ::close(tty);
  if (line.empty()) return Decision::Timeout;
  return (line[0] == 'y' || line[0] == 'Y') ? Decision::Allow : Decision::Deny;
}

Decision promptMac(std::string_view rp, std::string_view action, bool verification,
                   const std::function<bool()>& cancelled) {
#if defined(__APPLE__)
  int pipefd[2];
  if (::pipe(pipefd) != 0) return promptTerminal(rp, action, verification, cancelled);
  const std::string message = std::string(action) + "\n" + std::string(rp);
  std::string title = verification ? "Fidolizer verification" : "Fidolizer";
  setenv("FIDOLIZER_MSG", message.c_str(), 1);
  setenv("FIDOLIZER_TITLE", title.c_str(), 1);
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
  posix_spawn_file_actions_addclose(&actions, pipefd[0]);
  const char* script =
      "display dialog (system attribute \"FIDOLIZER_MSG\") "
      "buttons {\"Deny\", \"Allow\"} default button \"Allow\" "
      "with title (system attribute \"FIDOLIZER_TITLE\") giving up after 30";
  const char* argv[] = {"/usr/bin/osascript", "-e", script, nullptr};
  pid_t pid = 0;
  const int spawned = posix_spawn(&pid, "/usr/bin/osascript", &actions, nullptr,
                                  const_cast<char**>(argv), environ);
  posix_spawn_file_actions_destroy(&actions);
  ::close(pipefd[1]);
  if (spawned != 0) {
    ::close(pipefd[0]);
    return promptTerminal(rp, action, verification, cancelled);
  }
  std::string output;
  while (true) {
    if (cancelled && cancelled()) {
      ::kill(pid, SIGTERM);
      ::close(pipefd[0]);
      int status = 0;
      ::waitpid(pid, &status, 0);
      return Decision::Cancelled;
    }
    pollfd pfd{};
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;
    const int ready = ::poll(&pfd, 1, 100);
    if (ready < 0 && errno == EINTR) continue;
    if (ready > 0) {
      char buf[256];
      const ssize_t n = ::read(pipefd[0], buf, sizeof(buf));
      if (n > 0) output.append(buf, buf + n);
      if (n == 0) break;
    }
    int status = 0;
    const pid_t done = ::waitpid(pid, &status, WNOHANG);
    if (done == pid) {
      char buf[256];
      while (true) {
        const ssize_t n = ::read(pipefd[0], buf, sizeof(buf));
        if (n <= 0) break;
        output.append(buf, buf + n);
      }
      break;
    }
  }
  ::close(pipefd[0]);
  int status = 0;
  ::waitpid(pid, &status, 0);
  if (output.find("gave up:true") != std::string::npos) return Decision::Timeout;
  if (output.find("Allow") != std::string::npos) return Decision::Allow;
  return Decision::Deny;
#else
  (void)rp;
  (void)action;
  (void)verification;
  (void)cancelled;
  return promptTerminal(rp, action, verification, cancelled);
#endif
}

}  // namespace

Decision Presence::confirm(std::string_view rp_id, std::string_view action, bool verification,
                           const std::function<bool()>& cancelled) const {
  if (cancelled && cancelled()) return Decision::Cancelled;
  switch (mode_) {
    case PresenceMode::Auto:
      return Decision::Allow;
    case PresenceMode::Deny:
      return Decision::Deny;
    case PresenceMode::Prompt:
#if defined(__APPLE__)
      if (::access("/usr/bin/osascript", X_OK) == 0 && ::getenv("SSH_TTY") == nullptr &&
          ::getenv("FIDOLIZER_TERMINAL") == nullptr) {
        return promptMac(rp_id, action, verification, cancelled);
      }
#endif
      return promptTerminal(rp_id, action, verification, cancelled);
  }
  return Decision::Deny;
}

}  // namespace fidolizer
