#pragma once

// Portable child-process control for multiprocess proof surfaces.
//
// Child output is redirected to a log file rather than a pipe: a file is
// unbuffered from the parent's point of view, survives the child, and makes a
// failure diagnosable after the fact. Abrupt termination is explicit, because
// the point of these tests is to kill real processes at real moments.

#include <cstdint>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace ctf::test {

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { (void)kill(); }

  ChildProcess(ChildProcess&& other) noexcept { *this = std::move(other); }
  ChildProcess& operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
      (void)kill();
      handle_ = other.handle_;
      pid_ = other.pid_;
      exit_code_ = other.exit_code_;
      log_path_ = std::move(other.log_path_);
      output_ = std::move(other.output_);
      other.handle_ = invalid_handle();
      other.pid_ = 0;
    }
    return *this;
  }

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// Starts a process with stdout and stderr appended to log_file.
  [[nodiscard]] static std::optional<ChildProcess> start(const std::filesystem::path& executable,
                                                        const std::vector<std::string>& arguments,
                                                        const std::filesystem::path& log_file) {
    if (!log_file.parent_path().empty()) {
      std::error_code error;
      std::filesystem::create_directories(log_file.parent_path(), error);
      if (error) {
        return std::nullopt;
      }
    }
#if defined(_WIN32)
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    const HANDLE log_handle = CreateFileW(log_file.wstring().c_str(), FILE_APPEND_DATA,
                                          FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log_handle == INVALID_HANDLE_VALUE) {
      return std::nullopt;
    }
    std::string command_line = "\"" + executable.string() + "\"";
    for (const std::string& argument : arguments) {
      command_line += " \"" + argument + "\"";
    }
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = log_handle;
    startup.hStdError = log_handle;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION info{};
    std::vector<char> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back('\0');
    const BOOL created = CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, 0,
                                        nullptr, nullptr, &startup, &info);
    CloseHandle(log_handle);
    if (!created) {
      return std::nullopt;
    }
    CloseHandle(info.hThread);
    ChildProcess child;
    child.handle_ = info.hProcess;
    child.log_path_ = log_file;
    return child;
#else
    std::vector<std::string> storage;
    storage.push_back(executable.string());
    for (const std::string& argument : arguments) {
      storage.push_back(argument);
    }
    std::vector<char*> argv;
    for (std::string& item : storage) {
      argv.push_back(item.data());
    }
    argv.push_back(nullptr);
    const std::string log_text = log_file.string();
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, log_text.c_str(),
                                     O_WRONLY | O_CREAT | O_APPEND, 0644);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, log_text.c_str(),
                                     O_WRONLY | O_CREAT | O_APPEND, 0644);
    pid_t pid = 0;
    if (posix_spawn(&pid, executable.c_str(), &actions, nullptr, argv.data(), environ) != 0) {
      posix_spawn_file_actions_destroy(&actions);
      return std::nullopt;
    }
    posix_spawn_file_actions_destroy(&actions);
    ChildProcess child;
    child.pid_ = pid;
    child.log_path_ = log_file;
    return child;
#endif
  }

  /// Convenience overload: the child's output goes to a unique temporary log.
  [[nodiscard]] static std::optional<ChildProcess> start(const std::filesystem::path& executable,
                                                        const std::vector<std::string>& arguments) {
    static std::uint64_t counter = 0;
    const std::uint64_t index = ++counter;
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const std::filesystem::path log =
        std::filesystem::temp_directory_path() /
        ("ctf-child-" + std::to_string(index) + "-" + std::to_string(stamp) + ".log");
    return start(executable, arguments, log);
  }

  /// Re-reads the child's log into the accumulated output.
  void pump() {
    if (log_path_.empty()) {
      return;
    }
    std::ifstream input(log_path_, std::ios::binary);
    if (!input) {
      return;
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    output_ = buffer.str();
  }

  /// Waits until a line containing token appears in the child's output.
  [[nodiscard]] bool wait_for_line(const std::string& token, std::uint32_t max_seconds = 60) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(max_seconds);
    while (std::chrono::steady_clock::now() < deadline) {
      pump();
      if (output_.find(token) != std::string::npos) {
        return true;
      }
      if (exited()) {
        pump();
        return output_.find(token) != std::string::npos;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
  }

  [[nodiscard]] bool exited() {
#if defined(_WIN32)
    if (handle_ == invalid_handle()) {
      return true;
    }
    if (WaitForSingleObject(handle_, 0) == WAIT_OBJECT_0) {
      DWORD code = 0;
      if (GetExitCodeProcess(handle_, &code)) {
        exit_code_ = static_cast<int>(code);
      }
      return true;
    }
    return false;
#else
    if (pid_ == 0) {
      return true;
    }
    int status = 0;
    const pid_t result = waitpid(pid_, &status, WNOHANG);
    if (result == pid_) {
      exit_code_ = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
      pid_ = 0;
      return true;
    }
    return false;
#endif
  }

  /// Abrupt termination: what a crashed peer looks like to everyone else.
  [[nodiscard]] bool kill() {
    if (exited()) {
      return true;
    }
#if defined(_WIN32)
    const BOOL killed = TerminateProcess(handle_, 0xDEADU);
    WaitForSingleObject(handle_, 10000);
    CloseHandle(handle_);
    handle_ = invalid_handle();
    return killed != FALSE;
#else
    const bool killed = ::kill(pid_, SIGKILL) == 0;
    int status = 0;
    waitpid(pid_, &status, 0);
    pid_ = 0;
    return killed;
#endif
  }

  /// Waits for natural exit and returns the exit code (or nullopt on expiry).
  [[nodiscard]] std::optional<int> wait(std::uint32_t max_seconds = 60) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(max_seconds);
    while (std::chrono::steady_clock::now() < deadline) {
      if (exited()) {
        pump();
        return exit_code_;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return std::nullopt;
  }

  [[nodiscard]] const std::string& output() {
    pump();
    return output_;
  }

  [[nodiscard]] bool running() { return !exited(); }
  [[nodiscard]] const std::filesystem::path& log_path() const noexcept { return log_path_; }

 private:
#if defined(_WIN32)
  using Handle = HANDLE;
  static Handle invalid_handle() { return nullptr; }
#else
  using Handle = int;
  static Handle invalid_handle() { return -1; }
#endif

  Handle handle_ = invalid_handle();
  int pid_ = 0;
  int exit_code_ = 0;
  std::filesystem::path log_path_;
  std::string output_;
};

/// Finds a named executable next to the test binary.
[[nodiscard]] inline std::filesystem::path app_path(const std::string& name) {
  std::filesystem::path directory(CTF_APP_DIRECTORY);
#if defined(_WIN32)
  return directory / (name + ".exe");
#else
  return directory / name;
#endif
}

/// Extracts "key=value" from text, returning nullopt when absent.
[[nodiscard]] inline std::optional<std::string> extract_field(const std::string& text,
                                                             const std::string& key) {
  const std::string needle = key + "=";
  const std::size_t position = text.find(needle);
  if (position == std::string::npos) {
    return std::nullopt;
  }
  const std::size_t begin = position + needle.size();
  std::size_t end = begin;
  while (end < text.size() && text[end] != ' ' && text[end] != '\n' && text[end] != '\r') {
    ++end;
  }
  return text.substr(begin, end - begin);
}

}  // namespace ctf::test
