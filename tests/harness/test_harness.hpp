#pragma once

// Minimal, dependency-free test harness.
//
// Design notes:
//   * tests are proof obligations, so a failure prints file, line, expectation,
//     and the reproduction seed;
//   * a seeded generator is available to every test, and the seed used is
//     printed on failure so a randomized failure can be replayed exactly;
//   * REQUIRE aborts the current test (state after a failed precondition is not
//     meaningful), EXPECT records the failure and continues;
//   * the runner takes no timeouts: a hanging test is a defect to diagnose, not
//     something to hide behind a clock.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ctf::test {

/// Thrown by CTF_REQUIRE to abort the current test only.
class TestAbort : public std::exception {
 public:
  [[nodiscard]] const char* what() const noexcept override { return "test aborted"; }
};

class Context {
 public:
  Context(std::string suite, std::string name, std::uint64_t seed)
      : suite_(std::move(suite)), name_(std::move(name)), rng_(seed), seed_(seed) {}

  [[nodiscard]] const std::string& suite() const noexcept { return suite_; }
  [[nodiscard]] const std::string& name() const noexcept { return name_; }
  [[nodiscard]] std::uint64_t seed() const noexcept { return seed_; }
  [[nodiscard]] std::mt19937_64& rng() noexcept { return rng_; }

  [[nodiscard]] std::uint64_t random_u64() { return rng_(); }
  [[nodiscard]] std::uint64_t random_below(std::uint64_t bound) {
    return bound == 0 ? 0 : rng_() % bound;
  }
  [[nodiscard]] std::uint32_t random_u32() { return static_cast<std::uint32_t>(rng_() & 0xFFFFFFFFULL); }

  void fail(const char* file, int line, const std::string& message) {
    failures_.push_back(std::string(file) + ":" + std::to_string(line) + ": " + message);
    std::cout << "    FAIL " << file << ":" << line << ": " << message << std::endl;
  }

  [[nodiscard]] std::size_t failure_count() const noexcept { return failures_.size(); }
  [[nodiscard]] const std::vector<std::string>& failures() const noexcept { return failures_; }

 private:
  std::string suite_;
  std::string name_;
  std::mt19937_64 rng_;
  std::uint64_t seed_;
  std::vector<std::string> failures_;
};

using TestFn = void (*)(Context&);

struct TestCase {
  std::string suite;
  std::string name;
  TestFn fn;
};

class Registry {
 public:
  static Registry& instance() {
    static Registry registry;
    return registry;
  }

  void add(std::string suite, std::string name, TestFn fn) {
    cases_.push_back(TestCase{std::move(suite), std::move(name), fn});
  }

  [[nodiscard]] const std::vector<TestCase>& cases() const noexcept { return cases_; }

  int run(int argc, char** argv) {
    std::string filter;
    bool list_only = false;
    std::uint64_t base_seed = 0x5EED5EEDULL;
    for (int i = 1; i < argc; ++i) {
      const std::string_view arg(argv[i]);
      if (arg == "--list") {
        list_only = true;
      } else if (arg == "--filter" && i + 1 < argc) {
        filter = argv[++i];
      } else if (arg == "--seed" && i + 1 < argc) {
        base_seed = static_cast<std::uint64_t>(std::strtoull(argv[++i], nullptr, 10));
      } else if (arg == "--help") {
        std::cout << "usage: <suite> [--list] [--filter substring] [--seed N]\n";
        return 0;
      }
    }
    if (list_only) {
      for (const TestCase& test : cases_) {
        std::cout << test.suite << "." << test.name << "\n";
      }
      return 0;
    }
    std::size_t passed = 0;
    std::size_t failed = 0;
    for (std::size_t index = 0; index < cases_.size(); ++index) {
      const TestCase& test = cases_[index];
      const std::string full = test.suite + "." + test.name;
      if (!filter.empty() && full.find(filter) == std::string::npos) {
        continue;
      }
      const std::uint64_t seed = base_seed + index * 0x9E3779B97F4A7C15ULL;
      Context context(test.suite, test.name, seed);
      std::cout << "[ RUN  ] " << full << "\n";
      try {
        test.fn(context);
      } catch (const TestAbort&) {
        // failure already recorded
      } catch (const std::exception& error) {
        context.fail("<test>", 0, std::string("unexpected exception: ") + error.what());
      } catch (...) {
        context.fail("<test>", 0, "unexpected non-standard exception");
      }
      if (context.failure_count() == 0) {
        ++passed;
        std::cout << "[  OK  ] " << full << "\n";
      } else {
        ++failed;
        std::cout << "[ FAIL ] " << full << " (" << context.failure_count()
                  << " failure(s), seed=" << seed << ")\n";
      }
    }
    std::cout << (failed == 0 ? "SUITE PASSED" : "SUITE FAILED") << ": " << passed << " passed, "
              << failed << " failed\n";
    return failed == 0 ? 0 : 1;
  }

 private:
  std::vector<TestCase> cases_;
};

[[nodiscard]] inline std::string describe(const std::string& value) { return "\"" + value + "\""; }
[[nodiscard]] inline std::string describe(const char* value) {
  return std::string("\"") + (value == nullptr ? "<null>" : value) + "\"";
}
[[nodiscard]] inline std::string describe(bool value) { return value ? "true" : "false"; }

/// Renders enums through their to_string overload when one exists, and any
/// streamable value through operator<<.
template <class T>
[[nodiscard]] std::string describe(const T& value) {
  std::ostringstream out;
  if constexpr (std::is_enum_v<T>) {
    if constexpr (requires { to_string(value); }) {
      out << to_string(value);
    } else {
      out << static_cast<long long>(value);
    }
  } else if constexpr (requires { out << value; }) {
    out << value;
  } else {
    out << "<unprintable>";
  }
  return out.str();
}

/// Unique temporary directory that removes itself.
class TempDir {
 public:
  explicit TempDir(std::string_view label) {
    const std::filesystem::path base = std::filesystem::temp_directory_path();
    static std::uint64_t counter = 0;
    ++counter;
    path_ = base / ("ctf-test-" + std::string(label) + "-" + std::to_string(counter) + "-" +
                    std::to_string(static_cast<unsigned long long>(
                        std::chrono::steady_clock::now().time_since_epoch().count())));
    std::error_code error;
    std::filesystem::create_directories(path_, error);
  }

  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

 private:
  std::filesystem::path path_;
};

}  // namespace ctf::test

#define CTF_TEST(suite_name, test_name)                                                        \
  static void ctf_test_body_##suite_name##_##test_name(::ctf::test::Context&);                 \
  namespace {                                                                                  \
  const bool ctf_test_registered_##suite_name##_##test_name =                                  \
      (::ctf::test::Registry::instance().add(#suite_name, #test_name,                          \
                                             &ctf_test_body_##suite_name##_##test_name),       \
       true);                                                                                  \
  }                                                                                            \
  static void ctf_test_body_##suite_name##_##test_name(::ctf::test::Context& ctf_ctx)

#define CTF_EXPECT(expr)                                                                       \
  do {                                                                                         \
    if (!(expr)) {                                                                             \
      ctf_ctx.fail(__FILE__, __LINE__, "expected: " #expr);                                    \
    }                                                                                          \
  } while (false)

#define CTF_EXPECT_EQ(actual, expected)                                                        \
  do {                                                                                         \
    const auto& ctf_actual = (actual);                                                         \
    const auto& ctf_expected = (expected);                                                     \
    if (!(ctf_actual == ctf_expected)) {                                                       \
      ctf_ctx.fail(__FILE__, __LINE__,                                                         \
                   std::string("expected " #actual " == " #expected " but got ") +             \
                       ::ctf::test::describe(ctf_actual) + " vs " +                            \
                       ::ctf::test::describe(ctf_expected));                                   \
    }                                                                                          \
  } while (false)

#define CTF_EXPECT_NE(actual, expected)                                                        \
  do {                                                                                         \
    if ((actual) == (expected)) {                                                              \
      ctf_ctx.fail(__FILE__, __LINE__, "expected " #actual " != " #expected);                   \
    }                                                                                          \
  } while (false)

#define CTF_EXPECT_OK(expr)                                                                    \
  do {                                                                                         \
    const ::ctf::Status ctf_status = (expr);                                                   \
    if (!ctf_status.ok()) {                                                                    \
      ctf_ctx.fail(__FILE__, __LINE__,                                                         \
                   std::string("expected success from " #expr " but got ") +                   \
                       ctf_status.to_string());                                                \
    }                                                                                          \
  } while (false)

#define CTF_EXPECT_CODE(expr, expected_code)                                                   \
  do {                                                                                         \
    const ::ctf::Status ctf_status = (expr);                                                   \
    if (ctf_status.ok() || ctf_status.code() != (expected_code)) {                             \
      ctf_ctx.fail(__FILE__, __LINE__,                                                         \
                   std::string("expected " #expr " to fail with " #expected_code " but got ") + \
                       ctf_status.to_string());                                                \
    }                                                                                          \
  } while (false)

#define CTF_REQUIRE(expr)                                                                      \
  do {                                                                                         \
    if (!(expr)) {                                                                             \
      ctf_ctx.fail(__FILE__, __LINE__, "required: " #expr);                                    \
      throw ::ctf::test::TestAbort();                                                          \
    }                                                                                          \
  } while (false)

#define CTF_REQUIRE_OK(expr)                                                                   \
  do {                                                                                         \
    const ::ctf::Status ctf_status = (expr);                                                   \
    if (!ctf_status.ok()) {                                                                    \
      ctf_ctx.fail(__FILE__, __LINE__,                                                         \
                   std::string("required success from " #expr " but got ") +                   \
                       ctf_status.to_string());                                                \
      throw ::ctf::test::TestAbort();                                                          \
    }                                                                                          \
  } while (false)

#define CTF_REQUIRE_EQ(actual, expected)                                                         do {                                                                                             const auto& ctf_actual = (actual);                                                             const auto& ctf_expected = (expected);                                                         if (!(ctf_actual == ctf_expected)) {                                                             ctf_ctx.fail(__FILE__, __LINE__,                                                                            std::string("required " #actual " == " #expected " but got ") +                                    ::ctf::test::describe(ctf_actual) + " vs " +                                                   ::ctf::test::describe(ctf_expected));                                         throw ::ctf::test::TestAbort();                                                              }                                                                                            } while (false)

#define CTF_MAIN()                                                                             \
  int main(int argc, char** argv) {                                                            \
    return ::ctf::test::Registry::instance().run(argc, argv);                                  \
  }
