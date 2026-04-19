#define HASM_UNIT_TEST
#include "assembler_block_v2.cpp"

#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace hasm;
namespace fs = std::filesystem;

struct TestContext {
  int checks = 0;
  int failures = 0;

  void expect(bool cond, const std::string &msg) {
    ++checks;
    if (!cond) {
      ++failures;
      std::cout << "    FAIL: " << msg << "\n";
    }
  }

  template <typename T, typename U>
  void expect_eq(const T &actual, const U &expected, const std::string &msg) {
    ++checks;
    if (!(actual == expected)) {
      ++failures;
      std::cout << "    FAIL: " << msg
                << " (actual=" << actual << ", expected=" << expected << ")\n";
    }
  }
};

static bool has_error(const LineIR &line, const std::string &needle = "") {
  for (const auto &d : line.diags) {
    if (d.sev != Severity::Error) continue;
    if (needle.empty() || d.msg.find(needle) != std::string::npos) return true;
  }
  return false;
}

static fs::path test_root() {
  fs::path dir = fs::current_path() / "assembler_test_outputs";
  std::error_code ec;
  fs::create_directories(dir, ec);
  return dir;
}

static void write_lines(const fs::path &path, const std::vector<std::string> &lines) {
  std::ofstream out(path);
  for (const auto &line : lines) out << line << "\n";
}

static std::string read_all(const fs::path &path) {
  std::ifstream in(path);
  std::ostringstream oss;
  oss << in.rdbuf();
  return oss.str();
}

static void remove_if_exists(const fs::path &path) {
  std::error_code ec;
  fs::remove(path, ec);
}

static int run_with_capture(const fs::path &src,
                            std::string &captured_stdout,
                            std::string &captured_stderr) {
  std::ostringstream out;
  std::ostringstream err;

  std::streambuf *old_out = std::cout.rdbuf(out.rdbuf());
  std::streambuf *old_err = std::cerr.rdbuf(err.rdbuf());

  std::string src_string = src.string();
  char prog[] = "assembler_block_v2";
  std::vector<char> src_chars(src_string.begin(), src_string.end());
  src_chars.push_back('\0');
  char *argv[] = {prog, src_chars.data()};

  int rc = hasm::run(2, argv);

  std::cout.rdbuf(old_out);
  std::cerr.rdbuf(old_err);

  captured_stdout = out.str();
  captured_stderr = err.str();
  return rc;
}

static void test_parse_block_initialized(TestContext &ctx) {
  Config cfg;
  LineIR ir = parse_line(1, "nums .BLOCK =3, =7, =17", cfg);

  ctx.expect_eq((int)ir.kind, (int)LineKind::DirectiveBlock,
                "initialized .BLOCK should parse as DirectiveBlock");
  ctx.expect(ir.block_name.has_value() && *ir.block_name == "nums",
             "initialized .BLOCK should preserve the symbol name");
  ctx.expect_eq((int)ir.block_mode, (int)BlockMode::InitializedList,
                "initialized .BLOCK should use InitializedList mode");
  ctx.expect_eq(ir.block_span(), 3,
                "initialized .BLOCK should span three cells");
  ctx.expect_eq(ir.block_values.at(0), 3,
                "first initialized .BLOCK value should be 3");
  ctx.expect_eq(ir.block_values.at(1), 7,
                "second initialized .BLOCK value should be 7");
  ctx.expect_eq(ir.block_values.at(2), 17,
                "third initialized .BLOCK value should be 17");
  ctx.expect(!has_error(ir),
             "valid initialized .BLOCK should not produce errors");
}

static void test_parse_block_reserve(TestContext &ctx) {
  Config cfg;
  LineIR ir = parse_line(1, "temp .BLOCK 2", cfg);

  ctx.expect_eq((int)ir.kind, (int)LineKind::DirectiveBlock,
                "reserve .BLOCK should parse as DirectiveBlock");
  ctx.expect_eq((int)ir.block_mode, (int)BlockMode::Reserve,
                "reserve .BLOCK should use Reserve mode");
  ctx.expect(ir.block_reserve_count.has_value() && *ir.block_reserve_count == 2,
             "reserve .BLOCK should keep the requested size");
  ctx.expect_eq(ir.block_span(), 2,
                "reserve .BLOCK should span two cells");
  ctx.expect(!has_error(ir),
             "valid reserve .BLOCK should not produce errors");
}

static void test_parse_block_bad_syntax(TestContext &ctx) {
  Config cfg;
  LineIR ir = parse_line(1, "bad .BLOCK =3, =, =17", cfg);

  ctx.expect_eq((int)ir.kind, (int)LineKind::DirectiveBlock,
                "bad .BLOCK should still be recognized as a .BLOCK line");
  ctx.expect(has_error(ir),
             "bad .BLOCK syntax should produce an error");
}

static void test_pass1_address_assignment(TestContext &ctx) {
  Config cfg;
  std::vector<std::string> lines = {
      ".ALLOC 10",
      "x .DATA =5",
      "nums .BLOCK =3, =7, =17",
      "temp .BLOCK 2",
      ".BEGIN",
      "START: LOAD x",
      "BRANCH START",
      ".END",
  };

  Pass1Result p1 = pass1(lines, cfg);

  ctx.expect(!has_any_errors(p1.ir),
             "well-formed program should pass Pass 1 without errors");
  ctx.expect(p1.dmem_size.has_value() && *p1.dmem_size == 10,
             ".ALLOC size should be preserved in Pass 1");
  ctx.expect_eq(p1.dmem_used, 6,
                "Pass 1 should compute total DMEM usage correctly");
  ctx.expect_eq(p1.imem_count, 2,
                "Pass 1 should compute total IMEM usage correctly");
  ctx.expect_eq(p1.symtab.at("X").address, 0,
                "symbol X should be assigned data address 0");
  ctx.expect_eq(p1.symtab.at("NUMS").address, 1,
                "NUMS should point to the first initialized .BLOCK cell");
  ctx.expect_eq(p1.symtab.at("TEMP").address, 4,
                "TEMP should point to the first reserved .BLOCK cell");
  ctx.expect_eq(p1.symtab.at("START").address, 0,
                "START should be assigned instruction address 0");

  auto p2 = pass2(p1, cfg);
  ctx.expect(p2.has_value(),
             "Pass 2 should succeed for a valid Pass 1 result");
  if (p2.has_value()) {
    ctx.expect_eq(p2->dmem_init.at(0), 5,
                  ".DATA initializer should be emitted into DMEM");
    ctx.expect_eq(p2->dmem_init.at(1), 3,
                  "initialized .BLOCK value 0 should be emitted into DMEM");
    ctx.expect_eq(p2->dmem_init.at(2), 7,
                  "initialized .BLOCK value 1 should be emitted into DMEM");
    ctx.expect_eq(p2->dmem_init.at(3), 17,
                  "initialized .BLOCK value 2 should be emitted into DMEM");
    ctx.expect_eq(p2->dmem_init.at(4), cfg.default_uninitialized,
                  "reserved .BLOCK cells should keep the default value");
    ctx.expect_eq(p2->dmem_init.at(5), cfg.default_uninitialized,
                  "all reserved .BLOCK cells should keep the default value");
  }
}

static void test_pass1_failure_for_undefined_symbol(TestContext &ctx) {
  Config cfg;
  std::vector<std::string> lines = {
      ".ALLOC 4",
      "x .DATA =1",
      ".BEGIN",
      "LOAD missing",
      "HALT",
      ".END",
  };

  Pass1Result p1 = pass1(lines, cfg);

  ctx.expect(has_any_errors(p1.ir),
             "undefined symbol should be detected during Pass 1");
  bool found = false;
  for (const auto &line : p1.ir) {
    if (has_error(line, "Undefined symbol: missing")) found = true;
  }
  ctx.expect(found,
             "Pass 1 should report the undefined symbol by name");
}

static void test_run_failure_skips_pass2_message(TestContext &ctx) {
  fs::path root = test_root();
  const fs::path src = root / "two_pass_failure_sample.hal";
  const fs::path hlx = root / "two_pass_failure_sample.hlx";
  const fs::path hll = root / "two_pass_failure_sample.hll";
  const fs::path log = root / "two_pass_failure_sample.log";

  remove_if_exists(src);
  remove_if_exists(hlx);
  remove_if_exists(hll);
  remove_if_exists(log);

  write_lines(src, {
      ".ALLOC 4",
      "x .DATA =1",
      ".BEGIN",
      "LOAD missing",
      "HALT",
      ".END"
  });

  std::string stdout_text, stderr_text;
  int rc = run_with_capture(src, stdout_text, stderr_text);

  ctx.expect_eq(rc, 1,
                "run() should return 1 for an assembly failure");
  ctx.expect(stdout_text.find("Pass 1: Building symbol table and assigning addresses...") != std::string::npos,
             "failure path should print the Pass 1 message");
  ctx.expect(stdout_text.find("Pass 2: Generating machine code...") == std::string::npos,
             "failure path should not print the Pass 2 message when Pass 1 fails");
  ctx.expect(stdout_text.find("Assembly failed.") != std::string::npos,
             "failure path should report assembly failure");
  ctx.expect(fs::exists(hll),
             "failure path should generate the .hll listing file");
  ctx.expect(fs::exists(log),
             "failure path should generate the .log file");
  ctx.expect(!fs::exists(hlx),
             "failure path should not generate the .hlx file");
  ctx.expect(read_all(log).find("Undefined symbol: missing") != std::string::npos,
             "failure log should mention the undefined symbol");
  ctx.expect(stderr_text.empty(),
             "failure path should not use stderr for a normal assembly error");
}

static void test_run_success_prints_two_pass_messages(TestContext &ctx) {
  fs::path root = test_root();
  const fs::path src = root / "two_pass_success_sample.hal";
  const fs::path hlx = root / "two_pass_success_sample.hlx";
  const fs::path hll = root / "two_pass_success_sample.hll";
  const fs::path log = root / "two_pass_success_sample.log";

  remove_if_exists(src);
  remove_if_exists(hlx);
  remove_if_exists(hll);
  remove_if_exists(log);

  write_lines(src, {
      ".ALLOC 8",
      "x .DATA =4",
      "nums .BLOCK =3, =7, =17",
      "temp .BLOCK 2",
      ".BEGIN",
      "START: LOAD x",
      "WRITE x",
      "HALT",
      ".END",
  });

  std::string stdout_text, stderr_text;
  int rc = run_with_capture(src, stdout_text, stderr_text);

  ctx.expect_eq(rc, 0,
                "run() should return 0 for successful assembly");
  ctx.expect(stdout_text.find("Pass 1: Building symbol table and assigning addresses...") != std::string::npos,
             "success path should print the Pass 1 message");
  ctx.expect(stdout_text.find("Pass 2: Generating machine code...") != std::string::npos,
             "success path should print the Pass 2 message");
  ctx.expect(stdout_text.find("Assembly successful.") != std::string::npos,
             "success path should report assembly success");
  ctx.expect(fs::exists(hlx),
             "success path should generate the .hlx file");
  ctx.expect(fs::exists(hll),
             "success path should generate the .hll listing file");
  ctx.expect(fs::exists(log),
             "success path should generate the .log file");
  ctx.expect(read_all(log).find("Assembly completed with NO errors.") != std::string::npos,
             "success log should explicitly say that no errors were found");
  ctx.expect(stderr_text.empty(),
             "success path should not write to stderr");
}

int main() {
  struct NamedTest {
    std::string name;
    std::function<void(TestContext &)> fn;
  };

  const std::vector<NamedTest> tests = {
      {"parse_line initialized .BLOCK", test_parse_block_initialized},
      {"parse_line reserve .BLOCK", test_parse_block_reserve},
      {"parse_line bad .BLOCK", test_parse_block_bad_syntax},
      {"pass1 address assignment", test_pass1_address_assignment},
      {"pass1 undefined symbol failure", test_pass1_failure_for_undefined_symbol},
      {"run() failure skips Pass 2", test_run_failure_skips_pass2_message},
      {"run() success prints two-pass messages", test_run_success_prints_two_pass_messages},
  };

  TestContext ctx;
  int failed_tests = 0;

  for (const auto &test : tests) {
    std::cout << "[TEST] " << test.name << "\n";
    int failures_before = ctx.failures;
    test.fn(ctx);
    if (ctx.failures == failures_before) {
      std::cout << "    PASS\n";
    } else {
      ++failed_tests;
    }
  }

  std::cout << "\nExecuted " << tests.size()
            << " test(s), " << ctx.checks
            << " check(s), " << ctx.failures
            << " failure(s).\n";

  if (failed_tests == 0 && ctx.failures == 0) {
    std::cout << "All tests passed!\n";
    return 0;
  }

  std::cout << "Some tests failed.\n";
  return 1;
}