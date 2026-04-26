/*
Executive summary
-----------------
This file implements a single-file, self-contained two-pass assembler in C++17.

Compile:
  g++ -std=c++17 -O2 assembler_block_v2.cpp -o assembler

Run:
  ./assembler program.hal
  ./assembler --dump-log program.hal
  ./assembler program.hal --dump-log

Behavior:
  * Pass 1 builds the symbol table and assigns data/instruction addresses.
  * Pass 2 validates operands/mnemonics and generates machine code.
  * Pass 2 is printed and executed only if Pass 1 has no errors.
  * Produces three files next to the input source:
      - <name>.hlx : machine/data image
      - <name>.hll : annotated listing with HAL line mapping
      - <name>.log : error log using original .hal line numbers

Assumptions:
  * .ALLOC range is 1..65535.
  * Data values and initialized .BLOCK values must fit in signed 16-bit range
    (-32768..32767).
  * The instruction encoding remains decimal opcode*100 + operand, so
    data/label/immediate operands used by instructions must still fit in 0..99.
    Large .ALLOC sizes are allowed, but a referenced address above 99 is reported
    as a Pass 2 encoding error.
  * Comments are only valid when '#' is the first non-whitespace character on a
    line. Inline '#' after code is treated as an error.
*/

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace hasm {

struct Config {
  std::string version = "hasm-cpp 0.3-two-pass";
  int default_uninitialized = 9999;
  int word_min = -32768;
  int word_max = 32767;
  int alloc_min = 1;
  int alloc_max = 65535;
  int encoded_operand_min = 0;
  int encoded_operand_max = 99;
  bool case_sensitive = false;
};

static inline bool is_space(unsigned char ch) {
  return std::isspace(ch) != 0;
}

static inline std::string ltrim(std::string s) {
  s.erase(s.begin(),
          std::find_if(s.begin(), s.end(),
                       [](unsigned char ch) { return !is_space(ch); }));
  return s;
}

static inline std::string rtrim(std::string s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](unsigned char ch) { return !is_space(ch); })
              .base(),
          s.end());
  return s;
}

static inline std::string trim(std::string s) {
  return rtrim(ltrim(std::move(s)));
}

static inline std::string to_upper(std::string s) {
  for (char &c : s) {
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  }
  return s;
}

static inline bool iequals(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::toupper(static_cast<unsigned char>(a[i])) !=
        std::toupper(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

static inline bool is_ident(const std::string &s) {
  if (s.empty()) return false;
  auto is_alpha_ = [](char c) {
    const unsigned char uc = static_cast<unsigned char>(c);
    return std::isalpha(uc) != 0 || c == '_';
  };
  auto is_alnum_ = [](char c) {
    const unsigned char uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) != 0 || c == '_';
  };
  if (!is_alpha_(s[0])) return false;
  for (size_t i = 1; i < s.size(); ++i) {
    if (!is_alnum_(s[i])) return false;
  }
  return true;
}

static inline std::vector<std::string> split_ws(const std::string &s) {
  std::istringstream iss(s);
  std::vector<std::string> out;
  std::string tok;
  while (iss >> tok) out.push_back(tok);
  return out;
}

static inline std::optional<int> parse_int_strict(const std::string &s) {
  if (s.empty()) return std::nullopt;
  char *end = nullptr;
  long value = std::strtol(s.c_str(), &end, 10);
  if (end == nullptr || *end != '\0') return std::nullopt;
  if (value < std::numeric_limits<int>::min() ||
      value > std::numeric_limits<int>::max()) {
    return std::nullopt;
  }
  return static_cast<int>(value);
}

static inline std::string basename_only(const std::string &path) {
  const auto slash = path.find_last_of("/\\");
  if (slash == std::string::npos) return path;
  return path.substr(slash + 1);
}

static inline std::optional<std::string> replace_suffix(
    const std::string &path, const std::string &new_ext) {
  const auto pos = path.find_last_of('.');
  if (pos == std::string::npos) return std::nullopt;
  return path.substr(0, pos) + new_ext;
}

static inline std::string canon(const std::string &name,
                                const Config &cfg) {
  return cfg.case_sensitive ? name : to_upper(name);
}

enum class Severity { Note, Warning, Error };

enum class LineKind {
  Blank,
  Comment,
  DirectiveAlloc,
  DirectiveBegin,
  DirectiveEnd,
  DataDecl,
  BlockDecl,
  Instruction,
  Invalid
};

enum class SymKind { Data, Label };
enum class BlockMode { None, Reserve, InitializedList };
enum class OperandKind { None, Symbol, Immediate };
enum class AsmState { BeforeBegin, InCode, AfterEnd };
enum class OperandMode { None, DataAddr, InstAddr, Immediate };

struct Diagnostic {
  Severity sev = Severity::Error;
  std::string code;
  std::string msg;
};

struct SymEntry {
  std::string display_name;
  SymKind kind = SymKind::Data;
  int address = 0;
  int defined_line_no = 0;
};

struct LineIR {
  int hal_line_no = 0;
  std::string raw_text;
  std::string code_text;
  LineKind kind = LineKind::Invalid;

  std::optional<int> alloc_value;

  std::optional<std::string> data_name;
  std::optional<int> data_init;

  std::optional<std::string> block_name;
  BlockMode block_mode = BlockMode::None;
  std::optional<int> block_reserve_count;
  std::vector<int> block_values;

  std::optional<std::string> label_def;
  std::optional<std::string> mnemonic;
  OperandKind operand_kind = OperandKind::None;
  std::optional<std::string> operand_symbol;
  std::optional<int> operand_immediate;

  std::optional<int> dmem_addr;
  std::optional<int> imem_addr;
  std::optional<int> machine_word;

  std::vector<Diagnostic> diags;

  void add(Severity sev, std::string code, std::string msg) {
    diags.push_back(Diagnostic{sev, std::move(code), std::move(msg)});
  }

  void err(std::string code, std::string msg) {
    add(Severity::Error, std::move(code), std::move(msg));
  }

  int block_span() const {
    if (block_mode == BlockMode::Reserve &&
        block_reserve_count.has_value()) {
      return *block_reserve_count;
    }
    if (block_mode == BlockMode::InitializedList) {
      return static_cast<int>(block_values.size());
    }
    return 0;
  }
};

struct OpInfo {
  int opcode = 0;
  OperandMode mode = OperandMode::None;
};

static inline std::unordered_map<std::string, OpInfo> build_optab() {
  std::unordered_map<std::string, OpInfo> t;
  auto add = [&](const std::string &mnem, int op, OperandMode mode) {
    t.emplace(to_upper(mnem), OpInfo{op, mode});
  };

  add("READ",    1, OperandMode::DataAddr);
  add("WRITE",   2, OperandMode::DataAddr);
  add("LOAD",    3, OperandMode::DataAddr);
  add("STORE",   4, OperandMode::DataAddr);
  add("ADD",     5, OperandMode::DataAddr);
  add("SUB",     6, OperandMode::DataAddr);
  add("MULT",    7, OperandMode::DataAddr);
  add("DIV",     8, OperandMode::DataAddr);
  add("MOD",     9, OperandMode::DataAddr);
  add("BRANCH", 10, OperandMode::InstAddr);
  add("BRT",    11, OperandMode::InstAddr);
  add("BRF",    12, OperandMode::InstAddr);
  add("CLEAR",  13, OperandMode::None);
  add("SET",    14, OperandMode::None);
  add("DOUBLE", 15, OperandMode::DataAddr);
  add("INCR",   16, OperandMode::None);
  add("DECR",   17, OperandMode::None);
  add("CLT",    18, OperandMode::DataAddr);
  add("CLE",    19, OperandMode::DataAddr);
  add("CEQ",    20, OperandMode::DataAddr);
  add("CNE",    21, OperandMode::DataAddr);
  add("CGE",    22, OperandMode::DataAddr);
  add("CGT",    23, OperandMode::DataAddr);
  add("SETI",   24, OperandMode::Immediate);
  add("ADDI",   25, OperandMode::Immediate);
  add("SUBI",   26, OperandMode::Immediate);
  add("MULTI",  27, OperandMode::Immediate);
  add("DIVI",   28, OperandMode::Immediate);
  add("MODI",   29, OperandMode::Immediate);
  add("POW",    30, OperandMode::DataAddr);
  add("SHACC",  31, OperandMode::None);
  add("BSUB",   32, OperandMode::InstAddr);
  add("RET",    33, OperandMode::None);
  add("SHINDX", 34, OperandMode::None);
  add("LOADA",  35, OperandMode::DataAddr);
  add("ICLR",   36, OperandMode::None);
  add("IREAD",  37, OperandMode::None);
  add("IWRITE", 38, OperandMode::None);
  add("ILOAD",  39, OperandMode::None);
  add("ISTORE", 40, OperandMode::None);
  add("IINCR",  41, OperandMode::None);
  add("IDECR",  42, OperandMode::None);
  add("IADD",   43, OperandMode::None);
  add("ISUB",   44, OperandMode::None);
  add("IMULT",  45, OperandMode::None);
  add("IDIV",   46, OperandMode::None);
  add("IMOD",   47, OperandMode::None);
  add("ICLT",   48, OperandMode::None);
  add("ICLE",   49, OperandMode::None);
  add("ICEQ",   50, OperandMode::None);
  add("ICNE",   51, OperandMode::None);
  add("ICGE",   52, OperandMode::None);
  add("ICGT",   53, OperandMode::None);
  add("SHBASE", 54, OperandMode::None);
  add("HALT",   99, OperandMode::None);
  return t;
}

struct Pass1Result {
  std::vector<LineIR> ir;
  std::unordered_map<std::string, SymEntry> symtab;
  std::optional<int> alloc_size;
  int alloc_line_index = -1;
  int dmem_used = 0;
  int imem_count = 0;
  bool saw_alloc_directive = false;
  bool seen_begin = false;
  bool seen_end = false;
};

struct Pass2Result {
  std::vector<int> imem_words;
  std::vector<int> dmem_values;
};

static bool has_any_errors(const std::vector<LineIR> &ir) {
  for (const auto &line : ir) {
    for (const auto &d : line.diags) {
      if (d.sev == Severity::Error) return true;
    }
  }
  return false;
}

static int count_errors(const std::vector<LineIR> &ir) {
  int total = 0;
  for (const auto &line : ir) {
    for (const auto &d : line.diags) {
      if (d.sev == Severity::Error) ++total;
    }
  }
  return total;
}

static void attach_global_error(std::vector<LineIR> &ir, int at_index,
                                std::string code, std::string msg) {
  if (ir.empty()) return;
  if (at_index < 0) at_index = 0;
  if (at_index >= static_cast<int>(ir.size())) {
    at_index = static_cast<int>(ir.size()) - 1;
  }
  ir[static_cast<size_t>(at_index)].err(std::move(code), std::move(msg));
}

static size_t skip_ws(const std::string &s, size_t pos) {
  while (pos < s.size() && is_space(static_cast<unsigned char>(s[pos]))) {
    ++pos;
  }
  return pos;
}

static std::optional<std::pair<std::string, size_t>> read_token(
    const std::string &s, size_t pos) {
  pos = skip_ws(s, pos);
  if (pos >= s.size()) return std::nullopt;
  size_t end = pos;
  while (end < s.size() && !is_space(static_cast<unsigned char>(s[end]))) {
    ++end;
  }
  return std::make_pair(s.substr(pos, end - pos), end);
}

static std::string capture_initializer_snippet(const std::string &payload,
                                               size_t eq_pos) {
  size_t end = eq_pos;
  while (end < payload.size() && payload[end] != ',') ++end;
  return trim(payload.substr(eq_pos, end - eq_pos));
}

static bool add_symbol(Pass1Result &p1, LineIR &line,
                       const std::string &name, SymKind kind, int address,
                       const Config &cfg) {
  const std::string key = canon(name, cfg);
  auto it = p1.symtab.find(key);
  if (it != p1.symtab.end()) {
    line.err("E_SYM_DUP",
             "Duplicate symbol '" + name + "' (matches earlier symbol '" +
                 it->second.display_name + "' defined on line " +
                 std::to_string(it->second.defined_line_no) + ").");
    return false;
  }
  p1.symtab.emplace(key, SymEntry{name, kind, address, line.hal_line_no});
  return true;
}

static LineIR parse_alloc_line(int line_no, const std::string &raw,
                               const std::string &code,
                               const Config &cfg) {
  LineIR ir;
  ir.hal_line_no = line_no;
  ir.raw_text = raw;
  ir.code_text = code;
  ir.kind = LineKind::DirectiveAlloc;

  const auto tok = read_token(code, 0);
  if (!tok.has_value() || !iequals(tok->first, ".ALLOC")) {
    ir.kind = LineKind::Invalid;
    ir.err("E_INTERNAL", "Internal parser error while reading .ALLOC.");
    return ir;
  }

  const size_t after = skip_ws(code, tok->second);
  if (after >= code.size()) {
    ir.err("E_ALLOC_MISSING",
           ".ALLOC requires a single positive integer (1..65535); value is missing.");
    return ir;
  }

  const std::string payload = trim(code.substr(after));
  const auto parts = split_ws(payload);
  if (parts.size() != 1) {
    ir.err("E_ALLOC_FMT",
           ".ALLOC requires a single positive integer (1..65535); got '" +
               payload + "'.");
    return ir;
  }

  const auto value = parse_int_strict(parts[0]);
  if (!value.has_value()) {
    ir.err("E_ALLOC_INT",
           ".ALLOC requires a single positive integer (1..65535); got '" +
               parts[0] + "'.");
    return ir;
  }

  if (*value < cfg.alloc_min || *value > cfg.alloc_max) {
    ir.err("E_ALLOC_RANGE",
           ".ALLOC requires a single positive integer (1..65535); got '" +
               parts[0] + "'.");
    return ir;
  }

  ir.alloc_value = *value;
  return ir;
}

static LineIR parse_data_line(int line_no, const std::string &raw,
                              const std::string &code,
                              const std::string &name,
                              size_t after_directive_pos,
                              const Config &cfg) {
  LineIR ir;
  ir.hal_line_no = line_no;
  ir.raw_text = raw;
  ir.code_text = code;
  ir.kind = LineKind::DataDecl;
  ir.data_name = name;

  const size_t pos = skip_ws(code, after_directive_pos);
  if (pos >= code.size()) {
    return ir;
  }

  const std::string tail = code.substr(pos);
  if (tail[0] != '=') {
    ir.err("E_DATA_FMT",
           "Invalid .DATA syntax. Expected '" + name +
               " .DATA' or '" + name +
               " .DATA =<integer>' with no space after '='.");
    return ir;
  }

  if (tail.size() == 1) {
    ir.err("E_DATA_INIT",
           "Invalid .DATA initializer '='. Expected '=integer' with no space after '='.");
    return ir;
  }

  if (is_space(static_cast<unsigned char>(tail[1]))) {
    ir.err("E_DATA_INIT_SPACE",
           "Invalid .DATA initializer '= " + trim(tail.substr(2)) +
               "' (no space allowed after '=').");
    return ir;
  }

  const auto parts = split_ws(tail);
  if (parts.size() != 1) {
    ir.err("E_DATA_FMT",
           "Invalid .DATA initializer '" + tail +
               "'. Expected '=integer' with no space after '='.");
    return ir;
  }

  const std::string value_token = parts[0].substr(1);
  const auto value = parse_int_strict(value_token);
  if (!value.has_value()) {
    ir.err("E_DATA_INT",
           "Invalid .DATA initializer '" + parts[0] +
               "'. Expected '=integer'.");
    return ir;
  }

  if (*value < cfg.word_min || *value > cfg.word_max) {
    ir.err("E_DATA_RANGE",
           ".DATA initializer out of range (" +
               std::to_string(cfg.word_min) + ".." +
               std::to_string(cfg.word_max) + "); got '" + parts[0] + "'.");
    return ir;
  }

  ir.data_init = *value;
  return ir;
}

static LineIR parse_block_line(int line_no, const std::string &raw,
                               const std::string &code,
                               const std::optional<std::string> &name,
                               size_t after_directive_pos,
                               const Config &cfg) {
  LineIR ir;
  ir.hal_line_no = line_no;
  ir.raw_text = raw;
  ir.code_text = code;
  ir.kind = LineKind::BlockDecl;
  ir.block_name = name;

  const size_t pos = skip_ws(code, after_directive_pos);
  if (pos >= code.size()) {
    ir.err("E_BLOCK_MISSING",
           ".BLOCK requires either a single positive integer or an initialized list like '=3, =7, =17'.");
    return ir;
  }

  const std::string payload = code.substr(pos);
  const std::string payload_trimmed = trim(payload);
  if (payload_trimmed.empty()) {
    ir.err("E_BLOCK_MISSING",
           ".BLOCK requires either a single positive integer or an initialized list like '=3, =7, =17'.");
    return ir;
  }

  if (payload_trimmed[0] != '=') {
    const auto parts = split_ws(payload_trimmed);
    if (parts.size() != 1) {
      ir.err("E_BLOCK_FMT",
             ".BLOCK reserve form requires a single positive integer or an initialized list; got '" +
                 payload_trimmed + "'.");
      return ir;
    }

    const auto value = parse_int_strict(parts[0]);
    if (!value.has_value()) {
      ir.err("E_BLOCK_INT",
             ".BLOCK reserve form requires a single positive integer; got '" +
                 parts[0] + "'.");
      return ir;
    }

    if (*value <= 0 || *value > cfg.alloc_max) {
      ir.err("E_BLOCK_RANGE",
             ".BLOCK reserve count must be a positive integer (1..65535); got '" +
                 parts[0] + "'.");
      return ir;
    }

    ir.block_mode = BlockMode::Reserve;
    ir.block_reserve_count = *value;
    return ir;
  }

  // Strict initialized list parser: '=v, =w, ...' and no space after '='.
  size_t i = 0;
  const std::string &s = payload_trimmed;
  while (i < s.size()) {
    i = skip_ws(s, i);
    if (i >= s.size()) break;

    if (s[i] != '=') {
      ir.err("E_BLOCK_FMT",
             "Invalid .BLOCK initializer sequence near '" + trim(s.substr(i)) +
                 "'. Expected '=integer'.");
      return ir;
    }

    const size_t eq_pos = i;
    ++i;
    if (i >= s.size()) {
      ir.err("E_BLOCK_INIT",
             "Invalid .BLOCK initializer '='. Expected '=integer' with no space after '='.");
      return ir;
    }

    if (is_space(static_cast<unsigned char>(s[i]))) {
      ir.err("E_BLOCK_INIT_SPACE",
             "Invalid .BLOCK initializer '" +
                 capture_initializer_snippet(s, eq_pos) +
                 "' (no space allowed after '=').");
      return ir;
    }

    size_t value_start = i;
    if (s[i] == '+' || s[i] == '-') ++i;
    size_t digit_start = i;
    while (i < s.size() &&
           std::isdigit(static_cast<unsigned char>(s[i])) != 0) {
      ++i;
    }
    if (digit_start == i) {
      ir.err("E_BLOCK_INIT",
             "Invalid .BLOCK initializer '" +
                 capture_initializer_snippet(s, eq_pos) +
                 "'. Expected '=integer'.");
      return ir;
    }

    const std::string value_text = s.substr(value_start, i - value_start);
    const auto value = parse_int_strict(value_text);
    if (!value.has_value()) {
      ir.err("E_BLOCK_INT",
             "Invalid .BLOCK initializer '=" + value_text +
                 "'. Expected 16-bit signed integer.");
      return ir;
    }

    if (*value < cfg.word_min || *value > cfg.word_max) {
      ir.err("E_BLOCK_RANGE",
             ".BLOCK initializer out of range (" +
                 std::to_string(cfg.word_min) + ".." +
                 std::to_string(cfg.word_max) + "); got '=" + value_text +
                 "'.");
      return ir;
    }

    ir.block_values.push_back(*value);

    i = skip_ws(s, i);
    if (i >= s.size()) break;
    if (s[i] != ',') {
      ir.err("E_BLOCK_FMT",
             "Invalid .BLOCK initializer sequence near '" + trim(s.substr(i)) +
                 "'. Expected ',' between initializers.");
      return ir;
    }

    ++i;
    i = skip_ws(s, i);
    if (i >= s.size()) {
      ir.err("E_BLOCK_FMT",
             "Invalid .BLOCK initializer list. Trailing comma is not allowed.");
      return ir;
    }
  }

  if (ir.block_values.empty()) {
    ir.err("E_BLOCK_MISSING",
           "Initialized .BLOCK must contain at least one value.");
    return ir;
  }

  ir.block_mode = BlockMode::InitializedList;
  return ir;
}

static LineIR parse_instruction_line(int line_no, const std::string &raw,
                                     const std::string &code,
                                     const Config &cfg) {
  (void)cfg;
  LineIR ir;
  ir.hal_line_no = line_no;
  ir.raw_text = raw;
  ir.code_text = code;
  ir.kind = LineKind::Instruction;

  std::string work = trim(code);
  if (work.empty()) {
    ir.kind = LineKind::Blank;
    return ir;
  }

  // Optional label definition.
  const size_t colon = work.find(':');
  if (colon != std::string::npos) {
    const std::string left = trim(work.substr(0, colon));
    const std::string right = trim(work.substr(colon + 1));

    if (left.empty() || !is_ident(left)) {
      ir.err("E_LABEL_FMT", "Invalid label definition before ':'.");
    } else {
      ir.label_def = left;
    }

    if (right.empty()) {
      ir.err("E_LABEL_ONLY",
             "Label must be followed by an instruction on the same line.");
      ir.kind = LineKind::Invalid;
      return ir;
    }

    work = right;
  }

  const auto first = read_token(work, 0);
  if (!first.has_value()) {
    ir.err("E_MNEM_MISSING", "Missing instruction mnemonic.");
    ir.kind = LineKind::Invalid;
    return ir;
  }

  if (!is_ident(first->first)) {
    ir.err("E_MNEM_FMT",
           "Invalid mnemonic format '" + first->first + "'.");
    ir.kind = LineKind::Invalid;
    return ir;
  }

  ir.mnemonic = first->first;
  const size_t after_mnemonic = skip_ws(work, first->second);
  if (after_mnemonic >= work.size()) {
    ir.operand_kind = OperandKind::None;
    return ir;
  }

  const std::string rest = work.substr(after_mnemonic);

  if (rest[0] == '=') {
    if (rest.size() == 1) {
      ir.err("E_IMM_FMT",
             "Invalid immediate operand '='. Expected '=integer' with no space after '='.");
      return ir;
    }

    if (is_space(static_cast<unsigned char>(rest[1]))) {
      ir.err("E_IMM_SPACE",
             "Invalid immediate operand '= " + trim(rest.substr(2)) +
                 "' (no space allowed after '=').");
      return ir;
    }

    const auto parts = split_ws(rest);
    if (parts.size() != 1) {
      ir.err("E_IMM_FMT",
             "Invalid immediate operand '" + rest +
                 "'. Expected '=integer' with no embedded spaces.");
      return ir;
    }

    const auto value = parse_int_strict(parts[0].substr(1));
    if (!value.has_value()) {
      ir.err("E_IMM_INT",
             "Invalid immediate operand '" + parts[0] +
                 "'. Expected '=integer'.");
      return ir;
    }

    ir.operand_kind = OperandKind::Immediate;
    ir.operand_immediate = *value;
    return ir;
  }

  const auto parts = split_ws(rest);
  if (parts.size() != 1) {
    ir.err("E_OPERAND_FMT",
           "Invalid operand format '" + rest +
               "'. Expected a single symbol or '=integer'.");
    return ir;
  }

  if (!is_ident(parts[0])) {
    ir.err("E_OPERAND_FMT",
           "Invalid operand symbol '" + parts[0] +
               "'. Expected an identifier or '=integer'.");
    return ir;
  }

  ir.operand_kind = OperandKind::Symbol;
  ir.operand_symbol = parts[0];
  return ir;
}

static LineIR parse_line(int line_no, const std::string &raw,
                         const Config &cfg) {
  LineIR ir;
  ir.hal_line_no = line_no;
  ir.raw_text = raw;

  const size_t first_non_ws =
      raw.find_first_not_of(" \t\r\n\v\f");
  if (first_non_ws == std::string::npos) {
    ir.kind = LineKind::Blank;
    return ir;
  }

  if (raw[first_non_ws] == '#') {
    ir.kind = LineKind::Comment;
    ir.code_text.clear();
    return ir;
  }

  if (raw.find('#') != std::string::npos) {
    ir.kind = LineKind::Invalid;
    ir.code_text = raw;
    ir.err("E_COMMENT_FMT",
           "Malformed comment. '#' is only allowed as the first non-whitespace character on a line.");
    return ir;
  }

  const std::string code = trim(raw);
  const auto first = read_token(code, 0);
  if (!first.has_value()) {
    ir.kind = LineKind::Blank;
    return ir;
  }

  const std::string first_tok = first->first;
  const size_t after_first = first->second;

  if (iequals(first_tok, ".ALLOC")) {
    return parse_alloc_line(line_no, raw, code, cfg);
  }
  if (iequals(first_tok, ".BEGIN")) {
    ir.code_text = code;
    ir.kind = LineKind::DirectiveBegin;
    if (skip_ws(code, after_first) != code.size()) {
      ir.err("E_BEGIN_FMT",
             ".BEGIN does not accept operands or extra tokens.");
    }
    return ir;
  }
  if (iequals(first_tok, ".END")) {
    ir.code_text = code;
    ir.kind = LineKind::DirectiveEnd;
    if (skip_ws(code, after_first) != code.size()) {
      ir.err("E_END_FMT",
             ".END does not accept operands or extra tokens.");
    }
    return ir;
  }
  if (iequals(first_tok, ".BLOCK")) {
    return parse_block_line(line_no, raw, code, std::nullopt, after_first,
                            cfg);
  }

  if (is_ident(first_tok)) {
    const auto second = read_token(code, after_first);
    if (second.has_value() && iequals(second->first, ".DATA")) {
      return parse_data_line(line_no, raw, code, first_tok, second->second,
                             cfg);
    }
    if (second.has_value() && iequals(second->first, ".BLOCK")) {
      return parse_block_line(line_no, raw, code, first_tok, second->second,
                              cfg);
    }
  }

  return parse_instruction_line(line_no, raw, code, cfg);
}

static Pass1Result pass1(const std::vector<std::string> &lines,
                         const Config &cfg) {
  Pass1Result p1;
  p1.ir.reserve(lines.size());

  AsmState state = AsmState::BeforeBegin;
  int next_dmem = 0;
  int next_imem = 0;

  for (size_t i = 0; i < lines.size(); ++i) {
    LineIR line = parse_line(static_cast<int>(i) + 1, lines[i], cfg);
    p1.ir.push_back(std::move(line));
    LineIR &ir = p1.ir.back();

    if (ir.kind == LineKind::Blank || ir.kind == LineKind::Comment) {
      continue;
    }

    if (state == AsmState::AfterEnd) {
      ir.err("E_AFTER_END", "Statement after .END is not allowed.");
      continue;
    }

    switch (ir.kind) {
      case LineKind::DirectiveAlloc: {
        if (state != AsmState::BeforeBegin) {
          ir.err("E_ALLOC_POS", ".ALLOC must appear before .BEGIN.");
        }
        if (p1.saw_alloc_directive) {
          ir.err("E_ALLOC_DUP", "Duplicate .ALLOC directive.");
        }
        if (!p1.saw_alloc_directive) {
          p1.saw_alloc_directive = true;
          if (ir.alloc_value.has_value()) {
            p1.alloc_size = ir.alloc_value;
            p1.alloc_line_index = static_cast<int>(i);
          }
        }
        break;
      }

      case LineKind::DirectiveBegin: {
        if (p1.seen_begin) {
          ir.err("E_BEGIN_DUP", "Duplicate .BEGIN directive.");
        } else if (state != AsmState::BeforeBegin) {
          ir.err("E_BEGIN_POS", ".BEGIN is misplaced.");
        } else {
          p1.seen_begin = true;
          state = AsmState::InCode;
        }
        break;
      }

      case LineKind::DirectiveEnd: {
        if (!p1.seen_begin || state != AsmState::InCode) {
          ir.err("E_END_POS", ".END without matching .BEGIN.");
        } else if (p1.seen_end) {
          ir.err("E_END_DUP", "Duplicate .END directive.");
        } else {
          p1.seen_end = true;
          state = AsmState::AfterEnd;
        }
        break;
      }

      case LineKind::DataDecl: {
        if (state != AsmState::BeforeBegin) {
          ir.err("E_DATA_POS",
                 ".DATA declarations must appear before .BEGIN.");
          break;
        }
        if (ir.data_name.has_value() && ir.diags.empty()) {
          ir.dmem_addr = next_dmem;
          add_symbol(p1, ir, *ir.data_name, SymKind::Data, next_dmem, cfg);
          ++next_dmem;
          if (!ir.data_init.has_value()) {
            ir.data_init = cfg.default_uninitialized;
          }
        }
        break;
      }

      case LineKind::BlockDecl: {
        if (state != AsmState::BeforeBegin) {
          ir.err("E_BLOCK_POS",
                 ".BLOCK declarations must appear before .BEGIN.");
          break;
        }
        if (ir.diags.empty()) {
          const int span = ir.block_span();
          if (span > 0) {
            ir.dmem_addr = next_dmem;
            if (ir.block_name.has_value()) {
              add_symbol(p1, ir, *ir.block_name, SymKind::Data, next_dmem,
                         cfg);
            }
            next_dmem += span;
          }
        }
        break;
      }

      case LineKind::Instruction: {
        if (state != AsmState::InCode) {
          ir.err("E_INSTR_POS",
                 "Instruction outside .BEGIN/.END block.");
          break;
        }
        if (ir.label_def.has_value()) {
          add_symbol(p1, ir, *ir.label_def, SymKind::Label, next_imem, cfg);
        }
        ir.imem_addr = next_imem;
        ++next_imem;
        break;
      }

      case LineKind::Invalid:
        // Parse errors already attached.
        break;

      case LineKind::Blank:
      case LineKind::Comment:
        break;
    }
  }

  p1.dmem_used = next_dmem;
  p1.imem_count = next_imem;

  if (p1.ir.empty()) {
    LineIR placeholder;
    placeholder.hal_line_no = 1;
    placeholder.kind = LineKind::Blank;
    p1.ir.push_back(std::move(placeholder));
  }

  if (!p1.saw_alloc_directive) {
    attach_global_error(p1.ir, 0, "E_MISSING_ALLOC",
                        "Missing .ALLOC directive before .BEGIN.");
  }
  if (!p1.seen_begin) {
    attach_global_error(p1.ir, 0, "E_MISSING_BEGIN",
                        "Missing .BEGIN directive.");
  }
  if (p1.seen_begin && !p1.seen_end) {
    attach_global_error(p1.ir, static_cast<int>(p1.ir.size()) - 1,
                        "E_MISSING_END", "Missing .END directive.");
  }
  if (p1.alloc_size.has_value() && p1.dmem_used > *p1.alloc_size) {
    const int idx = (p1.alloc_line_index >= 0) ? p1.alloc_line_index : 0;
    attach_global_error(p1.ir, idx, "E_DMEM_OVERFLOW",
                        "Allocated data size is too small. .ALLOC reserves " +
                            std::to_string(*p1.alloc_size) +
                            " cell(s), but declarations require " +
                            std::to_string(p1.dmem_used) + ".");
  }

  return p1;
}

static std::optional<Pass2Result> pass2(Pass1Result &p1,
                                        const Config &cfg) {
  const auto optab = build_optab();

  if (!p1.alloc_size.has_value()) {
    attach_global_error(
        p1.ir, 0, "E_NO_ALLOC",
        "Cannot generate machine code without a valid .ALLOC value.");
    return std::nullopt;
  }

  Pass2Result out;
  out.imem_words.assign(static_cast<size_t>(p1.imem_count), 0);
  out.dmem_values.assign(static_cast<size_t>(*p1.alloc_size),
                         cfg.default_uninitialized);

  for (auto &line : p1.ir) {
    if (line.kind == LineKind::DataDecl && line.dmem_addr.has_value()) {
      out.dmem_values[static_cast<size_t>(*line.dmem_addr)] =
          line.data_init.value_or(cfg.default_uninitialized);
    } else if (line.kind == LineKind::BlockDecl &&
               line.dmem_addr.has_value()) {
      if (line.block_mode == BlockMode::InitializedList) {
        const int base = *line.dmem_addr;
        for (size_t i = 0; i < line.block_values.size(); ++i) {
          out.dmem_values[static_cast<size_t>(base + static_cast<int>(i))] =
              line.block_values[i];
        }
      }
    }
  }

  for (auto &line : p1.ir) {
    if (line.kind != LineKind::Instruction || !line.imem_addr.has_value()) {
      continue;
    }

    if (!line.mnemonic.has_value()) {
      line.err("E_MNEM_MISSING", "Missing instruction mnemonic.");
      continue;
    }

    const std::string mnem_key = to_upper(*line.mnemonic);
    const auto op_it = optab.find(mnem_key);
    if (op_it == optab.end()) {
      line.err("E_BAD_OPCODE",
               "Invalid opcode/mnemonic '" + *line.mnemonic + "'.");
      continue;
    }

    int operand_value = 0;
    switch (op_it->second.mode) {
      case OperandMode::None: {
        if (line.operand_kind != OperandKind::None) {
          line.err("E_OPERAND_UNEXPECTED",
                   "Instruction '" + *line.mnemonic +
                       "' does not take an operand.");
        }
        break;
      }

      case OperandMode::Immediate: {
        if (line.operand_kind != OperandKind::Immediate ||
            !line.operand_immediate.has_value()) {
          line.err(
              "E_OPERAND_IMM",
              "Instruction '" + *line.mnemonic +
                  "' requires an immediate operand of the form '=number'.");
          break;
        }

        if (*line.operand_immediate < cfg.encoded_operand_min ||
            *line.operand_immediate > cfg.encoded_operand_max) {
          line.err("E_IMM_RANGE",
                   "Immediate operand for '" + *line.mnemonic +
                       "' must be in range " +
                       std::to_string(cfg.encoded_operand_min) + ".." +
                       std::to_string(cfg.encoded_operand_max) + "; got '" +
                       std::to_string(*line.operand_immediate) + "'.");
          break;
        }

        operand_value = *line.operand_immediate;
        break;
      }

      case OperandMode::DataAddr:
      case OperandMode::InstAddr: {
        if (line.operand_kind != OperandKind::Symbol ||
            !line.operand_symbol.has_value()) {
          line.err("E_OPERAND_SYM",
                   "Instruction '" + *line.mnemonic +
                       "' requires a symbolic operand.");
          break;
        }

        const auto sym_it =
            p1.symtab.find(canon(*line.operand_symbol, cfg));
        if (sym_it == p1.symtab.end()) {
          line.err("E_UNDEF_SYM",
                   "Undefined symbol '" + *line.operand_symbol + "'.");
          break;
        }

        const SymKind expected =
            (op_it->second.mode == OperandMode::DataAddr)
                ? SymKind::Data
                : SymKind::Label;

        if (sym_it->second.kind != expected) {
          const std::string expected_text =
              (expected == SymKind::Data) ? "data symbol" : "label";
          line.err("E_SYM_KIND",
                   "Operand '" + *line.operand_symbol + "' must be a " +
                       expected_text + " for instruction '" + *line.mnemonic +
                       "'.");
          break;
        }

        if (sym_it->second.address < cfg.encoded_operand_min ||
            sym_it->second.address > cfg.encoded_operand_max) {
          line.err(
              "E_ADDR_RANGE",
              "Address " + std::to_string(sym_it->second.address) +
                  " for symbol '" + sym_it->second.display_name +
                  "' cannot be encoded in the instruction operand field (" +
                  std::to_string(cfg.encoded_operand_min) + ".." +
                  std::to_string(cfg.encoded_operand_max) + ").");
          break;
        }

        operand_value = sym_it->second.address;
        break;
      }
    }

    if (!line.diags.empty()) continue;

    const int word = op_it->second.opcode * 100 + operand_value;
    line.machine_word = word;
    out.imem_words[static_cast<size_t>(*line.imem_addr)] = word;
  }

  if (has_any_errors(p1.ir)) return std::nullopt;
  return out;
}

static std::string fmt_machine_word(int value) {
  std::ostringstream oss;
  oss << std::setw(4) << std::setfill('0') << value;
  return oss.str();
}

static std::string fmt_addr(int value) {
  std::ostringstream oss;
  oss << value;
  return oss.str();
}

static std::string fmt_data_word(int value) {
  return std::to_string(value);
}

static void write_hll(const std::string &hll_path,
                      const std::string &src_name,
                      const std::string &hll_name,
                      const std::string &hlx_name,
                      const Pass1Result &p1,
                      const Config &cfg) {
  std::ofstream out(hll_path);
  if (!out) return;

  out << "Source:  " << src_name << "\n";
  out << "Listing: " << hll_name << "\n";
  out << "Machine: " << hlx_name << "\n";
  out << "Version: " << cfg.version << "\n\n";
  out << "HAL   SEC   ADDR     WORD       SOURCE\n";

  for (const auto &line : p1.ir) {
    auto emit_row = [&](const std::string &sec, const std::string &addr,
                        const std::string &word, const std::string &src) {
      out << std::left << std::setw(5) << line.hal_line_no
          << std::setw(6) << sec
          << std::setw(9) << addr
          << std::setw(11) << word
          << src << "\n";
    };

    if (line.kind == LineKind::BlockDecl && line.dmem_addr.has_value() &&
        line.block_span() > 0) {
      const int base = *line.dmem_addr;
      const int span = line.block_span();
      for (int i = 0; i < span; ++i) {
        int value = cfg.default_uninitialized;
        if (line.block_mode == BlockMode::InitializedList) {
          value = line.block_values[static_cast<size_t>(i)];
        }
        emit_row("D", fmt_addr(base + i), fmt_data_word(value),
                 i == 0 ? line.raw_text : "");
      }
    } else if (line.kind == LineKind::DataDecl &&
               line.dmem_addr.has_value()) {
      emit_row(
          "D", fmt_addr(*line.dmem_addr),
          fmt_data_word(line.data_init.value_or(cfg.default_uninitialized)),
          line.raw_text);
    } else if (line.kind == LineKind::Instruction &&
               line.imem_addr.has_value()) {
      emit_row("I", fmt_addr(*line.imem_addr),
               line.machine_word.has_value()
                   ? fmt_machine_word(*line.machine_word)
                   : "????",
               line.raw_text);
    } else {
      emit_row("-", "-", "-", line.raw_text);
    }

    for (const auto &d : line.diags) {
      const char *sev = (d.sev == Severity::Error)
                            ? "ERROR"
                            : (d.sev == Severity::Warning) ? "WARN" : "NOTE";
      out << "      >>> " << sev << " " << d.code << ": " << d.msg << "\n";
    }
  }
}

static void write_hlx(const std::string &hlx_path,
                      const Pass2Result &p2,
                      int imem_count,
                      int alloc_size) {
  std::ofstream out(hlx_path);
  if (!out) return;

  out << imem_count << "\n";
  for (int word : p2.imem_words) {
    out << fmt_machine_word(word) << "\n";
  }
  out << alloc_size << "\n";
  for (int value : p2.dmem_values) {
    out << value << "\n";
  }
}

static void write_log(const std::string &log_path,
                      const Pass1Result &p1) {
  std::ofstream out(log_path);
  if (!out) return;

  const int errors = count_errors(p1.ir);
  if (errors == 0) {
    out << "Assembly completed with NO errors.\n";
    return;
  }

  out << "Assembly completed with " << errors << " error(s):\n\n";
  for (const auto &line : p1.ir) {
    for (const auto &d : line.diags) {
      if (d.sev != Severity::Error) continue;
      out << "LINE " << line.hal_line_no << ": ERROR - " << d.msg << "\n";
    }
  }
}

static void dump_log_to_stdout(const std::string &log_path) {
  std::ifstream in(log_path);
  if (!in) {
    std::cout << "\n[Unable to open log file for dump: "
              << basename_only(log_path) << "]\n";
    return;
  }

  std::cout << "\n";
  std::string line;
  while (std::getline(in, line)) {
    std::cout << line << "\n";
  }
}

int run(int argc, char **argv) {
  bool dump_log = false;
  std::string src_path;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--dump-log") {
      dump_log = true;
      continue;
    }
    if (!src_path.empty()) {
      std::cerr << "Usage: ./assembler [--dump-log] input.hal\n";
      return 2;
    }
    src_path = arg;
  }

  if (src_path.empty()) {
    std::cerr << "Usage: ./assembler [--dump-log] input.hal\n";
    return 2;
  }

  if (src_path.size() < 4 ||
      src_path.substr(src_path.size() - 4) != ".hal") {
    std::cerr << "error: input must be a .hal file\n";
    return 2;
  }

  std::ifstream in(src_path);
  if (!in) {
    std::cerr << "error: cannot open input file: " << src_path << "\n";
    return 2;
  }

  std::vector<std::string> lines;
  std::string line;
  while (std::getline(in, line)) {
    lines.push_back(line);
  }

  const auto hll_path_opt = replace_suffix(src_path, ".hll");
  const auto hlx_path_opt = replace_suffix(src_path, ".hlx");
  const auto log_path_opt = replace_suffix(src_path, ".log");
  if (!hll_path_opt.has_value() || !hlx_path_opt.has_value() ||
      !log_path_opt.has_value()) {
    std::cerr << "error: cannot derive output file names\n";
    return 2;
  }

  const std::string hll_path = *hll_path_opt;
  const std::string hlx_path = *hlx_path_opt;
  const std::string log_path = *log_path_opt;

  const std::string src_name = basename_only(src_path);
  const std::string hll_name = basename_only(hll_path);
  const std::string hlx_name = basename_only(hlx_path);
  const std::string log_name = basename_only(log_path);

  Config cfg;

  std::cout << "Source : " << src_name << "\n\n";
  std::cout << "Pass 1: Building symbol table and assigning addresses...\n";
  Pass1Result p1 = pass1(lines, cfg);

  if (has_any_errors(p1.ir)) {
    write_hll(hll_path, src_name, hll_name, hlx_name, p1, cfg);
    write_log(log_path, p1);

    std::cout << "\nAssembly failed.\n";
    std::cout << "Listing: " << hll_name << "\n";
    std::cout << "Log    : " << log_name << "\n";

    if (dump_log) {
      dump_log_to_stdout(log_path);
    }
    return 1;
  }

  std::cout << "Pass 2: Generating machine code...\n";
  const auto p2 = pass2(p1, cfg);

  write_hll(hll_path, src_name, hll_name, hlx_name, p1, cfg);
  write_log(log_path, p1);

  if (!p2.has_value()) {
    std::cout << "\nAssembly failed.\n";
    std::cout << "Listing: " << hll_name << "\n";
    std::cout << "Log    : " << log_name << "\n";

    if (dump_log) {
      dump_log_to_stdout(log_path);
    }
    return 1;
  }

  write_hlx(hlx_path, *p2, p1.imem_count, *p1.alloc_size);

  std::cout << "\nAssembly successful.\n";
  std::cout << "Output : " << hlx_name << "\n";
  std::cout << "Listing: " << hll_name << "\n";
  std::cout << "Log    : " << log_name << "\n";

  if (dump_log) {
    dump_log_to_stdout(log_path);
  }

  return 0;
}

}  // namespace hasm

#ifndef HASM_UNIT_TEST
int main(int argc, char **argv) {
  return hasm::run(argc, argv);
}
#endif
