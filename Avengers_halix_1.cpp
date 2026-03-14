#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <limits>

namespace hasm {

// -----------------------------
// Config
// -----------------------------
struct Config {
  std::string version = "hasm-cpp 0.1";

  // Default values
  int default_uninitialized = 9999;

  // Ranges (tuned for 4-decimal-digit words and 2-digit operand field)
  int data_min = -9999;
  int data_max = 9999;

  int operand_min = 0;
  int operand_max = 99;  // 2-digit address/operand

  int max_dmem_size = 100;  // addresses 0..99
  int max_imem_size = 100;  // addresses 0..99

  bool case_sensitive = false;
};

// -----------------------------
// String helpers
// -----------------------------
static inline std::string ltrim(std::string s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                 [](unsigned char ch) { return !std::isspace(ch); }));
  return s;
}

static inline std::string rtrim(std::string s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); }).base(),
          s.end());
  return s;
}

static inline std::string trim(std::string s) { return rtrim(ltrim(std::move(s))); }

static inline std::string to_upper(std::string s) {
  for (char &c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

static inline bool iequals(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); i++) {
    if (std::toupper(static_cast<unsigned char>(a[i])) !=
        std::toupper(static_cast<unsigned char>(b[i]))) return false;
  }
  return true;
}

static inline bool is_ident(const std::string &s) {
  if (s.empty()) return false;
  auto is_alpha_ = [](char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    return std::isalpha(uc) || c == '_';
  };
  auto is_alnum_ = [](char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) || c == '_';
  };
  if (!is_alpha_(s[0])) return false;
  for (size_t i = 1; i < s.size(); i++) {
    if (!is_alnum_(s[i])) return false;
  }
  return true;
}

static inline std::vector<std::string> split_ws(const std::string &s) {
  std::istringstream iss(s);
  std::vector<std::string> toks;
  std::string tok;
  while (iss >> tok) toks.push_back(tok);
  return toks;
}

static inline std::pair<std::string, std::string> split_comment(const std::string &raw) {
  auto pos = raw.find('#');
  if (pos == std::string::npos) return {raw, ""};
  return {raw.substr(0, pos), raw.substr(pos)};
}

// Parse int with full-consumption check.
static inline std::optional<int> parse_int_strict(const std::string &s) {
  if (s.empty()) return std::nullopt;
  char *end = nullptr;
  long v = std::strtol(s.c_str(), &end, 10);
  if (end == nullptr) return std::nullopt;
  if (*end != '\0') return std::nullopt;
  if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max())
    return std::nullopt;
  return static_cast<int>(v);
}

// -----------------------------
// Diagnostics
// -----------------------------
enum class Severity { Note, Warning, Error };

struct Diagnostic {
  Severity sev;
  std::string code;
  std::string msg;
};

// -----------------------------
// IR
// -----------------------------
enum class LineKind {
  BlankOrComment,
  DirectiveAlloc,
  DirectiveBegin,
  DirectiveEnd,
  DataDecl,
  Instruction,
  Invalid
};

enum class OperandKind { None, Symbol, Immediate };

enum class SymKind { Data, Label };

struct SymEntry {
  std::string display_name;  // original spelling at definition
  SymKind kind;
  int address;               // DMem addr for Data, IMem addr for Label
  int defined_line_no;
};

struct LineIR {
  int line_no = 0;
  std::string raw_text;
  std::string code_part;
  std::string comment_part;
  LineKind kind = LineKind::Invalid;

  // .ALLOC
  std::optional<int> alloc_n;

  // .DATA
  std::optional<std::string> data_name;
  std::optional<int> data_init;

  // instruction
  std::optional<std::string> label_def;
  std::optional<std::string> mnemonic;

  OperandKind operand_kind = OperandKind::None;
  std::optional<std::string> operand_sym;
  std::optional<int> operand_imm;

  // assigned in pass1
  std::optional<int> dmem_addr;
  std::optional<int> imem_addr;

  // assigned in pass2
  std::optional<int> machine_word;

  std::vector<Diagnostic> diags;

  void add(Severity sev, std::string code, std::string msg) {
    diags.push_back(Diagnostic{sev, std::move(code), std::move(msg)});
  }
  void err(std::string code, std::string msg) { add(Severity::Error, std::move(code), std::move(msg)); }
};

// Canonicalize symbol key for symtab.
static inline std::string canon(const std::string &name, const Config &cfg) {
  return cfg.case_sensitive ? name : to_upper(name);
}

// -----------------------------
// Opcode table
// -----------------------------
enum class OperandMode { None, DataAddr, InstAddr, Immediate };

struct OpInfo {
  int opcode;               // 0..99
  OperandMode mode;
};

static inline std::unordered_map<std::string, OpInfo> build_optab() {
  // Keyed by uppercase mnemonic
  std::unordered_map<std::string, OpInfo> t;

  auto add = [&](const std::string &mnem, int op, OperandMode mode) {
    t.emplace(to_upper(mnem), OpInfo{op, mode});
  };

  // 01..23
  add("READ",   1, OperandMode::DataAddr);
  add("WRITE",  2, OperandMode::DataAddr);
  add("LOAD",   3, OperandMode::DataAddr);
  add("STORE",  4, OperandMode::DataAddr);
  add("ADD",    5, OperandMode::DataAddr);
  add("SUB",    6, OperandMode::DataAddr);
  add("MULT",   7, OperandMode::DataAddr);
  add("DIV",    8, OperandMode::DataAddr);
  add("MOD",    9, OperandMode::DataAddr);
  add("BRANCH",10, OperandMode::InstAddr);
  add("BRT",   11, OperandMode::InstAddr);
  add("BRF",   12, OperandMode::InstAddr);
  add("CLEAR", 13, OperandMode::None);
  add("SET",   14, OperandMode::None);
  add("DOUBLE",15, OperandMode::DataAddr);
  add("INCR",  16, OperandMode::None);
  add("DECR",  17, OperandMode::None);
  add("CLT",   18, OperandMode::DataAddr);
  add("CLE",   19, OperandMode::DataAddr);
  add("CEQ",   20, OperandMode::DataAddr);
  add("CNE",   21, OperandMode::DataAddr);
  add("CGE",   22, OperandMode::DataAddr);
  add("CGT",   23, OperandMode::DataAddr);

  // 24..33 immediate and subroutine
  add("SETI",  24, OperandMode::Immediate);
  add("ADDI",  25, OperandMode::Immediate);
  add("SUBI",  26, OperandMode::Immediate);
  add("MULTI", 27, OperandMode::Immediate);
  add("DIVI",  28, OperandMode::Immediate);
  add("MODI",  29, OperandMode::Immediate);
  add("POW",   30, OperandMode::DataAddr);
  add("SHACC", 31, OperandMode::None);
  add("BSUB",  32, OperandMode::InstAddr);
  add("RET",   33, OperandMode::None);

  // 34..54 base-index instruction family
  add("SHINDX",34, OperandMode::None);
  add("LOADA", 35, OperandMode::DataAddr);
  add("ICLR",  36, OperandMode::None);
  add("IREAD", 37, OperandMode::None);
  add("IWRITE",38, OperandMode::None);
  add("ILOAD", 39, OperandMode::None);
  add("ISTORE",40, OperandMode::None);
  add("IINCR", 41, OperandMode::None);
  add("IDECR", 42, OperandMode::None);
  add("IADD",  43, OperandMode::None);
  add("ISUB",  44, OperandMode::None);
  add("IMULT", 45, OperandMode::None);
  add("IDIV",  46, OperandMode::None);
  add("IMOD",  47, OperandMode::None);
  add("ICLT",  48, OperandMode::None);
  add("ICLE",  49, OperandMode::None);
  add("ICEQ",  50, OperandMode::None);
  add("ICNE",  51, OperandMode::None);
  add("ICGE",  52, OperandMode::None);
  add("ICGT",  53, OperandMode::None);
  add("SHBASE",54, OperandMode::None);

  // 99
  add("HALT",  99, OperandMode::None);

  return t;
}

// -----------------------------
// Parsing into LineIR
// -----------------------------
static LineIR parse_line(int line_no, const std::string &raw, const Config &cfg) {
  LineIR ir;
  ir.line_no = line_no;
  ir.raw_text = raw;

  auto [code_part, comment_part] = split_comment(raw);
  ir.code_part = code_part;
  ir.comment_part = comment_part;

  std::string code = trim(code_part);
  if (code.empty()) {
    ir.kind = LineKind::BlankOrComment;
    return ir;
  }

  // Tokenize for directive/data quick checks
  auto toks = split_ws(code);
  if (!toks.empty() && toks[0].size() > 0) {
    // .BEGIN / .END
    if (toks.size() == 1 && iequals(toks[0], ".BEGIN")) {
      ir.kind = LineKind::DirectiveBegin;
      return ir;
    }
    if (toks.size() == 1 && iequals(toks[0], ".END")) {
      ir.kind = LineKind::DirectiveEnd;
      return ir;
    }

    // .ALLOC n
    if (iequals(toks[0], ".ALLOC")) {
      ir.kind = LineKind::DirectiveAlloc;
      if (toks.size() != 2) {
        ir.err("E_ALLOC_FMT", "Invalid .ALLOC syntax (expected: .ALLOC n).");
        return ir;
      }
      auto v = parse_int_strict(toks[1]);
      if (!v.has_value()) {
        ir.err("E_ALLOC_INT", "Invalid .ALLOC value (expected integer).");
        return ir;
      }
      if (*v < 0 || *v > cfg.max_dmem_size) {
        ir.err("E_ALLOC_RANGE", "Invalid .ALLOC value (out of supported range).");
        return ir;
      }
      ir.alloc_n = *v;
      return ir;
    }

    // name .DATA [=k]
    if (toks.size() >= 2 && is_ident(toks[0]) && iequals(toks[1], ".DATA")) {
      ir.kind = LineKind::DataDecl;
      ir.data_name = toks[0];

      if (toks.size() == 2) {
        // uninitialized; default applied in Pass 1
        return ir;
      }

      // initializer can be "=7" or "= 7"
      if (toks.size() == 3) {
        std::string t = toks[2];
        if (t.size() >= 2 && t[0] == '=') {
          auto v = parse_int_strict(t.substr(1));
          if (!v.has_value()) {
            ir.err("E_DATA_INT", "Invalid .DATA initializer (expected =number).");
            return ir;
          }
          if (*v < cfg.data_min || *v > cfg.data_max) {
            ir.err("E_DATA_RANGE", "Invalid .DATA initializer (out of range for 4-digit word).");
            return ir;
          }
          ir.data_init = *v;
          return ir;
        }
        ir.err("E_DATA_FMT", "Invalid .DATA initializer (expected '=number').");
        return ir;
      }

      if (toks.size() == 4 && toks[2] == "=") {
        auto v = parse_int_strict(toks[3]);
        if (!v.has_value()) {
          ir.err("E_DATA_INT", "Invalid .DATA initializer (expected integer after '=').");
          return ir;
        }
        if (*v < cfg.data_min || *v > cfg.data_max) {
          ir.err("E_DATA_RANGE", "Invalid .DATA initializer (out of range for 4-digit word).");
          return ir;
        }
        ir.data_init = *v;
        return ir;
      }

      ir.err("E_DATA_FMT", "Invalid .DATA syntax (expected: name .DATA or name .DATA =k).");
      return ir;
    }
  }

  // Otherwise: instruction (optional label)
  ir.kind = LineKind::Instruction;

  std::string s = ltrim(code_part); // preserve internal spacing somewhat
  s = trim(s);

  // Detect label at start: IDENT :
  // We'll accept "Loop:" or "Loop :"
  std::optional<std::string> label;
  {
    // Find colon; only treat as label if it's before any whitespace after ident
    auto colon_pos = s.find(':');
    if (colon_pos != std::string::npos) {
      std::string left = trim(s.substr(0, colon_pos));
      std::string right = trim(s.substr(colon_pos + 1));
      if (is_ident(left)) {
        label = left;
        s = right;
        if (s.empty()) {
          ir.err("E_LABEL_ONLY", "Label must be followed by an instruction.");
          ir.kind = LineKind::Invalid;
          return ir;
        }
      }
    }
  }
  if (label.has_value()) ir.label_def = *label;

  s = trim(s);
  if (s.empty()) {
    ir.err("E_INSTR_EMPTY", "Missing mnemonic.");
    ir.kind = LineKind::Invalid;
    return ir;
  }

  // mnemonic is first token
  std::string mnemonic;
  std::string rest;
  {
    std::istringstream iss(s);
    iss >> mnemonic;
    std::getline(iss, rest);
    rest = trim(rest);
  }

  if (!is_ident(mnemonic)) {
    ir.err("E_MNEM_FMT", "Invalid mnemonic format.");
    ir.kind = LineKind::Invalid;
    return ir;
  }

  ir.mnemonic = mnemonic;

  if (rest.empty()) {
    ir.operand_kind = OperandKind::None;
    return ir;
  }

  // Operand parsing:
  // - Immediate: "=number" or "= number"
  // - Symbol: IDENT
  if (!rest.empty() && rest[0] == '=') {
    std::string rhs = trim(rest.substr(1));
    if (rhs.empty()) {
      ir.err("E_IMM_FMT", "Invalid immediate (expected =number).");
      return ir;
    }
    auto v = parse_int_strict(rhs);
    if (!v.has_value()) {
      ir.err("E_IMM_INT", "Invalid immediate (expected integer after '=').");
      return ir;
    }
    // For immediate-operand opcodes, we restrict to operand field range (0..99 by default)
    if (*v < cfg.operand_min || *v > cfg.operand_max) {
      ir.err("E_IMM_RANGE", "Immediate out of range for 2-digit operand field.");
      return ir;
    }
    ir.operand_kind = OperandKind::Immediate;
    ir.operand_imm = *v;
    return ir;
  }

  // Symbol operand must be exactly one identifier (no extra tokens)
  auto rest_toks = split_ws(rest);
  if (rest_toks.size() == 1 && is_ident(rest_toks[0])) {
    ir.operand_kind = OperandKind::Symbol;
    ir.operand_sym = rest_toks[0];
    return ir;
  }

  ir.err("E_OPERAND_FMT", "Invalid operand format (expected SYMBOL or =number).");
  return ir;
}

// -----------------------------
// Pass 1
// -----------------------------
enum class AsmState { PreBegin, InCode, PostEnd };

struct Pass1Result {
  std::vector<LineIR> ir;
  std::unordered_map<std::string, SymEntry> symtab;
  std::optional<int> dmem_size;
  int dmem_used = 0;
  int imem_count = 0;
};

static bool has_any_errors(const std::vector<LineIR> &ir) {
  for (const auto &line : ir) {
    for (const auto &d : line.diags) if (d.sev == Severity::Error) return true;
  }
  return false;
}

static void attach_global_error(std::vector<LineIR> &ir, int attach_idx,
                                std::string code, std::string msg) {
  if (ir.empty()) return;
  attach_idx = std::max(0, std::min<int>(attach_idx, static_cast<int>(ir.size()) - 1));
  ir[attach_idx].err(std::move(code), std::move(msg));
}

static Pass1Result pass1(const std::vector<std::string> &lines, const Config &cfg) {
  Pass1Result res;
  res.ir.reserve(lines.size());

  AsmState state = AsmState::PreBegin;
  int dmem_lc = 0;
  int imem_lc = 0;

  bool seen_alloc = false;
  bool seen_begin = false;
  bool seen_end = false;

  int alloc_idx = -1;

  for (size_t i = 0; i < lines.size(); i++) {
    LineIR line = parse_line(static_cast<int>(i) + 1, lines[i], cfg);
    res.ir.push_back(line);
    LineIR &lir = res.ir.back();

    if (lir.kind == LineKind::BlankOrComment) continue;

    // After .END, only allow blank/comment
    if (state == AsmState::PostEnd) {
      lir.err("E_AFTER_END", "Statement after .END is not allowed.");
      continue;
    }

    if (lir.kind == LineKind::DirectiveAlloc) {
      if (state != AsmState::PreBegin) lir.err("E_ALLOC_POS", ".ALLOC must appear before .BEGIN.");
      if (seen_alloc) lir.err("E_ALLOC_DUP", "Duplicate .ALLOC.");
      if (!lir.alloc_n.has_value()) continue;

      if (!seen_alloc) {
        seen_alloc = true;
        res.dmem_size = *lir.alloc_n;
        alloc_idx = static_cast<int>(i);
      }
      continue;
    }

    if (lir.kind == LineKind::DataDecl) {
      if (state != AsmState::PreBegin) {
        lir.err("E_DATA_POS", ".DATA is not allowed after .BEGIN.");
        continue;
      }
      if (!lir.data_name.has_value()) {
        lir.err("E_DATA_NAME", ".DATA missing variable name.");
        continue;
      }

      std::string key = canon(*lir.data_name, cfg);
      if (res.symtab.find(key) != res.symtab.end()) {
        lir.err("E_SYM_DUP", "Duplicate symbol: " + *lir.data_name);
        continue;
      }

      int addr = dmem_lc++;
      int init = lir.data_init.value_or(cfg.default_uninitialized);

      lir.dmem_addr = addr;
      lir.data_init = init;

      res.symtab.emplace(key, SymEntry{*lir.data_name, SymKind::Data, addr, lir.line_no});
      continue;
    }

    if (lir.kind == LineKind::DirectiveBegin) {
      if (seen_begin) {
        lir.err("E_BEGIN_DUP", "Duplicate .BEGIN.");
        continue;
      }
      if (state != AsmState::PreBegin) {
        lir.err("E_BEGIN_POS", ".BEGIN is misplaced.");
        continue;
      }

      seen_begin = true;
      state = AsmState::InCode;
      imem_lc = 0;
      continue;
    }

    if (lir.kind == LineKind::DirectiveEnd) {
      if (seen_end) {
        lir.err("E_END_DUP", "Duplicate .END.");
        continue;
      }
      if (state != AsmState::InCode) {
        lir.err("E_END_POS", ".END without matching .BEGIN.");
        continue; // do not transition
      }

      seen_end = true;
      state = AsmState::PostEnd;
      continue;
    }

    if (lir.kind == LineKind::Instruction) {
      if (state != AsmState::InCode) {
        lir.err("E_INSTR_POS", "Instruction outside .BEGIN/.END.");
        continue;
      }

      // Define label if present
      if (lir.label_def.has_value()) {
        std::string key = canon(*lir.label_def, cfg);
        if (res.symtab.find(key) != res.symtab.end()) {
          lir.err("E_SYM_DUP", "Duplicate symbol: " + *lir.label_def);
        } else {
          res.symtab.emplace(key, SymEntry{*lir.label_def, SymKind::Label, imem_lc, lir.line_no});
        }
      }

      lir.imem_addr = imem_lc++;
      continue;
    }

    // Invalid line stays invalid (already has diag); continue
  }

  // Final validations
  if (!seen_alloc) {
    attach_global_error(res.ir, 0, "E_MISSING_ALLOC", "Missing .ALLOC directive.");
  }
  if (!seen_begin) {
    // attach to first non-blank if possible
    int idx = 0;
    for (size_t i = 0; i < res.ir.size(); i++) {
      if (res.ir[i].kind != LineKind::BlankOrComment) { idx = static_cast<int>(i); break; }
    }
    attach_global_error(res.ir, idx, "E_MISSING_BEGIN", "Missing .BEGIN directive.");
  }
  if (seen_begin && !seen_end) {
    attach_global_error(res.ir, static_cast<int>(res.ir.size()) - 1,
                        "E_MISSING_END", "Missing .END directive.");
  }

  res.dmem_used = dmem_lc;
  res.imem_count = imem_lc;

  if (res.dmem_size.has_value() && *res.dmem_size < res.dmem_used) {
    int attach = (alloc_idx >= 0) ? alloc_idx : static_cast<int>(res.ir.size()) - 1;
    attach_global_error(res.ir, attach, "E_DMEM_OVERFLOW",
                        "More .DATA declarations than .ALLOC size.");
  }

  if (res.dmem_size.has_value() && *res.dmem_size > cfg.max_dmem_size) {
    int attach = (alloc_idx >= 0) ? alloc_idx : 0;
    attach_global_error(res.ir, attach, "E_ALLOC_RANGE",
                        "DMem size exceeds supported maximum for 2-digit address field.");
  }

  if (res.imem_count > cfg.max_imem_size) {
    attach_global_error(res.ir, static_cast<int>(res.ir.size()) - 1,
                        "E_IMEM_OVERFLOW",
                        "Instruction count exceeds supported maximum for 2-digit address field.");
  }

  return res;
}

// -----------------------------
// Pass 2
// -----------------------------
struct Pass2Result {
  std::vector<int> imem_words; // size = instruction_count
  std::vector<int> dmem_init;  // size = dmem_size
};

static std::string fmt_word4_unsigned(int v) {
  std::ostringstream oss;
  oss << std::setw(4) << std::setfill('0') << v;
  return oss.str();
}

static std::string fmt_word4_signed(int v) {
  // prints -0007 style for negative values
  if (v >= 0) return fmt_word4_unsigned(v);
  int av = std::abs(v);
  std::ostringstream oss;
  oss << "-" << std::setw(4) << std::setfill('0') << av;
  return oss.str();
}

static std::optional<Pass2Result> pass2(Pass1Result &p1, const Config &cfg) {
  auto optab = build_optab();

  if (!p1.dmem_size.has_value()) return std::nullopt;
  int dmem_size = *p1.dmem_size;

  Pass2Result out;
  out.imem_words.assign(p1.imem_count, 0);
  out.dmem_init.assign(dmem_size, cfg.default_uninitialized);

  // Fill DMem initialization from .DATA lines
  for (auto &line : p1.ir) {
    if (line.kind == LineKind::DataDecl && line.dmem_addr.has_value()) {
      int addr = *line.dmem_addr;
      int val = line.data_init.value_or(cfg.default_uninitialized);
      if (addr >= 0 && addr < dmem_size) out.dmem_init[addr] = val;
    }
  }

  // Assemble instructions
  for (auto &line : p1.ir) {
    if (line.kind != LineKind::Instruction || !line.imem_addr.has_value()) continue;
    int addr = *line.imem_addr;

    if (!line.mnemonic.has_value()) {
      line.err("E_MNEM_MISSING", "Missing mnemonic.");
      continue;
    }

    std::string mkey = to_upper(*line.mnemonic);
    auto it = optab.find(mkey);
    if (it == optab.end()) {
      line.err("E_BAD_OPCODE", "Invalid opcode/mnemonic: " + *line.mnemonic);
      continue;
    }

    OpInfo op = it->second;
    int operand = 0;

    auto require_none = [&]() {
      if (line.operand_kind != OperandKind::None) {
        line.err("E_OPERAND_UNEXPECTED", "Unexpected operand.");
        return false;
      }
      operand = 0;
      return true;
    };

    auto require_immediate = [&]() {
      if (line.operand_kind != OperandKind::Immediate || !line.operand_imm.has_value()) {
        line.err("E_OPERAND_IMM", "Immediate operand required (use =number).");
        return false;
      }
      operand = *line.operand_imm;
      if (operand < cfg.operand_min || operand > cfg.operand_max) {
        line.err("E_OPERAND_RANGE", "Immediate out of range for 2-digit operand field.");
        return false;
      }
      return true;
    };

    auto require_symbol = [&](SymKind expectedKind, const std::string &kindName) {
      if (line.operand_kind != OperandKind::Symbol || !line.operand_sym.has_value()) {
        line.err("E_OPERAND_SYM", "Symbol operand required (" + kindName + ").");
        return false;
      }
      std::string skey = canon(*line.operand_sym, cfg);
      auto sit = p1.symtab.find(skey);
      if (sit == p1.symtab.end()) {
        line.err("E_UNDEF_SYM", "Undefined symbol: " + *line.operand_sym);
        return false;
      }
      if (sit->second.kind != expectedKind) {
        line.err("E_SYM_KIND", "Symbol kind mismatch for operand: " + *line.operand_sym);
        return false;
      }
      operand = sit->second.address;
      if (operand < cfg.operand_min || operand > cfg.operand_max) {
        line.err("E_OPERAND_RANGE", "Address out of range for 2-digit operand field.");
        return false;
      }
      return true;
    };

    bool ok = true;
    switch (op.mode) {
      case OperandMode::None:      ok = require_none(); break;
      case OperandMode::Immediate: ok = require_immediate(); break;
      case OperandMode::DataAddr:  ok = require_symbol(SymKind::Data, "data symbol"); break;
      case OperandMode::InstAddr:  ok = require_symbol(SymKind::Label, "label"); break;
    }
    if (!ok) continue;

    int word = op.opcode * 100 + operand;
    if (word < 0 || word > 9999) {
      line.err("E_WORD_RANGE", "Encoded word out of range (0..9999).");
      continue;
    }

    line.machine_word = word;
    if (addr >= 0 && addr < static_cast<int>(out.imem_words.size())) {
      out.imem_words[addr] = word;
    }
  }

  if (has_any_errors(p1.ir)) return std::nullopt;
  return out;
}

// -----------------------------
// Emit .hll and .hlx
// -----------------------------
static void write_hll(const std::string &hll_path,
                      const std::string &src_name,
                      const std::string &hll_name,
                      const std::string &hlx_name,
                      const Pass1Result &p1,
                      const Config &cfg) {
  std::ofstream out(hll_path);
  if (!out) {
    std::cerr << "error: cannot write listing file: " << hll_path << "\n";
    return;
  }

  out << "Source:  " << src_name << "\n";
  out << "Listing: " << hll_name << "\n";
  out << "Machine: " << hlx_name << "\n";
  out << "Version: " << cfg.version << "\n\n";
  out << "Addr  Word  Source\n";

  for (const auto &line : p1.ir) {
    std::string addr_field = "  ";
    std::string word_field = "    ";

    if (line.kind == LineKind::DataDecl && line.dmem_addr.has_value()) {
      std::ostringstream a; a << std::setw(2) << std::setfill('0') << *line.dmem_addr;
      addr_field = a.str();
      int v = line.data_init.value_or(cfg.default_uninitialized);
      word_field = fmt_word4_signed(v);
    } else if (line.kind == LineKind::Instruction && line.imem_addr.has_value()) {
      std::ostringstream a; a << std::setw(2) << std::setfill('0') << *line.imem_addr;
      addr_field = a.str();
      if (line.machine_word.has_value()) word_field = fmt_word4_unsigned(*line.machine_word);
      else word_field = "????";
    } else {
      addr_field = "  ";
      word_field = "    ";
    }

    out << addr_field << "   " << word_field << "  " << line.raw_text << "\n";

    for (const auto &d : line.diags) {
      const char *sev =
          (d.sev == Severity::Error) ? "ERROR" :
          (d.sev == Severity::Warning) ? "WARN" : "NOTE";
      out << "           >>> " << sev << " " << d.code << ": " << d.msg << "\n";
    }
  }
}

static void write_hlx(const std::string &hlx_path,
                      const Pass2Result &p2,
                      int instruction_count,
                      int dmem_size) {
  std::ofstream out(hlx_path);
  if (!out) {
    std::cerr << "error: cannot write machine file: " << hlx_path << "\n";
    return;
  }

  out << instruction_count << "\n";
  for (int w : p2.imem_words) out << fmt_word4_unsigned(w) << "\n";
  out << dmem_size << "\n";
  for (int v : p2.dmem_init) out << fmt_word4_signed(v) << "\n";
}

// -----------------------------
// Driver
// -----------------------------
static std::optional<std::string> replace_suffix(const std::string &path, const std::string &new_ext) {
  auto pos = path.find_last_of('.');
  if (pos == std::string::npos) return std::nullopt;
  return path.substr(0, pos) + new_ext;
}

static std::string basename_only(const std::string &path) {
  // Works on POSIX paths in Codio; also OK-ish for simple Windows-style.
  auto slash = path.find_last_of("/\\");
  if (slash == std::string::npos) return path;
  return path.substr(slash + 1);
}

int run(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: ./hasm input.hal\n";
    return 2;
  }

  Config cfg;

  std::string src_path = argv[1];
  if (src_path.size() < 4 || src_path.substr(src_path.size() - 4) != ".hal") {
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
  while (std::getline(in, line)) lines.push_back(line);

  Pass1Result p1 = pass1(lines, cfg);

  std::string src_name = basename_only(src_path);

  auto hll_path_opt = replace_suffix(src_path, ".hll");
  auto hlx_path_opt = replace_suffix(src_path, ".hlx");
  if (!hll_path_opt.has_value() || !hlx_path_opt.has_value()) {
    std::cerr << "error: cannot derive output file names\n";
    return 2;
  }

  std::string hll_path = *hll_path_opt;
  std::string hlx_path = *hlx_path_opt;

  std::string hll_name = basename_only(hll_path);
  std::string hlx_name = basename_only(hlx_path);

  // Pass 2 (only succeeds if no diagnostics with Severity::Error)
  auto p2 = pass2(p1, cfg);

  // Always write listing (includes diagnostics and/or ???? words where unresolved)
  write_hll(hll_path, src_name, hll_name, hlx_name, p1, cfg);

  if (!p2.has_value()) {
    std::cerr << "Assembly failed; see listing: " << hll_path << "\n";
    return 1;
  }

  int instruction_count = p1.imem_count;
  int dmem_size = *p1.dmem_size;

  write_hlx(hlx_path, *p2, instruction_count, dmem_size);
  std::cout << "OK: wrote " << hll_path << " and " << hlx_path << "\n";
  return 0;
}

} // namespace hasm

int main(int argc, char **argv) {
  return hasm::run(argc, argv);
}
