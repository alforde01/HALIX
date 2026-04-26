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
  std::string version = "hasm-cpp 0.3";
  int default_uninitialized = 9999;
  int data_min = -9999;
  int data_max = 9999;
  int operand_min = 0;
  int operand_max = 99;
  int max_dmem_size = 200;   // .ALLOC range = 0..200
  int max_imem_size = 100;
  bool case_sensitive = true;
};

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
    unsigned char uc = static_cast<unsigned char>(c);
    return std::isalpha(uc) || c == '_';
  };

  auto is_alnum_ = [](char c) {
    unsigned char uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) || c == '_';
  };

  if (!is_alpha_(s[0])) return false;
  for (size_t i = 1; i < s.size(); ++i) {
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

static inline std::optional<int> parse_int_strict(const std::string &s) {
  if (s.empty()) return std::nullopt;

  char *end = nullptr;
  long v = std::strtol(s.c_str(), &end, 10);

  if (end == nullptr || *end != '\0') return std::nullopt;
  if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) {
    return std::nullopt;
  }

  return static_cast<int>(v);
}

static inline std::string basename_only(const std::string &path) {
  auto slash = path.find_last_of("/\\");
  if (slash == std::string::npos) return path;
  return path.substr(slash + 1);
}

static inline std::optional<std::string> replace_suffix(const std::string &path,
                                                        const std::string &new_ext) {
  auto pos = path.find_last_of('.');
  if (pos == std::string::npos) return std::nullopt;
  return path.substr(0, pos) + new_ext;
}

enum class Severity { Note, Warning, Error };

struct Diagnostic {
  Severity sev;
  std::string code;
  std::string msg;
};

enum class LineKind {
  BlankOrComment,
  DirectiveAlloc,
  DirectiveBegin,
  DirectiveEnd,
  DataDecl,
  DirectiveBlock,
  Instruction,
  Invalid
};

enum class OperandKind { None, Symbol, Immediate };
enum class SymKind { Data, Label };
enum class BlockMode { None, Reserve, InitializedList };
enum class AsmState { PreBegin, InCode, PostEnd };

struct SymEntry {
  std::string display_name;
  SymKind kind;
  int address;
  int defined_line_no;
};

struct LineIR {
  int line_no = 0;
  std::string raw_text;
  std::string code_part;
  std::string comment_part;
  LineKind kind = LineKind::Invalid;

  std::optional<int> alloc_n;

  std::optional<std::string> data_name;
  std::optional<int> data_init;

  std::optional<std::string> block_name;
  BlockMode block_mode = BlockMode::None;
  std::optional<int> block_reserve_count;
  std::vector<int> block_values;

  std::optional<std::string> label_def;
  std::optional<std::string> mnemonic;
  OperandKind operand_kind = OperandKind::None;
  std::optional<std::string> operand_sym;
  std::optional<int> operand_imm;

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
    if (block_mode == BlockMode::Reserve && block_reserve_count.has_value()) {
      return *block_reserve_count;
    }
    if (block_mode == BlockMode::InitializedList) {
      return static_cast<int>(block_values.size());
    }
    return 0;
  }
};

static inline std::string canon(const std::string &name, const Config &cfg) {
  return cfg.case_sensitive ? name : to_upper(name);
}

enum class OperandMode { None, DataAddr, InstAddr, Immediate };

struct OpInfo {
  int opcode;
  OperandMode mode;
};

static inline std::unordered_map<std::string, OpInfo> build_optab() {
  std::unordered_map<std::string, OpInfo> t;
  auto add = [&](const std::string &mnem, int op, OperandMode mode) {
    t.emplace(mnem, OpInfo{op, mode});
  };

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
  add("HALT",  99, OperandMode::None);
  return t;
}

static inline const std::vector<std::string> &known_directives() {
  static const std::vector<std::string> dirs = {
      ".ALLOC", ".BEGIN", ".END", ".DATA", ".BLOCK"};
  return dirs;
}

static std::optional<std::string> directive_suggestion(const std::string &token) {
  for (const auto &dir : known_directives()) {
    if (iequals(token, dir)) return dir;
  }
  return std::nullopt;
}

struct ParseBlockResult {
  BlockMode mode = BlockMode::None;
  std::optional<int> reserve_count;
  std::vector<int> values;
  std::string error_message;
};

static ParseBlockResult parse_block_payload(const std::vector<std::string> &toks,
                                            size_t start_idx,
                                            const Config &cfg) {
  ParseBlockResult out;

  if (start_idx >= toks.size()) {
    out.error_message =
        "Invalid .BLOCK syntax. Expected: name .BLOCK n or name .BLOCK =3, =7, =17";
    return out;
  }

  std::string joined;
  for (size_t i = start_idx; i < toks.size(); ++i) joined += toks[i];
  joined = trim(joined);

  if (joined.empty()) {
    out.error_message =
        "Invalid .BLOCK syntax. Expected: name .BLOCK n or name .BLOCK =3, =7, =17";
    return out;
  }

  if (joined[0] == '=') {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : joined) {
      if (c == ',') {
        parts.push_back(trim(cur));
        cur.clear();
      } else {
        cur.push_back(c);
      }
    }
    parts.push_back(trim(cur));

    if (parts.empty()) {
      out.error_message = "Invalid .BLOCK initialized list.";
      return out;
    }

    for (const auto &part : parts) {
      if (part.size() < 2 || part[0] != '=') {
        out.error_message =
            "Invalid .BLOCK initialized list. Use items like =3, =7, =17";
        return out;
      }

      auto v = parse_int_strict(trim(part.substr(1)));
      if (!v.has_value()) {
        out.error_message = ".BLOCK initialized values must be integers: " + part;
        return out;
      }

      if (*v < cfg.data_min || *v > cfg.data_max) {
        out.error_message =
            ".BLOCK initialized value out of range (" +
            std::to_string(cfg.data_min) + ".." +
            std::to_string(cfg.data_max) + "): " + part;
        return out;
      }

      out.values.push_back(*v);
    }

    if (out.values.empty()) {
      out.error_message = "Initialized .BLOCK must contain at least one value.";
      return out;
    }

    out.mode = BlockMode::InitializedList;
    return out;
  }

  auto n = parse_int_strict(joined);
  if (!n.has_value()) {
    out.error_message = ".BLOCK size must be an integer.";
    return out;
  }
  if (*n <= 0) {
    out.error_message = ".BLOCK size must be a positive integer.";
    return out;
  }
  if (*n > cfg.max_dmem_size) {
    out.error_message =
        ".BLOCK size exceeds supported memory size (1.." +
        std::to_string(cfg.max_dmem_size) + ").";
    return out;
  }

  out.mode = BlockMode::Reserve;
  out.reserve_count = *n;
  return out;
}

static void validate_comment_format(LineIR &ir) {
  if (ir.comment_part.empty()) return;
  if (ir.comment_part.size() == 1) return;  // just '#'
  unsigned char ch = static_cast<unsigned char>(ir.comment_part[1]);
  if (!std::isspace(ch)) {
    ir.err("E_COMMENT_FMT",
           "Invalid comment format — a space is required after '#'.");
  }
}

static LineIR parse_line(int line_no, const std::string &raw, const Config &cfg) {
  LineIR ir;
  ir.line_no = line_no;
  ir.raw_text = raw;

  auto [code_part, comment_part] = split_comment(raw);
  ir.code_part = code_part;
  ir.comment_part = comment_part;
  validate_comment_format(ir);

  std::string code = trim(code_part);
  if (code.empty()) {
    ir.kind = LineKind::BlankOrComment;
    return ir;
  }

  auto toks = split_ws(code);
  if (toks.empty()) {
    ir.kind = LineKind::BlankOrComment;
    return ir;
  }

  // Exact-case directives only.
  if (toks[0] == ".BEGIN") {
    ir.kind = LineKind::DirectiveBegin;
    if (toks.size() != 1) {
      ir.err("E_BEGIN_FMT", "Invalid .BEGIN syntax. Expected: .BEGIN");
    }
    return ir;
  }

  if (toks[0] == ".END") {
    ir.kind = LineKind::DirectiveEnd;
    if (toks.size() != 1) {
      ir.err("E_END_FMT", "Invalid .END syntax. Expected: .END");
    }
    return ir;
  }

  if (toks[0] == ".ALLOC") {
    ir.kind = LineKind::DirectiveAlloc;

    if (toks.size() == 1) {
      ir.err("E_ALLOC_MISSING",
             "Missing .ALLOC value. Expected: .ALLOC n, where n is between 0 and 200.");
      return ir;
    }

    if (toks.size() != 2) {
      ir.err("E_ALLOC_FMT",
             "Invalid .ALLOC syntax. Expected exactly one integer after .ALLOC (range 0..200).");
      return ir;
    }

    auto v = parse_int_strict(toks[1]);
    if (!v.has_value()) {
      ir.err("E_ALLOC_INT",
             "Invalid .ALLOC value. Expected an integer in the range 0..200.");
      return ir;
    }

    if (*v < 0) {
      ir.err("E_ALLOC_NEG", "Error: .ALLOC value cannot be negative.");
      return ir;
    }

    if (*v > cfg.max_dmem_size) {
      ir.err("E_ALLOC_RANGE", "Error: .ALLOC value must be between 0 and 200.");
      return ir;
    }

    ir.alloc_n = *v;
    return ir;
  }

  if (!toks[0].empty() && toks[0][0] == '.') {
    ir.kind = LineKind::Invalid;
    auto guess = directive_suggestion(toks[0]);
    if (guess.has_value()) {
      ir.err("E_DIR_CASE",
             "Unknown directive '" + toks[0] + "'. Did you mean '" + *guess + "'?");
    } else {
      ir.err("E_DIR_UNKNOWN", "Unknown directive '" + toks[0] + "'.");
    }
    return ir;
  }

  if (toks.size() >= 2 && is_ident(toks[0]) && toks[1] == ".BLOCK") {
    ir.kind = LineKind::DirectiveBlock;
    ir.block_name = toks[0];

    auto parsed = parse_block_payload(toks, 2, cfg);
    if (parsed.mode == BlockMode::None) {
      ir.err("E_BLOCK_FMT", parsed.error_message);
      return ir;
    }

    ir.block_mode = parsed.mode;
    ir.block_reserve_count = parsed.reserve_count;
    ir.block_values = std::move(parsed.values);
    return ir;
  }

  if (toks[0] == ".BLOCK") {
    ir.kind = LineKind::DirectiveBlock;

    auto parsed = parse_block_payload(toks, 1, cfg);
    if (parsed.mode == BlockMode::None) {
      ir.err("E_BLOCK_FMT", parsed.error_message);
      return ir;
    }

    ir.block_mode = parsed.mode;
    ir.block_reserve_count = parsed.reserve_count;
    ir.block_values = std::move(parsed.values);
    return ir;
  }

  if (toks.size() >= 2 && is_ident(toks[0]) && toks[1] == ".DATA") {
    ir.kind = LineKind::DataDecl;
    ir.data_name = toks[0];

    if (toks.size() == 2) return ir;

    if (toks.size() == 3) {
      const std::string &t = toks[2];
      if (t.size() >= 2 && t[0] == '=') {
        auto v = parse_int_strict(t.substr(1));
        if (!v.has_value()) {
          ir.err("E_DATA_INT",
                 "Invalid .DATA initializer. Expected '=number' with no space after '='.");
          return ir;
        }

        if (*v < cfg.data_min || *v > cfg.data_max) {
          ir.err("E_DATA_RANGE",
                 "Invalid .DATA initializer. Value must be between " +
                 std::to_string(cfg.data_min) + " and " +
                 std::to_string(cfg.data_max) + ".");
          return ir;
        }

        ir.data_init = *v;
        return ir;
      }

      ir.err("E_DATA_FMT",
             "Invalid .DATA initializer. Expected '=number' with no space after '='.");
      return ir;
    }

    // Deliberately reject spaced '=' form such as: x .DATA = 3
    if (toks.size() >= 4 && toks[2] == "=") {
      ir.err("E_DATA_FMT",
             "Invalid .DATA initializer. Expected '=number' with no space after '='.");
      return ir;
    }

    ir.err("E_DATA_FMT",
           "Invalid .DATA syntax. Expected: name .DATA or name .DATA =3");
    return ir;
  }

  if (toks.size() >= 2 && is_ident(toks[0]) &&
      !toks[1].empty() && toks[1][0] == '.') {
    ir.kind = LineKind::Invalid;
    auto guess = directive_suggestion(toks[1]);
    if (guess.has_value()) {
      ir.err("E_DIR_CASE",
             "Unknown directive '" + toks[1] + "'. Did you mean '" + *guess + "'?");
    } else {
      ir.err("E_DIR_UNKNOWN", "Unknown directive '" + toks[1] + "'.");
    }
    return ir;
  }

  // Instruction / label parsing.
  ir.kind = LineKind::Instruction;
  std::string s = trim(ltrim(code_part));

  std::optional<std::string> label;
  auto colon_pos = s.find(':');
  if (colon_pos != std::string::npos) {
    std::string left  = trim(s.substr(0, colon_pos));
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

  if (label.has_value()) ir.label_def = *label;

  if (s.empty()) {
    ir.err("E_INSTR_EMPTY", "Missing mnemonic.");
    ir.kind = LineKind::Invalid;
    return ir;
  }

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

  if (rest[0] == '=') {
    std::string rhs = trim(rest.substr(1));
    if (rhs.empty()) {
      ir.err("E_IMM_FMT", "Invalid immediate. Expected =number.");
      return ir;
    }

    auto v = parse_int_strict(rhs);
    if (!v.has_value()) {
      ir.err("E_IMM_INT", "Invalid immediate. Expected an integer after '='.");
      return ir;
    }

    if (*v < cfg.operand_min || *v > cfg.operand_max) {
      ir.err("E_IMM_RANGE",
             "Immediate out of range. Value must be between " +
             std::to_string(cfg.operand_min) + " and " +
             std::to_string(cfg.operand_max) + ".");
      return ir;
    }

    ir.operand_kind = OperandKind::Immediate;
    ir.operand_imm = *v;
    return ir;
  }

  auto rest_toks = split_ws(rest);
  if (rest_toks.size() == 1 && is_ident(rest_toks[0])) {
    ir.operand_kind = OperandKind::Symbol;
    ir.operand_sym = rest_toks[0];
    return ir;
  }

  ir.err("E_OPERAND_FMT", "Invalid operand format. Expected SYMBOL or =number.");
  return ir;
}

struct Pass1Result {
  std::vector<LineIR> ir;
  std::unordered_map<std::string, SymEntry> symtab;
  std::optional<int> dmem_size;
  int dmem_used = 0;
  int imem_count = 0;
  bool seen_alloc = false;
  bool seen_begin = false;
  bool seen_end = false;
  int alloc_idx = -1;
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
  int n = 0;
  for (const auto &line : ir) {
    for (const auto &d : line.diags) {
      if (d.sev == Severity::Error) ++n;
    }
  }
  return n;
}

static void attach_global_error(std::vector<LineIR> &ir,
                                int attach_idx,
                                std::string code,
                                std::string msg) {
  if (ir.empty()) return;
  attach_idx = std::max(0, std::min<int>(attach_idx, static_cast<int>(ir.size()) - 1));
  ir[attach_idx].err(std::move(code), std::move(msg));
}

static Pass1Result pass1(const std::vector<std::string> &lines, const Config &cfg) {
  Pass1Result ctx;
  ctx.ir.reserve(lines.size());

  AsmState state = AsmState::PreBegin;
  int dmem_lc = 0;
  int imem_lc = 0;

  for (size_t i = 0; i < lines.size(); ++i) {
    LineIR line = parse_line(static_cast<int>(i) + 1, lines[i], cfg);
    ctx.ir.push_back(std::move(line));
    LineIR &lir = ctx.ir.back();

    if (lir.kind == LineKind::BlankOrComment) continue;

    if (state == AsmState::PostEnd) {
      lir.err("E_AFTER_END", "Statement after .END is not allowed.");
      continue;
    }

    if (lir.kind == LineKind::DirectiveAlloc) {
      if (state != AsmState::PreBegin) {
        lir.err("E_ALLOC_POS", ".ALLOC must appear before .BEGIN.");
      }
      if (ctx.seen_alloc) {
        lir.err("E_ALLOC_DUP", "Duplicate .ALLOC directive.");
      }
      if (!ctx.seen_alloc) {
        ctx.seen_alloc = true;   // presence counts even if value invalid
        ctx.alloc_idx = static_cast<int>(i);
        if (lir.alloc_n.has_value()) {
          ctx.dmem_size = *lir.alloc_n;
        }
      }
      continue;
    }

    if (lir.kind == LineKind::DirectiveBegin) {
      if (ctx.seen_begin) {
        lir.err("E_BEGIN_DUP", "Duplicate .BEGIN directive.");
      } else if (state != AsmState::PreBegin) {
        lir.err("E_BEGIN_POS", ".BEGIN is misplaced.");
      } else {
        ctx.seen_begin = true;
        state = AsmState::InCode;
      }
      continue;
    }

    if (lir.kind == LineKind::DirectiveEnd) {
      if (ctx.seen_end) {
        lir.err("E_END_DUP", "Duplicate .END directive.");
      } else if (state != AsmState::InCode) {
        lir.err("E_END_POS", ".END without matching .BEGIN.");
      } else {
        ctx.seen_end = true;
        state = AsmState::PostEnd;
      }
      continue;
    }

    if ((lir.kind == LineKind::DataDecl || lir.kind == LineKind::DirectiveBlock) &&
        state != AsmState::PreBegin) {
      lir.err("E_DATA_POS", "Data directives are not allowed after .BEGIN.");
      continue;
    }

    if (lir.kind == LineKind::Instruction && state != AsmState::InCode) {
      lir.err("E_INSTR_POS", "Instruction outside .BEGIN/.END.");
      continue;
    }

    if (lir.kind == LineKind::Invalid) {
      continue;
    }

    if (lir.kind == LineKind::DataDecl) {
      if (!lir.data_name.has_value()) continue;

      std::string key = canon(*lir.data_name, cfg);
      if (ctx.symtab.find(key) != ctx.symtab.end()) {
        lir.err("E_SYM_DUP", "Duplicate symbol: " + *lir.data_name);
        continue;
      }

      lir.dmem_addr = dmem_lc++;
      lir.data_init = lir.data_init.value_or(cfg.default_uninitialized);
      ctx.symtab.emplace(key, SymEntry{*lir.data_name, SymKind::Data,
                                       *lir.dmem_addr, lir.line_no});
      continue;
    }

    if (lir.kind == LineKind::DirectiveBlock) {
      int span = lir.block_span();
      if (span <= 0) continue;

      lir.dmem_addr = dmem_lc;

      if (lir.block_name.has_value()) {
        std::string key = canon(*lir.block_name, cfg);
        if (ctx.symtab.find(key) != ctx.symtab.end()) {
          lir.err("E_SYM_DUP", "Duplicate symbol: " + *lir.block_name);
          continue;
        }
        ctx.symtab.emplace(key, SymEntry{*lir.block_name, SymKind::Data,
                                         *lir.dmem_addr, lir.line_no});
      }

      dmem_lc += span;
      continue;
    }

    if (lir.kind == LineKind::Instruction) {
      if (lir.label_def.has_value()) {
        std::string key = canon(*lir.label_def, cfg);
        if (ctx.symtab.find(key) != ctx.symtab.end()) {
          lir.err("E_SYM_DUP", "Duplicate symbol: " + *lir.label_def);
        } else {
          ctx.symtab.emplace(key, SymEntry{*lir.label_def, SymKind::Label,
                                           imem_lc, lir.line_no});
        }
      }
      lir.imem_addr = imem_lc++;
      continue;
    }
  }

  ctx.dmem_used = dmem_lc;
  ctx.imem_count = imem_lc;

  if (!ctx.seen_alloc) {
    attach_global_error(ctx.ir, 0, "E_MISSING_ALLOC", "Missing .ALLOC directive.");
  }

  if (!ctx.seen_begin) {
    int idx = 0;
    for (size_t i = 0; i < ctx.ir.size(); ++i) {
      if (ctx.ir[i].kind != LineKind::BlankOrComment) {
        idx = static_cast<int>(i);
        break;
      }
    }
    attach_global_error(ctx.ir, idx, "E_MISSING_BEGIN", "Missing .BEGIN directive.");
  }

  if (ctx.seen_begin && !ctx.seen_end) {
    attach_global_error(ctx.ir, static_cast<int>(ctx.ir.size()) - 1,
                        "E_MISSING_END", "Missing .END directive.");
  }

  if (ctx.dmem_size.has_value() && ctx.dmem_used > *ctx.dmem_size) {
    int attach = (ctx.alloc_idx >= 0) ? ctx.alloc_idx
                                      : static_cast<int>(ctx.ir.size()) - 1;
    attach_global_error(
        ctx.ir, attach, "E_DMEM_OVERFLOW",
        "Allocated data memory is too small. .ALLOC reserves " +
            std::to_string(*ctx.dmem_size) + " cell(s), but declarations require " +
            std::to_string(ctx.dmem_used) + ".");
  }

  if (ctx.imem_count > cfg.max_imem_size) {
    attach_global_error(
        ctx.ir, static_cast<int>(ctx.ir.size()) - 1, "E_IMEM_OVERFLOW",
        "Instruction count exceeds supported maximum of " +
            std::to_string(cfg.max_imem_size) + ".");
  }

  return ctx;
}

struct Pass2Result {
  std::vector<int> imem_words;
  std::vector<int> dmem_init;
};

static void validate_pass2(Pass1Result &ctx, const Config &cfg) {
  const auto optab = build_optab();

  for (auto &lir : ctx.ir) {
    if (lir.kind != LineKind::Instruction || !lir.mnemonic.has_value()) continue;

    auto it = optab.find(*lir.mnemonic);  // exact-case mnemonic check
    if (it == optab.end()) {
      lir.err("E_BAD_OPCODE", "Invalid opcode/mnemonic: " + *lir.mnemonic);
      continue;
    }

    auto mode = it->second.mode;

    if (mode == OperandMode::None) {
      if (lir.operand_kind != OperandKind::None) {
        lir.err("E_OPERAND_UNEXPECTED",
                "Unexpected operand for instruction '" + *lir.mnemonic + "'.");
      }
      continue;
    }

    if (mode == OperandMode::Immediate) {
      if (lir.operand_kind != OperandKind::Immediate || !lir.operand_imm.has_value()) {
        lir.err("E_OPERAND_IMM",
                "Immediate operand required for instruction '" +
                *lir.mnemonic + "' (use =number).");
      } else if (*lir.operand_imm < cfg.operand_min ||
                 *lir.operand_imm > cfg.operand_max) {
        lir.err("E_OPERAND_RANGE",
                "Immediate out of range. Value must be between " +
                std::to_string(cfg.operand_min) + " and " +
                std::to_string(cfg.operand_max) + ".");
      }
      continue;
    }

    if (lir.operand_kind != OperandKind::Symbol || !lir.operand_sym.has_value()) {
      lir.err("E_OPERAND_SYM",
              "Symbol operand required for instruction '" +
              *lir.mnemonic + "'.");
      continue;
    }

    auto sit = ctx.symtab.find(canon(*lir.operand_sym, cfg));
    if (sit == ctx.symtab.end()) {
      lir.err("E_UNDEF_SYM", "Undefined variable '" + *lir.operand_sym + "'.");
      continue;
    }

    SymKind expected = (mode == OperandMode::DataAddr) ? SymKind::Data
                                                       : SymKind::Label;
    const char *expected_name = (mode == OperandMode::DataAddr) ? "data symbol"
                                                                : "label";
    if (sit->second.kind != expected) {
      lir.err("E_SYM_KIND",
              "Operand '" + *lir.operand_sym + "' must refer to a " +
              std::string(expected_name) + ".");
      continue;
    }

    if (sit->second.address < cfg.operand_min ||
        sit->second.address > cfg.operand_max) {
      lir.err("E_OPERAND_RANGE",
              "Resolved address for '" + *lir.operand_sym +
              "' is out of range for the 2-digit operand field.");
    }
  }
}

static std::optional<Pass2Result> pass2(Pass1Result &ctx, const Config &cfg) {
  validate_pass2(ctx, cfg);

  if (has_any_errors(ctx.ir)) return std::nullopt;
  if (!ctx.dmem_size.has_value()) return std::nullopt;

  const auto optab = build_optab();

  Pass2Result out;
  out.imem_words.assign(ctx.imem_count, 0);
  out.dmem_init.assign(*ctx.dmem_size, cfg.default_uninitialized);

  for (auto &lir : ctx.ir) {
    if (lir.kind == LineKind::DataDecl && lir.dmem_addr.has_value()) {
      out.dmem_init[*lir.dmem_addr] =
          lir.data_init.value_or(cfg.default_uninitialized);
    } else if (lir.kind == LineKind::DirectiveBlock && lir.dmem_addr.has_value()) {
      int base = *lir.dmem_addr;
      if (lir.block_mode == BlockMode::InitializedList) {
        for (size_t i = 0; i < lir.block_values.size(); ++i) {
          int idx = base + static_cast<int>(i);
          if (0 <= idx && idx < static_cast<int>(out.dmem_init.size())) {
            out.dmem_init[idx] = lir.block_values[i];
          }
        }
      }
    }
  }

  for (auto &lir : ctx.ir) {
    if (lir.kind != LineKind::Instruction ||
        !lir.imem_addr.has_value() ||
        !lir.mnemonic.has_value()) {
      continue;
    }

    auto it = optab.find(*lir.mnemonic);
    if (it == optab.end()) continue;

    int operand = 0;
    switch (it->second.mode) {
      case OperandMode::None:
        operand = 0;
        break;

      case OperandMode::Immediate:
        if (!lir.operand_imm.has_value()) continue;
        operand = *lir.operand_imm;
        break;

      case OperandMode::DataAddr:
      case OperandMode::InstAddr: {
        if (!lir.operand_sym.has_value()) continue;
        auto sit = ctx.symtab.find(canon(*lir.operand_sym, cfg));
        if (sit == ctx.symtab.end()) continue;
        operand = sit->second.address;
        break;
      }
    }

    int word = it->second.opcode * 100 + operand;
    if (word < 0 || word > 9999) {
      lir.err("E_WORD_RANGE", "Encoded word out of range (0..9999).");
      continue;
    }

    lir.machine_word = word;
    out.imem_words[*lir.imem_addr] = word;
  }

  if (has_any_errors(ctx.ir)) return std::nullopt;
  return out;
}

static std::string fmt_word4_unsigned(int v) {
  std::ostringstream oss;
  oss << std::setw(4) << std::setfill('0') << v;
  return oss.str();
}

static std::string fmt_word4_signed(int v) {
  if (v >= 0) return fmt_word4_unsigned(v);
  int av = std::abs(v);
  std::ostringstream oss;
  oss << '-' << std::setw(4) << std::setfill('0') << av;
  return oss.str();
}

static void write_hll(const std::string &hll_path,
                      const std::string &src_name,
                      const std::string &hll_name,
                      const std::string &hlx_name,
                      const Pass1Result &ctx,
                      const Config &cfg) {
  std::ofstream out(hll_path);
  if (!out) return;

  out << "Source:  " << src_name << "\n";
  out << "Listing: " << hll_name << "\n";
  out << "Machine: " << hlx_name << "\n";
  out << "Version: " << cfg.version << "\n\n";
  out << "Addr  Word  Source\n";

  auto fmt_addr2 = [](int addr) {
    std::ostringstream a;
    a << std::setw(2) << std::setfill('0') << addr;
    return a.str();
  };

  for (const auto &line : ctx.ir) {
    if (line.kind == LineKind::DirectiveBlock && line.dmem_addr.has_value()) {
      int base = *line.dmem_addr;
      int span = line.block_span();

      for (int i = 0; i < span; ++i) {
        int value = cfg.default_uninitialized;
        if (line.block_mode == BlockMode::InitializedList) {
          value = line.block_values[static_cast<size_t>(i)];
        }

        out << fmt_addr2(base + i) << "   "
            << fmt_word4_signed(value) << "  "
            << (i == 0 ? line.raw_text : "") << "\n";
      }
    } else {
      std::string addr_field = "  ";
      std::string word_field = "    ";

      if (line.kind == LineKind::DataDecl && line.dmem_addr.has_value()) {
        addr_field = fmt_addr2(*line.dmem_addr);
        word_field = fmt_word4_signed(
            line.data_init.value_or(cfg.default_uninitialized));
      } else if (line.kind == LineKind::Instruction && line.imem_addr.has_value()) {
        addr_field = fmt_addr2(*line.imem_addr);
        word_field = line.machine_word.has_value()
                         ? fmt_word4_unsigned(*line.machine_word)
                         : "????";
      }

      out << addr_field << "   " << word_field << "  " << line.raw_text << "\n";
    }

    for (const auto &d : line.diags) {
      const char *sev =
          (d.sev == Severity::Error) ? "ERROR"
          : (d.sev == Severity::Warning) ? "WARN"
          : "NOTE";
      out << "           >>> " << sev << " " << d.code << ": " << d.msg << "\n";
    }
  }
}

static void write_hlx(const std::string &hlx_path,
                      const Pass2Result &p2,
                      int instruction_count,
                      int dmem_size) {
  std::ofstream out(hlx_path);
  if (!out) return;

  out << instruction_count << "\n";
  for (int w : p2.imem_words) out << fmt_word4_unsigned(w) << "\n";
  out << dmem_size << "\n";
  for (int v : p2.dmem_init) out << fmt_word4_signed(v) << "\n";
}

static void emit_log_report(std::ostream &out, const Pass1Result &ctx) {
  int err_count = count_errors(ctx.ir);

  if (err_count == 0) {
    out << "Assembly completed with NO errors.\n";
    return;
  }

  out << "Assembly completed with " << err_count << " error(s):\n\n";
  for (const auto &line : ctx.ir) {
    for (const auto &d : line.diags) {
      if (d.sev != Severity::Error) continue;
      out << "  LINE " << line.line_no << ": ERROR - " << d.msg << "\n";
    }
  }
}

static void write_log(const std::string &log_path, const Pass1Result &ctx) {
  std::ofstream out(log_path);
  if (!out) return;
  emit_log_report(out, ctx);
}

static void print_errors_to_terminal(const Pass1Result &ctx) {
  if (!has_any_errors(ctx.ir)) return;
  emit_log_report(std::cerr, ctx);
}

int run(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: ./assembler input.hal\n";
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

  auto hll_path_opt = replace_suffix(src_path, ".hll");
  auto hlx_path_opt = replace_suffix(src_path, ".hlx");
  auto log_path_opt = replace_suffix(src_path, ".log");

  if (!hll_path_opt.has_value() ||
      !hlx_path_opt.has_value() ||
      !log_path_opt.has_value()) {
    std::cerr << "error: cannot derive output file names\n";
    return 2;
  }

  std::string src_name = basename_only(src_path);
  std::string hll_path = *hll_path_opt;
  std::string hlx_path = *hlx_path_opt;
  std::string log_path = *log_path_opt;

  std::string hll_name = basename_only(hll_path);
  std::string hlx_name = basename_only(hlx_path);
  std::string log_name = basename_only(log_path);

  std::cout << "Source : " << src_name << "\n\n";

  std::cout << "Pass 1: Building symbol table and assigning addresses...\n";
  Pass1Result p1 = pass1(lines, cfg);

  if (has_any_errors(p1.ir)) {
    // Collect additional semantic errors without printing Pass 2.
    validate_pass2(p1, cfg);

    write_hll(hll_path, src_name, hll_name, hlx_name, p1, cfg);
    write_log(log_path, p1);
    print_errors_to_terminal(p1);

    std::cout << "\nAssembly failed.\n";
    std::cout << "Listing: " << hll_name << "\n";
    std::cout << "Log    : " << log_name << "\n";
    return 1;
  }

  std::cout << "Pass 2: Generating machine code...\n";
  auto p2 = pass2(p1, cfg);

  write_hll(hll_path, src_name, hll_name, hlx_name, p1, cfg);
  write_log(log_path, p1);

  if (!p2.has_value()) {
    print_errors_to_terminal(p1);

    std::cout << "\nAssembly failed.\n";
    std::cout << "Listing: " << hll_name << "\n";
    std::cout << "Log    : " << log_name << "\n";
    return 1;
  }

  write_hlx(hlx_path, *p2, p1.imem_count, *p1.dmem_size);

  std::cout << "\nAssembly successful.\n";
  std::cout << "Output : " << hlx_name << "\n";
  std::cout << "Listing: " << hll_name << "\n";
  std::cout << "Log    : " << log_name << "\n";
  return 0;
}

}  // namespace hasm

#ifndef HASM_UNIT_TEST
int main(int argc, char **argv) {
  return hasm::run(argc, argv);
}
#endif
