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
  int max_dmem_size = 100;
  int max_imem_size = 100;
  bool case_sensitive = false;
};

static std::string trim(std::string s) {
  auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

static std::string upper(std::string s) {
  for (char &c : s) c = static_cast<char>(std::toupper((unsigned char)c));
  return s;
}

static bool iequals(const std::string &a, const std::string &b) {
  return upper(a) == upper(b);
}

static bool is_ident(const std::string &s) {
  if (s.empty()) return false;
  auto ok_first = [](unsigned char ch) { return std::isalpha(ch) || ch == '_'; };
  auto ok_rest = [](unsigned char ch) { return std::isalnum(ch) || ch == '_'; };
  if (!ok_first((unsigned char)s[0])) return false;
  for (size_t i = 1; i < s.size(); ++i) if (!ok_rest((unsigned char)s[i])) return false;
  return true;
}

static std::vector<std::string> split_ws(const std::string &s) {
  std::istringstream iss(s);
  std::vector<std::string> out;
  std::string tok;
  while (iss >> tok) out.push_back(tok);
  return out;
}

static std::pair<std::string, std::string> split_comment(const std::string &raw) {
  auto pos = raw.find('#');
  if (pos == std::string::npos) return {raw, ""};
  return {raw.substr(0, pos), raw.substr(pos)};
}

static std::optional<int> parse_int_strict(const std::string &s) {
  if (s.empty()) return std::nullopt;
  char *end = nullptr;
  long v = std::strtol(s.c_str(), &end, 10);
  if (end == nullptr || *end != '\0') return std::nullopt;
  if (v < std::numeric_limits<int>::min() || v > std::numeric_limits<int>::max()) return std::nullopt;
  return static_cast<int>(v);
}

static std::string basename_only(const std::string &path) {
  auto pos = path.find_last_of("/\\");
  return pos == std::string::npos ? path : path.substr(pos + 1);
}

static std::optional<std::string> replace_suffix(const std::string &path, const std::string &ext) {
  auto pos = path.find_last_of('.');
  if (pos == std::string::npos) return std::nullopt;
  return path.substr(0, pos) + ext;
}

enum class Severity { Note, Warning, Error };
enum class LineKind { BlankOrComment, DirectiveAlloc, DirectiveBegin, DirectiveEnd, DataDecl, DirectiveBlock, Instruction, Invalid };
enum class OperandKind { None, Symbol, Immediate };
enum class SymKind { Data, Label };
enum class BlockMode { None, Reserve, InitializedList };
enum class OperandMode { None, DataAddr, InstAddr, Immediate };

struct Diagnostic {
  Severity sev = Severity::Error;
  std::string code;
  std::string msg;
};

struct SymEntry {
  std::string display_name;
  SymKind kind = SymKind::Data;
  int address = -1;
  int defined_line_no = -1;
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

  void err(std::string code, std::string msg) {
    diags.push_back(Diagnostic{Severity::Error, std::move(code), std::move(msg)});
  }

  int block_span() const {
    if (block_mode == BlockMode::Reserve && block_reserve_count.has_value()) return *block_reserve_count;
    if (block_mode == BlockMode::InitializedList) return static_cast<int>(block_values.size());
    return 0;
  }
};

struct OpInfo { int opcode = 0; OperandMode mode = OperandMode::None; };

static std::string canon(const std::string &name, const Config &cfg) {
  return cfg.case_sensitive ? name : upper(name);
}

static const std::unordered_map<std::string, OpInfo> &optab() {
  static const std::unordered_map<std::string, OpInfo> table = {
      {"READ", {1, OperandMode::DataAddr}},   {"WRITE", {2, OperandMode::DataAddr}},
      {"LOAD", {3, OperandMode::DataAddr}},   {"STORE", {4, OperandMode::DataAddr}},
      {"ADD", {5, OperandMode::DataAddr}},    {"SUB", {6, OperandMode::DataAddr}},
      {"MULT", {7, OperandMode::DataAddr}},   {"DIV", {8, OperandMode::DataAddr}},
      {"MOD", {9, OperandMode::DataAddr}},    {"BRANCH", {10, OperandMode::InstAddr}},
      {"BRT", {11, OperandMode::InstAddr}},   {"BRF", {12, OperandMode::InstAddr}},
      {"CLEAR", {13, OperandMode::None}},     {"SET", {14, OperandMode::None}},
      {"DOUBLE", {15, OperandMode::DataAddr}},{"INCR", {16, OperandMode::None}},
      {"DECR", {17, OperandMode::None}},      {"CLT", {18, OperandMode::DataAddr}},
      {"CLE", {19, OperandMode::DataAddr}},   {"CEQ", {20, OperandMode::DataAddr}},
      {"CNE", {21, OperandMode::DataAddr}},   {"CGE", {22, OperandMode::DataAddr}},
      {"CGT", {23, OperandMode::DataAddr}},   {"SETI", {24, OperandMode::Immediate}},
      {"ADDI", {25, OperandMode::Immediate}}, {"SUBI", {26, OperandMode::Immediate}},
      {"MULTI", {27, OperandMode::Immediate}},{"DIVI", {28, OperandMode::Immediate}},
      {"MODI", {29, OperandMode::Immediate}}, {"POW", {30, OperandMode::DataAddr}},
      {"SHACC", {31, OperandMode::None}},     {"BSUB", {32, OperandMode::InstAddr}},
      {"RET", {33, OperandMode::None}},       {"SHINDX", {34, OperandMode::None}},
      {"LOADA", {35, OperandMode::DataAddr}}, {"ICLR", {36, OperandMode::None}},
      {"IREAD", {37, OperandMode::None}},     {"IWRITE", {38, OperandMode::None}},
      {"ILOAD", {39, OperandMode::None}},     {"ISTORE", {40, OperandMode::None}},
      {"IINCR", {41, OperandMode::None}},     {"IDECR", {42, OperandMode::None}},
      {"IADD", {43, OperandMode::None}},      {"ISUB", {44, OperandMode::None}},
      {"IMULT", {45, OperandMode::None}},     {"IDIV", {46, OperandMode::None}},
      {"IMOD", {47, OperandMode::None}},      {"ICLT", {48, OperandMode::None}},
      {"ICLE", {49, OperandMode::None}},      {"ICEQ", {50, OperandMode::None}},
      {"ICNE", {51, OperandMode::None}},      {"ICGE", {52, OperandMode::None}},
      {"ICGT", {53, OperandMode::None}},      {"SHBASE", {54, OperandMode::None}},
      {"HALT", {99, OperandMode::None}},
  };
  return table;
}

struct ParseBlockResult {
  BlockMode mode = BlockMode::None;
  std::optional<int> reserve_count;
  std::vector<int> values;
  std::string error_message;
};

static ParseBlockResult parse_block_payload(const std::vector<std::string> &toks, size_t start_idx, const Config &cfg) {
  ParseBlockResult out;
  if (start_idx >= toks.size()) {
    out.error_message = "Invalid .BLOCK syntax.";
    return out;
  }

  std::string joined;
  for (size_t i = start_idx; i < toks.size(); ++i) joined += toks[i];
  joined = trim(joined);
  if (joined.empty()) {
    out.error_message = "Invalid .BLOCK syntax.";
    return out;
  }

  if (joined[0] == '=') {
    std::vector<std::string> parts;
    std::string cur;
    for (char c : joined) {
      if (c == ',') { parts.push_back(trim(cur)); cur.clear(); } else { cur.push_back(c); }
    }
    parts.push_back(trim(cur));
    for (const auto &part : parts) {
      if (part.size() < 2 || part[0] != '=') {
        out.error_message = "Invalid .BLOCK initialized list. Use: name .BLOCK =3, =7, =17";
        return out;
      }
      auto v = parse_int_strict(trim(part.substr(1)));
      if (!v.has_value()) {
        out.error_message = "Invalid .BLOCK initializer: " + part;
        return out;
      }
      if (*v < cfg.data_min || *v > cfg.data_max) {
        out.error_message = ".BLOCK initializer out of range: " + part;
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
  if (!n.has_value() || *n <= 0) {
    out.error_message = ".BLOCK size must be a positive integer: " + joined;
    return out;
  }
  if (*n > cfg.max_dmem_size) {
    out.error_message = ".BLOCK size exceeds supported memory size: " + joined;
    return out;
  }
  out.mode = BlockMode::Reserve;
  out.reserve_count = *n;
  return out;
}

LineIR parse_line(int line_no, const std::string &raw, const Config &cfg) {
  LineIR ir;
  ir.line_no = line_no;
  ir.raw_text = raw;
  auto parts = split_comment(raw);
  ir.code_part = parts.first;
  ir.comment_part = parts.second;

  std::string code = trim(ir.code_part);
  if (code.empty()) {
    ir.kind = LineKind::BlankOrComment;
    return ir;
  }

  auto toks = split_ws(code);
  if (toks.empty()) {
    ir.kind = LineKind::BlankOrComment;
    return ir;
  }

  if (toks.size() == 1 && iequals(toks[0], ".BEGIN")) { ir.kind = LineKind::DirectiveBegin; return ir; }
  if (toks.size() == 1 && iequals(toks[0], ".END"))   { ir.kind = LineKind::DirectiveEnd;   return ir; }

  if (iequals(toks[0], ".ALLOC")) {
    ir.kind = LineKind::DirectiveAlloc;
    if (toks.size() != 2) { ir.err("E_ALLOC_FMT", "Invalid .ALLOC syntax (expected: .ALLOC n)."); return ir; }
    auto v = parse_int_strict(toks[1]);
    if (!v.has_value()) { ir.err("E_ALLOC_INT", "Invalid .ALLOC value (expected integer)."); return ir; }
    if (*v < 0 || *v > cfg.max_dmem_size) { ir.err("E_ALLOC_RANGE", "Invalid .ALLOC value (out of supported range)."); return ir; }
    ir.alloc_n = *v;
    return ir;
  }

  if (iequals(toks[0], ".BLOCK")) {
    ir.kind = LineKind::DirectiveBlock;
    ir.err("E_BLOCK_NAME", ".BLOCK requires a symbol name.");
    return ir;
  }

  if (toks.size() >= 2 && is_ident(toks[0]) && iequals(toks[1], ".DATA")) {
    ir.kind = LineKind::DataDecl;
    ir.data_name = toks[0];
    if (toks.size() == 2) return ir;
    if (toks.size() == 3 && !toks[2].empty() && toks[2][0] == '=') {
      auto v = parse_int_strict(toks[2].substr(1));
      if (!v.has_value()) { ir.err("E_DATA_INT", "Invalid .DATA initializer (expected =number)."); return ir; }
      if (*v < cfg.data_min || *v > cfg.data_max) { ir.err("E_DATA_RANGE", "Invalid .DATA initializer (out of range)."); return ir; }
      ir.data_init = *v;
      return ir;
    }
    if (toks.size() == 4 && toks[2] == "=") {
      auto v = parse_int_strict(toks[3]);
      if (!v.has_value()) { ir.err("E_DATA_INT", "Invalid .DATA initializer (expected integer after '=')."); return ir; }
      if (*v < cfg.data_min || *v > cfg.data_max) { ir.err("E_DATA_RANGE", "Invalid .DATA initializer (out of range)."); return ir; }
      ir.data_init = *v;
      return ir;
    }
    ir.err("E_DATA_FMT", "Invalid .DATA syntax (expected: name .DATA or name .DATA =k).");
    return ir;
  }

  if (toks.size() >= 2 && is_ident(toks[0]) && iequals(toks[1], ".BLOCK")) {
    ir.kind = LineKind::DirectiveBlock;
    ir.block_name = toks[0];
    auto pb = parse_block_payload(toks, 2, cfg);
    if (pb.mode == BlockMode::None) { ir.err("E_BLOCK_FMT", pb.error_message); return ir; }
    ir.block_mode = pb.mode;
    ir.block_reserve_count = pb.reserve_count;
    ir.block_values = std::move(pb.values);
    return ir;
  }

  ir.kind = LineKind::Instruction;
  std::string s = trim(code);
  auto colon = s.find(':');
  if (colon != std::string::npos) {
    std::string left = trim(s.substr(0, colon));
    std::string right = trim(s.substr(colon + 1));
    if (is_ident(left)) {
      ir.label_def = left;
      s = right;
      if (s.empty()) { ir.kind = LineKind::Invalid; ir.err("E_LABEL_ONLY", "Label must be followed by an instruction."); return ir; }
    }
  }

  std::string mnemonic, rest;
  {
    std::istringstream iss(s);
    iss >> mnemonic;
    std::getline(iss, rest);
    rest = trim(rest);
  }
  if (!is_ident(mnemonic)) { ir.kind = LineKind::Invalid; ir.err("E_MNEM_FMT", "Invalid mnemonic format."); return ir; }
  ir.mnemonic = mnemonic;
  if (rest.empty()) return ir;

  if (rest[0] == '=') {
    auto v = parse_int_strict(trim(rest.substr(1)));
    if (!v.has_value()) { ir.err("E_IMM_INT", "Invalid immediate (expected integer after '=')."); return ir; }
    if (*v < cfg.operand_min || *v > cfg.operand_max) { ir.err("E_IMM_RANGE", "Immediate out of range for 2-digit operand field."); return ir; }
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

  ir.err("E_OPERAND_FMT", "Invalid operand format (expected SYMBOL or =number).");
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

bool has_any_errors(const std::vector<LineIR> &ir) {
  for (const auto &line : ir) for (const auto &d : line.diags) if (d.sev == Severity::Error) return true;
  return false;
}

int count_errors(const std::vector<LineIR> &ir) {
  int n = 0;
  for (const auto &line : ir) for (const auto &d : line.diags) if (d.sev == Severity::Error) ++n;
  return n;
}

static void attach_global_error(std::vector<LineIR> &ir, int idx, std::string code, std::string msg) {
  if (ir.empty()) return;
  idx = std::max(0, std::min<int>(idx, static_cast<int>(ir.size()) - 1));
  ir[idx].err(std::move(code), std::move(msg));
}

Pass1Result pass1(const std::vector<std::string> &lines, const Config &cfg) {
  Pass1Result p1;
  enum class AsmState { PreBegin, InCode, PostEnd };
  AsmState state = AsmState::PreBegin;

  for (size_t i = 0; i < lines.size(); ++i) {
    p1.ir.push_back(parse_line(static_cast<int>(i) + 1, lines[i], cfg));
    LineIR &lir = p1.ir.back();
    if (lir.kind == LineKind::BlankOrComment) continue;

    if (state == AsmState::PostEnd) { lir.err("E_AFTER_END", "Statement after .END is not allowed."); continue; }

    if (lir.kind == LineKind::DirectiveAlloc) {
      if (state != AsmState::PreBegin) lir.err("E_ALLOC_POS", ".ALLOC must appear before .BEGIN.");
      if (p1.seen_alloc) lir.err("E_ALLOC_DUP", "Duplicate .ALLOC.");
      else if (lir.alloc_n.has_value()) { p1.seen_alloc = true; p1.dmem_size = *lir.alloc_n; p1.alloc_idx = static_cast<int>(i); }
      continue;
    }

    if (lir.kind == LineKind::DirectiveBegin) {
      if (p1.seen_begin) lir.err("E_BEGIN_DUP", "Duplicate .BEGIN.");
      else if (state != AsmState::PreBegin) lir.err("E_BEGIN_POS", ".BEGIN is misplaced.");
      else { p1.seen_begin = true; state = AsmState::InCode; }
      continue;
    }

    if (lir.kind == LineKind::DirectiveEnd) {
      if (p1.seen_end) lir.err("E_END_DUP", "Duplicate .END.");
      else if (state != AsmState::InCode) lir.err("E_END_POS", ".END without matching .BEGIN.");
      else { p1.seen_end = true; state = AsmState::PostEnd; }
      continue;
    }

    if ((lir.kind == LineKind::DataDecl || lir.kind == LineKind::DirectiveBlock) && state != AsmState::PreBegin) {
      lir.err("E_DATA_POS", "Data directives are not allowed after .BEGIN.");
      continue;
    }

    if (lir.kind == LineKind::Instruction && state != AsmState::InCode) {
      lir.err("E_INSTR_POS", "Instruction outside .BEGIN/.END.");
      continue;
    }
  }

  if (!p1.seen_alloc) attach_global_error(p1.ir, 0, "E_MISSING_ALLOC", "Missing .ALLOC directive.");
  if (!p1.seen_begin) attach_global_error(p1.ir, 0, "E_MISSING_BEGIN", "Missing .BEGIN directive.");
  if (p1.seen_begin && !p1.seen_end) attach_global_error(p1.ir, (int)p1.ir.size() - 1, "E_MISSING_END", "Missing .END directive.");

  int daddr = 0;
  for (auto &lir : p1.ir) {
    if (lir.kind == LineKind::DataDecl && lir.data_name.has_value()) {
      lir.dmem_addr = daddr;
      lir.data_init = lir.data_init.value_or(cfg.default_uninitialized);
      std::string key = canon(*lir.data_name, cfg);
      if (p1.symtab.find(key) != p1.symtab.end()) lir.err("E_SYM_DUP", "Duplicate symbol: " + *lir.data_name);
      else p1.symtab.emplace(key, SymEntry{*lir.data_name, SymKind::Data, daddr, lir.line_no});
      ++daddr;
      continue;
    }

    if (lir.kind == LineKind::DirectiveBlock && lir.block_name.has_value()) {
      int span = lir.block_span();
      lir.dmem_addr = daddr;
      std::string key = canon(*lir.block_name, cfg);
      if (p1.symtab.find(key) != p1.symtab.end()) lir.err("E_SYM_DUP", "Duplicate symbol: " + *lir.block_name);
      else p1.symtab.emplace(key, SymEntry{*lir.block_name, SymKind::Data, daddr, lir.line_no});
      daddr += std::max(0, span);
    }
  }
  p1.dmem_used = daddr;
  if (p1.dmem_size.has_value() && p1.dmem_used > *p1.dmem_size) {
    attach_global_error(p1.ir, p1.alloc_idx >= 0 ? p1.alloc_idx : (int)p1.ir.size() - 1,
                        "E_DMEM_OVERFLOW", "More .DATA/.BLOCK storage than .ALLOC size.");
  }

  int iaddr = 0;
  for (auto &lir : p1.ir) {
    if (lir.kind != LineKind::Instruction) continue;
    lir.imem_addr = iaddr;
    if (lir.label_def.has_value()) {
      std::string key = canon(*lir.label_def, cfg);
      if (p1.symtab.find(key) != p1.symtab.end()) lir.err("E_SYM_DUP", "Duplicate symbol: " + *lir.label_def);
      else p1.symtab.emplace(key, SymEntry{*lir.label_def, SymKind::Label, iaddr, lir.line_no});
    }
    ++iaddr;
  }
  p1.imem_count = iaddr;
  if (p1.imem_count > cfg.max_imem_size) {
    attach_global_error(p1.ir, (int)p1.ir.size() - 1, "E_IMEM_OVERFLOW", "Instruction count exceeds supported maximum.");
  }

  for (auto &lir : p1.ir) {
    if (lir.kind != LineKind::Instruction || !lir.mnemonic.has_value()) continue;
    auto it = optab().find(upper(*lir.mnemonic));
    if (it == optab().end()) { lir.err("E_BAD_OPCODE", "Invalid opcode/mnemonic: " + *lir.mnemonic); continue; }

    OperandMode mode = it->second.mode;
    if (mode == OperandMode::None) {
      if (lir.operand_kind != OperandKind::None) lir.err("E_OPERAND_UNEXPECTED", "Unexpected operand.");
      continue;
    }
    if (mode == OperandMode::Immediate) {
      if (lir.operand_kind != OperandKind::Immediate || !lir.operand_imm.has_value()) lir.err("E_OPERAND_IMM", "Immediate operand required (use =number).");
      else if (*lir.operand_imm < cfg.operand_min || *lir.operand_imm > cfg.operand_max) lir.err("E_OPERAND_RANGE", "Immediate out of range for 2-digit operand field.");
      continue;
    }
    if (lir.operand_kind != OperandKind::Symbol || !lir.operand_sym.has_value()) { lir.err("E_OPERAND_SYM", "Symbol operand required."); continue; }

    auto sit = p1.symtab.find(canon(*lir.operand_sym, cfg));
    if (sit == p1.symtab.end()) { lir.err("E_UNDEF_SYM", "Undefined symbol: " + *lir.operand_sym); continue; }
    SymKind expected = mode == OperandMode::DataAddr ? SymKind::Data : SymKind::Label;
    if (sit->second.kind != expected) { lir.err("E_SYM_KIND", "Symbol kind mismatch for operand: " + *lir.operand_sym); continue; }
    if (sit->second.address < cfg.operand_min || sit->second.address > cfg.operand_max) lir.err("E_OPERAND_RANGE", "Address out of range for 2-digit operand field.");
  }

  return p1;
}

struct Pass2Result {
  std::vector<int> imem_words;
  std::vector<int> dmem_init;
};

std::optional<Pass2Result> pass2(Pass1Result &p1, const Config &cfg) {
  if (!p1.dmem_size.has_value()) {
    attach_global_error(p1.ir, 0, "E_NO_ALLOC", "Cannot generate machine code without .ALLOC.");
    return std::nullopt;
  }

  Pass2Result out;
  out.imem_words.assign(p1.imem_count, 0);
  out.dmem_init.assign(*p1.dmem_size, cfg.default_uninitialized);

  for (const auto &lir : p1.ir) {
    if (lir.kind == LineKind::DataDecl && lir.dmem_addr.has_value()) out.dmem_init[*lir.dmem_addr] = lir.data_init.value_or(cfg.default_uninitialized);
    if (lir.kind == LineKind::DirectiveBlock && lir.dmem_addr.has_value() && lir.block_mode == BlockMode::InitializedList) {
      for (size_t i = 0; i < lir.block_values.size(); ++i) out.dmem_init[*lir.dmem_addr + (int)i] = lir.block_values[i];
    }
  }

  for (auto &lir : p1.ir) {
    if (lir.kind != LineKind::Instruction || !lir.imem_addr.has_value() || !lir.mnemonic.has_value()) continue;
    auto it = optab().find(upper(*lir.mnemonic));
    if (it == optab().end()) continue;
    int operand = 0;
    switch (it->second.mode) {
      case OperandMode::None: operand = 0; break;
      case OperandMode::Immediate: if (!lir.operand_imm.has_value()) continue; operand = *lir.operand_imm; break;
      case OperandMode::DataAddr:
      case OperandMode::InstAddr: {
        if (!lir.operand_sym.has_value()) continue;
        auto sit = p1.symtab.find(canon(*lir.operand_sym, cfg));
        if (sit == p1.symtab.end()) continue;
        operand = sit->second.address;
        break;
      }
    }
    int word = it->second.opcode * 100 + operand;
    if (word < 0 || word > 9999) { lir.err("E_WORD_RANGE", "Encoded word out of range (0..9999)."); continue; }
    lir.machine_word = word;
    out.imem_words[*lir.imem_addr] = word;
  }

  if (has_any_errors(p1.ir)) return std::nullopt;
  return out;
}

static std::string fmt_word4u(int v) {
  std::ostringstream oss; oss << std::setw(4) << std::setfill('0') << v; return oss.str();
}

static std::string fmt_word4s(int v) {
  if (v >= 0) return fmt_word4u(v);
  std::ostringstream oss; oss << '-' << std::setw(4) << std::setfill('0') << std::abs(v); return oss.str();
}

void write_hll(const std::string &hll_path, const std::string &src_name, const std::string &hll_name,
               const std::string &hlx_name, const Pass1Result &p1, const Config &cfg) {
  std::ofstream out(hll_path);
  if (!out) return;
  out << "Source:  " << src_name << "\n"
      << "Listing: " << hll_name << "\n"
      << "Machine: " << hlx_name << "\n"
      << "Version: " << cfg.version << "\n\n"
      << "Addr  Word  Source\n";

  auto fmt_addr = [](int a) { std::ostringstream oss; oss << std::setw(2) << std::setfill('0') << a; return oss.str(); };

  for (const auto &line : p1.ir) {
    if (line.kind == LineKind::DirectiveBlock && line.dmem_addr.has_value()) {
      int base = *line.dmem_addr;
      for (int i = 0; i < line.block_span(); ++i) {
        int value = line.block_mode == BlockMode::InitializedList ? line.block_values[(size_t)i] : cfg.default_uninitialized;
        out << fmt_addr(base + i) << "   " << fmt_word4s(value) << "  " << (i == 0 ? line.raw_text : "") << "\n";
      }
    } else {
      std::string addr = "  ", word = "    ";
      if (line.kind == LineKind::DataDecl && line.dmem_addr.has_value()) { addr = fmt_addr(*line.dmem_addr); word = fmt_word4s(line.data_init.value_or(cfg.default_uninitialized)); }
      if (line.kind == LineKind::Instruction && line.imem_addr.has_value()) { addr = fmt_addr(*line.imem_addr); word = line.machine_word.has_value() ? fmt_word4u(*line.machine_word) : "????"; }
      out << addr << "   " << word << "  " << line.raw_text << "\n";
    }
    for (const auto &d : line.diags) out << "           >>> ERROR " << d.code << ": " << d.msg << "\n";
  }
}

void write_hlx(const std::string &hlx_path, const Pass2Result &p2, int instruction_count, int dmem_size) {
  std::ofstream out(hlx_path);
  if (!out) return;
  out << instruction_count << "\n";
  for (int w : p2.imem_words) out << fmt_word4u(w) << "\n";
  out << dmem_size << "\n";
  for (int v : p2.dmem_init) out << fmt_word4s(v) << "\n";
}

void write_log(const std::string &log_path, const Pass1Result &p1) {
  std::ofstream out(log_path);
  if (!out) return;
  int n = count_errors(p1.ir);
  if (n == 0) { out << "Assembly completed with NO errors.\n"; return; }
  out << "Assembly completed with " << n << " error(s):\n\n";
  for (const auto &line : p1.ir) for (const auto &d : line.diags) if (d.sev == Severity::Error) out << "  LINE " << line.line_no << ": ERROR - " << d.msg << "\n";
}

int run(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "Usage: ./assembler_block_v2 input.hal\n";
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
  if (!hll_path_opt.has_value() || !hlx_path_opt.has_value() || !log_path_opt.has_value()) {
    std::cerr << "error: cannot derive output file names\n";
    return 2;
  }

  std::string src_name = basename_only(src_path);
  std::string hll_path = *hll_path_opt, hlx_path = *hlx_path_opt, log_path = *log_path_opt;
  std::string hll_name = basename_only(hll_path), hlx_name = basename_only(hlx_path), log_name = basename_only(log_path);

  std::cout << "Source : " << src_name << "\n\n";

  // PASS 1
  std::cout << "Pass 1: Building symbol table and assigning addresses...\n";
  Pass1Result p1 = pass1(lines, cfg);

  // STOP if Pass 1 fails
  if (has_any_errors(p1.ir)) {
    write_hll(hll_path, src_name, hll_name, hlx_name, p1, cfg);
    write_log(log_path, p1);

    std::cout << "\nAssembly failed.\n";
    std::cout << "Listing: " << hll_name << "\n";
    std::cout << "Log    : " << log_name << "\n";
    return 1;
  }

  // PASS 2 (only if Pass 1 is clean)
  std::cout << "Pass 2: Generating machine code...\n";
  auto p2 = pass2(p1, cfg);

  // write listing always
  write_hll(hll_path, src_name, hll_name, hlx_name, p1, cfg);
  write_log(log_path, p1);

  if (!p2.has_value()) {
    std::cout << "\nAssembly failed.\n";
    std::cout << "Listing: " << hll_name << "\n";
    std::cout << "Log    : " << log_name << "\n";
    return 1;
  }

  // success
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
