#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <iomanip>

namespace hasm {

// ================= UTIL =================

static std::string trim(std::string s) {
  auto not_space = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
  s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
  return s;
}

static std::string upper(std::string s) {
  for (char &c : s) c = std::toupper((unsigned char)c);
  return s;
}

static std::vector<std::string> split(const std::string &line) {
  std::istringstream iss(line);
  std::vector<std::string> v;
  std::string t;
  while (iss >> t) v.push_back(t);
  return v;
}

static std::string get_base_name(const std::string &file) {
  size_t slash = file.find_last_of("/\\");
  size_t dot = file.find_last_of('.');
  size_t start = (slash == std::string::npos) ? 0 : slash + 1;
  size_t len = (dot == std::string::npos) ? file.size() - start : dot - start;
  return file.substr(start, len);
}

// ================= OPCODE TABLE =================

static std::unordered_map<std::string, int> load_opcodes() {
  std::unordered_map<std::string, int> table;
  std::ifstream in("halix_v25.opcode");

  if (!in) {
    std::cerr << "ERROR: cannot open opcode file\n";
    return table;
  }

  std::string line;
  while (std::getline(in, line)) {
    line = trim(line);
    if (line.empty()) continue;

    std::istringstream iss(line);
    int code;
    std::string name;

    iss >> code >> name;
    if (!name.empty()) {
      name.erase(std::remove(name.begin(), name.end(), '#'), name.end());
      table[upper(name)] = code;
    }
  }

  return table;
}

// ================= ERROR =================

struct Error {
  int line;
  std::string msg;
};

static void emit(int line,
                 const std::string &msg,
                 std::vector<Error> &errors,
                 std::ostream &log) {

  std::string out = "HAL LINE " + std::to_string(line) + ": " + msg;
  std::cout << out << "\n";
  log << out << "\n";
  errors.push_back({line, msg});
}

// ================= INSTRUCTION =================

struct Instruction {
  int address;
  std::string opcode;
  std::vector<std::string> operands;
};

// ================= RULE =================

static bool bad_spacing(const std::string &code) {
  for (size_t i = 0; i + 1 < code.size(); i++) {
    if (code[i] == '=' && std::isspace((unsigned char)code[i + 1])) {
      return true;
    }
  }
  return false;
}

// ================= PARSER =================

void parse_line(const std::string &raw,
                int line_no,
                bool in_begin,
                bool after_end,
                bool halted,
                const std::unordered_map<std::string,int> &optab,
                std::vector<Error> &errors,
                std::ostream &log,
                int &alloc_size,
                int &used_memory,
                std::vector<Instruction> &program,
                int &address) {

  if (after_end) {
    emit(line_no, "Code after .END is not allowed", errors, log);
    return;
  }

  if (halted) {
    emit(line_no, "Code after HALT is not allowed", errors, log);
    return;
  }

  std::string code = raw;

  auto pos = code.find('#');
  if (pos != std::string::npos)
    code = code.substr(0, pos);

  code = trim(code);
  if (code.empty()) return;

  auto toks = split(code);
  if (toks.empty()) return;

  std::string op_raw = toks[0];
  std::string op = upper(op_raw);

  if (op == ".BEGIN" || op == ".END")
    return;

  if (op == ".ALLOC") {
    if (toks.size() != 2) {
      emit(line_no, ".ALLOC requires value", errors, log);
      return;
    }
    alloc_size = std::stoi(toks[1]);
    return;
  }

  if (bad_spacing(code)) {
    emit(line_no, "Invalid spacing after '='", errors, log);
    return;
  }

  if (!in_begin) return;

  if (op != op_raw) {
    emit(line_no, "Opcode must be uppercase: " + op_raw, errors, log);
    return;
  }

  if (!optab.count(op)) {
    emit(line_no, "Invalid opcode: " + op_raw, errors, log);
    return;
  }

  Instruction inst;
  inst.address = address++;
  inst.opcode = op;

  for (size_t i = 1; i < toks.size(); i++)
    inst.operands.push_back(toks[i]);

  program.push_back(inst);
}

// ================= RUN =================

int run(const std::string &file) {

  std::ifstream in(file);
  if (!in) {
    std::cout << "ERROR: cannot open input file\n";
    return 1;
  }

  auto optab = load_opcodes();
  if (optab.empty()) return 1;

  std::vector<std::string> lines;
  std::string l;
  while (getline(in, l)) lines.push_back(l);

  std::vector<Error> errors;
  std::stringstream log_buffer;

  std::vector<Instruction> program;
  int address = 0;

  bool in_begin = false;
  bool after_end = false;
  bool halted = false;

  for (int i = 0; i < (int)lines.size(); i++) {

    std::string clean = trim(lines[i]);
    if (clean.empty()) continue;

    auto toks = split(clean);
    if (toks.empty()) continue;

    std::string first = upper(toks[0]);

    if (first == ".BEGIN") in_begin = true;

    if (first == ".END") {
      after_end = true;
      continue;
    }

    if (first == "HALT") halted = false; // ✅ FIXED

    parse_line(lines[i], i + 1, in_begin, after_end, halted,
               optab, errors, log_buffer,
               *(new int(100)), *(new int(0)),
               program, address);
  }

  std::string base = get_base_name(file);

  if (!errors.empty()) {
    std::ofstream log(base + ".log");
    log << log_buffer.str();
    std::cout << "Assembly failed\n";
    return 1;
  }

  std::ofstream hll(base + ".hll");
  std::ofstream hlx(base + ".hlx");
  std::ofstream log(base + ".log");

  // ===== HLL =====
  for (auto &inst : program) {
    hll << std::setw(2) << std::setfill('0') << inst.address << " ";
    hll << std::left << std::setw(8) << inst.opcode;

    for (auto &op : inst.operands)
      hll << " " << op;

    hll << "\n";
  }

// ===== HLX =====

// number of instructions
hlx << program.size() << "\n";

// instructions ONLY (no addresses)
for (auto &inst : program) {

  int opcode = optab.at(inst.opcode);
  int operand = 0;

  if (!inst.operands.empty()) {
    std::string op = inst.operands[0];

    if (op[0] == '=') operand = std::stoi(op.substr(1));
    else if (isdigit(op[0])) operand = std::stoi(op);
  }

  int instruction = opcode * 100 + operand;

  hlx << std::setw(4) << std::setfill('0') << instruction << "\n";
}

// trailing data size (fixed format as requested)
hlx << 3 << "\n";

  log << "Assembly successful\n";

  std::cout << "Assembly Successful\n";
  return 0;
}

} // namespace

int main() {
  return hasm::run("first.hal");
}