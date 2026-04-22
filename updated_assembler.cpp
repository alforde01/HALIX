#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

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
    if (name.empty()) continue;

    name.erase(std::remove(name.begin(), name.end(), '#'), name.end());
    table[upper(name)] = code;
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
                 std::ofstream &log) {
  std::string out = "HAL LINE " + std::to_string(line) + ": " + msg;
  std::cout << out << "\n";
  log << out << "\n";
  errors.push_back({line, msg});
}

// ================= SPACE RULE =================

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
                std::ofstream &log,
                int &alloc_size,
                int &used_memory) {

  // ================= HARD STOP =================
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

  // ================= DIRECTIVES =================
  if (op == ".BEGIN" || op == ".END")
    return;

  // ================= ALLOC =================
  if (op == ".ALLOC") {
    if (toks.size() != 2) {
      emit(line_no, ".ALLOC requires value", errors, log);
      return;
    }

    int val = std::stoi(toks[1]);

    if (val < 0 || val > 100) {
      emit(line_no, ".ALLOC out of range (0–100)", errors, log);
      return;
    }

    alloc_size = val;
    return;
  }

  // ================= SPACE RULE =================
  if (bad_spacing(code)) {
    emit(line_no,
         "Invalid spacing: '=' must NOT be followed by space (use =2)",
         errors, log);
    return;
  }

  // ================= MEMORY TRACKING (.DATA / .BLOCK) =================
  if (op == ".DATA" || op == ".BLOCK") {
    used_memory++;

    if (used_memory > alloc_size) {
      emit(line_no,
           "Memory overflow: exceeds .ALLOC limit",
           errors, log);
      return;
    }

    return;
  }

  // ================= BEFORE BEGIN =================
  if (!in_begin)
    return;

  // ================= OPCODE VALIDATION =================
  if (op != op_raw) {
    emit(line_no,
         "Opcode must be uppercase: " + op_raw,
         errors, log);
    return;
  }

  if (!optab.count(op)) {
    emit(line_no,
         "Invalid opcode: " + op_raw,
         errors, log);
  }
}

// ================= RUN =================

int run(const std::string &file) {

  std::ifstream in(file);
  if (!in) return 1;

  std::ofstream log("error.log");

  auto optab = load_opcodes();
  if (optab.empty()) {
    std::cout << "ERROR: opcode file not loaded\n";
    return 1;
  }

  std::vector<std::string> lines;
  std::string l;

  while (getline(in, l))
    lines.push_back(l);

  std::vector<Error> errors;

  bool in_begin = false;
  bool after_end = false;
  bool halted = false;

  int alloc_size = 100;   // default memory limit
  int used_memory = 0;

  std::cout << "\n--- Assembly Output ---\n";

  for (int i = 0; i < (int)lines.size(); i++) {

    std::string clean = trim(lines[i]);
    if (clean.empty()) continue;

    auto first = upper(split(clean)[0]);

    if (first == ".BEGIN") in_begin = true;

    if (first == ".END") {
      after_end = true;
      continue;
    }

    if (first == "HALT") {
      halted = false;
    }

    parse_line(lines[i],
               i + 1,
               in_begin,
               after_end,
               halted,
               optab,
               errors,
               log,
               alloc_size,
               used_memory);
  }

  if (!errors.empty()) {
    std::cout << "\nAssembly failed: " << errors.size() << " error(s)\n";
    return 1;
  }

  std::cout << "Assembly Successful\n";
  return 0;
}

} // namespace

int main() {
  return hasm::run("first.hal");
}