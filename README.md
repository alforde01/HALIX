# Halix Two-Pass Assembler (C++)

A simple C++ implementation of a **two-pass assembler** with support for `.DATA` and `.BLOCK` directives.

---

## 🔧Step-1: Compile Assembler

g++ -std=c++17 -O2 assembler_block_v2.cpp -o assembler


###  Step-2: Unit Testing

g++ -std=c++17 -O2 assembler_block_v2_tests.cpp -o assembler_tests

###  Step-3: Run Tests

./assembler_tests

###  Step-4:Run Assembler

./assembler_block_v2 any_inputfile.hal
```bash
