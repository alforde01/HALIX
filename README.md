# HALIX
Repository to store HALIX project files and version control.


🧠 Halix Two-Pass Assembler (C++)

A clean implementation of a Two-Pass Assembler for the Halix instruction set, written in C++.

This project supports:

✅ .DATA directive
✅ .BLOCK directive (both reserve & initialized array-style)
✅ Symbol table generation
✅ Two-pass assembly process
✅ Machine code generation (.hlx)
✅ Listing file (.hll)
✅ Error log file (.log)
✅ Unit testing for validation
⚙️ Features
🔹 Two-Pass Architecture
Pass 1
Builds symbol table
Assigns memory addresses
Detects early errors
Pass 2
Generates machine code
Resolves symbols
🔹 .BLOCK Directive Support
# Reserve memory (uninitialized)
temp .BLOCK 2

# Initialize multiple values (array-like)
nums .BLOCK =3, =7, =17
🔹 Output Files
File	Description
.hlx	Machine code
.hll	Listing file
.log	Error report
📁 Project Structure
.
├── assembler_block_v2.cpp        # Main assembler
├── assembler_block_v2_tests.cpp  # Unit tests
├── sample.hal                    # Example input
└── README.md
🚀 How to Compile & Run
1️⃣ Compile the Assembler
g++ -std=c++17 -O2 assembler_block_v2.cpp -o assembler_block_v2
2️⃣ Run the Assembler
./assembler_block_v2 sample.hal
📌 Example Output
Source : sample.hal

Pass 1: Building symbol table and assigning addresses...
Pass 2: Generating machine code...

Assembly successful.
Output : sample.hlx
Listing: sample.hll
Log    : sample.log
❌ Example Failure
Source : bad_sample.hal

Pass 1: Building symbol table and assigning addresses...

Assembly failed.
Listing: bad_sample.hll
Log    : bad_sample.log
🧪 Running Unit Tests
Compile Tests
g++ -std=c++17 -O2 assembler_block_v2_tests.cpp -o assembler_block_v2_tests
Run Tests
./assembler_block_v2_tests
Expected Output
[TEST] parse_line initialized .BLOCK
    PASS
[TEST] parse_line reserve .BLOCK
    PASS
...

All tests passed!
⚠️ Important Notes
🔹 Do NOT compile both files together

❌ Incorrect:

g++ assembler_block_v2.cpp assembler_block_v2_tests.cpp

✅ Correct:

g++ assembler_block_v2_tests.cpp -o tests
🔹 Why?

The test file already includes the assembler:

#define HASM_UNIT_TEST
#include "assembler_block_v2.cpp"

This prevents:

duplicate definitions
multiple main() errors
🧩 Example Input (sample.hal)
.ALLOC 10

x .DATA =5
nums .BLOCK =3, =7, =17
temp .BLOCK 2

.BEGIN
LOAD x
WRITE x
HALT
.END
🛠️ Error Handling

Errors are written to .log file:

Assembly completed with 1 error(s):

  LINE 4: ERROR - Undefined symbol: missing
📚 Concepts Covered
Two-pass assembler design
Symbol tables
Memory layout
Instruction encoding
Parsing and validation
Unit testing in C++
🧑‍💻 Author

Kalab Markos
Computer Science Graduate Student
Research Focus: Systems, ML, and Software Engineering
