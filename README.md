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
