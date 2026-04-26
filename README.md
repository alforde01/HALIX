# Halix Two-Pass Assembler (C++)

A simple C++ implementation of a **two-pass assembler** 

### Step 1a: Clone This Repository in Codio

In a codio terminal run:
git clone [use code web URL in this repository]

### Step 1: Compile Assembler

g++ -std=c++17 -O2 avengersAssembler.cpp -o assembler

###  Step 2: Move into the Created Folder

cd HALIX

###  Step 3: Run Tests

./assembler_tests

###  Step 4: Run Assembler

./assembler any_inputfile.hal

###  Step 5: Run Dr.Jones' emulator (halix_v25.crun) to generate '.hlt' file. 

./halix_v25.crun anyfile.hlx
