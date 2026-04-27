# Halix Two-Pass Assembler (C++)

A simple C++ implementation of a **two-pass assembler** 

Steps for Running and Cloning Repository from GitHub:
### Step 1a: Clone This Repository in Codio

In a codio terminal run:
git clone [use code web URL in this repository]

###  Step 1b: Move into the Created Folder

cd HALIX

### Step 2: Compile Assembler

g++ -std=c++17 -O2 avengersAssembler.cpp -o assembler

###  Step 3: Run Assembler

./assembler any_inputfile.hal

###  Step 4: Run Dr.Jones' emulator (halix_v25.crun) to generate '.hlt' file. 

chmod 555 *.crun

./halix_v25.crun anyfile.hlx
