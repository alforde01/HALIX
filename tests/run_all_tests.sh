#!/bin/bash
ASSEMBLER="./halixAssembler"
PASS=0; FAIL=0; TOTAL=0

run_test() {
    local id=$1 file=$2 expect_exit=$3 expect_msg=$4
    TOTAL=$((TOTAL + 1))
    $ASSEMBLER "$file" > /dev/null 2>&1
    actual_exit=$?
    local filename=$(basename "$file" .hal)
    actual_msg=$(cat "${filename}.log" 2>/dev/null)
    if [ "$actual_exit" -eq "$expect_exit" ]; then
        if [ -z "$expect_msg" ] || echo "$actual_msg" | grep -q "$expect_msg"; then
            echo "  PASS  $id"; PASS=$((PASS + 1))
        else
            echo "  FAIL  $id — expected: '$expect_msg'"
            echo "         got: '$actual_msg'"; FAIL=$((FAIL + 1))
        fi
    else
        echo "  FAIL  $id — expected exit $expect_exit, got $actual_exit"
        echo "         log: $actual_msg"; FAIL=$((FAIL + 1))
    fi
}

run_test_file() {
    local id=$1 file=$2 expect_line=$3 expect_content=$4
    TOTAL=$((TOTAL + 1))
    $ASSEMBLER "$file" > /dev/null 2>&1
    local filename=$(basename "$file" .hal)
    actual_line=$(sed -n "${expect_line}p" "${filename}.hlx" 2>/dev/null)
    if [ "$actual_line" = "$expect_content" ]; then
        echo "  PASS  $id"; PASS=$((PASS + 1))
    else
        echo "  FAIL  $id — expected line $expect_line: '$expect_content', got: '$actual_line'"
        FAIL=$((FAIL + 1))
    fi
}

echo "========================================"
echo "  HALIX Assembler - Full Test Suite"
echo "========================================"

echo ""; echo "--- Pass 0: Directive Validation ---"
run_test "TC-P0-01" "tests/tc_p0_01.hal" 0 "NO errors"
run_test "TC-P0-02" "tests/tc_p0_02.hal" 2 "Unknown directive"
run_test "TC-P0-03" "tests/tc_p0_03.hal" 2 "missing size argument"
run_test "TC-P0-04" "tests/tc_p0_04.hal" 2 "not an integer"
run_test "TC-P0-05" "tests/tc_p0_05.hal" 2 "before .ALLOC"
run_test "TC-P0-06" "tests/tc_p0_06.hal" 2 "Second .BEGIN"

echo ""; echo "--- Pass 1: Data Symbol Table ---"
run_test "TC-P1-01" "tests/tc_p1_01.hal" 0 "NO errors"
run_test "TC-P1-02" "tests/tc_p1_02.hal" 0 "NO errors"
run_test "TC-P1-03" "tests/tc_p1_03.hal" 2 "Invalid variable name"
run_test "TC-P1-04" "tests/tc_p1_04.hal" 2 "Duplicate variable"
run_test "TC-P1-05" "tests/tc_p1_05.hal" 2 "only reserved"
run_test "TC-P1-06" "tests/tc_p1_06.hal" 2 "Invalid"
run_test "TC-P1-07" "tests/tc_p1_07.hal" 2 "Invalid"
run_test "TC-P1-08" "tests/tc_p1_08.hal" 0 "NO errors"

echo ""; echo "--- Pass 2a: Mnemonic Validation ---"
run_test "TC-P2a-01" "tests/tc_p2a_01.hal" 0 "NO errors"
run_test "TC-P2a-02" "tests/tc_p2a_02.hal" 2 "Unknown instruction"
run_test "TC-P2a-03" "tests/tc_p2a_03.hal" 2 "Unknown instruction"
run_test "TC-P2a-04" "tests/tc_p2a_04.hal" 0 "NO errors"
run_test "TC-P2a-05" "tests/tc_p2a_05.hal" 2 "Unknown instruction"
run_test "TC-P2a-06" "tests/tc_p2a_06.hal" 2 "Unknown instruction"

echo ""; echo "--- Pass 3: Operand Validation ---"
run_test "TC-P3-01" "tests/tc_p3_01.hal" 0 "NO errors"
run_test "TC-P3-02" "tests/tc_p3_02.hal" 0 "NO errors"
run_test "TC-P3-03" "tests/tc_p3_03.hal" 0 "NO errors"
run_test "TC-P3-04" "tests/tc_p3_04.hal" 3 "Undefined variable"
run_test "TC-P3-05" "tests/tc_p3_05.hal" 3 "label not found"
run_test "TC-P3-06" "tests/tc_p3_06.hal" 3 "requires an operand"
run_test "TC-P3-07" "tests/tc_p3_07.hal" 3 "takes no operand"
run_test "TC-P3-08" "tests/tc_p3_08.hal" 3 "immediate operand"

echo ""; echo "--- Pass 4: Machine Code Generation ---"
# .hlx format: line1=.DATA, line2=data values, line3=.CODE, line4+=instructions
run_test      "TC-P4-01"     "tests/tc_p4_01.hal" 0 "NO errors"
run_test_file "TC-P4-01-hlx" "tests/tc_p4_01.hal" 2 "0300"
run_test      "TC-P4-02"     "tests/tc_p4_02.hal" 0 "NO errors"
run_test_file "TC-P4-02-hlx" "tests/tc_p4_02.hal" 2 "0300"
run_test      "TC-P4-03"     "tests/tc_p4_03.hal" 0 "NO errors"
run_test_file "TC-P4-03-hlx" "tests/tc_p4_03.hal" 2 "2442"
run_test      "TC-P4-04"     "tests/tc_p4_04.hal" 0 "NO errors"
run_test_file "TC-P4-04-hlx" "tests/tc_p4_04.hal" 2 "3500"

echo ""
echo "========================================"
printf "  Results: %d passed, %d failed, %d total\n" $PASS $FAIL $TOTAL
echo "========================================"
if [ "$FAIL" -eq 0 ]; then echo "  ALL TESTS PASSED"; exit 0
else echo "  SOME TESTS FAILED"; exit 1; fi
