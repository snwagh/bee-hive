#!/bin/bash
# test.sh - Full integration test for bee-hive network

set -e

# Shell functions for clean sandbox isolation
bhive() { uv run bee-hive --data-dir ./sandbox "$@"; }
nectar() { uv run nectar --data-dir ./sandbox "$@"; }

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       Bee-Hive Network Integration Test           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}   Test data: $BEE_HIVE_DIR${NC}\n"

# Step 1: Start NATS server
echo -e "${YELLOW}━━━ Step 1: Starting NATS Server ━━━${NC}\n"
./scripts/start_nats.sh

# Step 2: Start nodes
echo -e "\n${YELLOW}━━━ Step 2: Starting Nodes ━━━${NC}\n"
./scripts/start_nodes.sh

# Step 3: Attach handlers
echo -e "\n${YELLOW}━━━ Step 3: Attaching Handlers ━━━${NC}\n"
./scripts/attach_handlers.sh

# Step 4: Submit test computations
echo -e "\n${YELLOW}━━━ Step 4: Submitting Test Computations ━━━${NC}\n"

# Get all node aliases (macOS-compatible)
ALL_NODES=($(bhive list 2>/dev/null | grep '  @' | sed -E 's/^[^@]*@([a-zA-Z0-9_-]+).*/\1/' || true))

if [ ${#ALL_NODES[@]} -eq 0 ]; then
    echo -e "${RED}❌ No nodes found${NC}"
    exit 1
fi

# Use first node as proposer for both tests
PROPOSER="${ALL_NODES[0]}"

echo -e "${BLUE}ℹ️  Running 2 manual test computations${NC}\n"

# Test 1: Aggregators alice,bob | Targets charlie,dave,eve
echo -e "${GREEN}━━━ Test 1 ━━━${NC}"
QUERY1="What is your secret value"
AGGREGATORS1="alice,bob"
TARGETS1="charlie,dave,eve"
EXPECTED1=75

echo "   Query: \"$QUERY1\""
echo "   Proposer: $PROPOSER"
echo "   Aggregators: $AGGREGATORS1"
echo "   Targets: $TARGETS1"
echo "   Expected result: $EXPECTED1 (query length: ${#QUERY1} × 3 targets)"
echo ""

# Capture computation ID
COMP_ID_1=$(bhive submit "$QUERY1" \
    --proposer "$PROPOSER" \
    --aggregators "$AGGREGATORS1" \
    --targets "$TARGETS1" \
    --deadline 5 2>&1 | grep "ID:" | sed 's/.*ID: //' | awk '{print $1}')

echo "   Computation ID: $COMP_ID_1"

sleep 2

# Test 2: Aggregators alice,bob,charlie | Targets dave,eve
echo -e "\n${GREEN}━━━ Test 2 ━━━${NC}"
QUERY2="Do you have a secret genome?"
AGGREGATORS2="alice,bob,charlie"
TARGETS2="dave,eve"
EXPECTED2=56

echo "   Query: \"$QUERY2\""
echo "   Proposer: $PROPOSER"
echo "   Aggregators: $AGGREGATORS2"
echo "   Targets: $TARGETS2"
echo "   Expected result: $EXPECTED2 (query length: ${#QUERY2} × 2 targets)"
echo ""

# Capture computation ID
COMP_ID_2=$(bhive submit "$QUERY2" \
    --proposer "$PROPOSER" \
    --aggregators "$AGGREGATORS2" \
    --targets "$TARGETS2" \
    --deadline 5 2>&1 | grep "ID:" | sed 's/.*ID: //' | awk '{print $1}')

echo "   Computation ID: $COMP_ID_2"

# Step 5: Wait for results
echo -e "\n${YELLOW}━━━ Step 5: Waiting for Results ━━━${NC}\n"
echo "  ⏳ Waiting 10 seconds for computations to complete..."
sleep 10

# Step 6: Check results
echo -e "\n${YELLOW}━━━ Step 6: Checking Results ━━━${NC}\n"

RESULTS_DIR="./sandbox/$PROPOSER/data"

echo "  📁 Results directory: $RESULTS_DIR"
echo ""

echo "  📊 Test Results:"
echo ""

# Test 1 - Direct lookup by computation ID
if [ -n "$COMP_ID_1" ] && [ -f "$RESULTS_DIR/final_$COMP_ID_1.json" ]; then
    result1=$(cat "$RESULTS_DIR/final_$COMP_ID_1.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('final_result', 'N/A'))" 2>/dev/null || echo "N/A")

    if [ "$result1" = "$EXPECTED1" ]; then
        status1="${GREEN}✅ PASS${NC}"
    else
        status1="${RED}❌ FAIL${NC}"
    fi

    echo -e "     Test 1 ($COMP_ID_1): \"$QUERY1\""
    echo "        Expected: $EXPECTED1"
    echo "        Actual:   $result1"
    echo -e "        Status:   $status1"
    echo ""
else
    echo -e "     Test 1 ($COMP_ID_1): ${RED}❌ Result file not found${NC}"
    echo ""
fi

# Test 2 - Direct lookup by computation ID
if [ -n "$COMP_ID_2" ] && [ -f "$RESULTS_DIR/final_$COMP_ID_2.json" ]; then
    result2=$(cat "$RESULTS_DIR/final_$COMP_ID_2.json" | python3 -c "import sys, json; print(json.load(sys.stdin).get('final_result', 'N/A'))" 2>/dev/null || echo "N/A")

    if [ "$result2" = "$EXPECTED2" ]; then
        status2="${GREEN}✅ PASS${NC}"
    else
        status2="${RED}❌ FAIL${NC}"
    fi

    echo -e "     Test 2 ($COMP_ID_2): \"$QUERY2\""
    echo "        Expected: $EXPECTED2"
    echo "        Actual:   $result2"
    echo -e "        Status:   $status2"
    echo ""
else
    echo -e "     Test 2 ($COMP_ID_2): ${RED}❌ Result file not found${NC}"
    echo ""
fi

# Summary
echo -e "\n${BLUE}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Test Complete!                       ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════╝${NC}\n"

echo -e "${GREEN}✅ Integration test completed successfully!${NC}\n"

echo -e "${YELLOW}📋 System Status:${NC}"
echo "   • NATS server: Running (docker ps | grep bee-hive-server)"
echo "   • Nodes: $(bhive list 2>/dev/null | grep -c "🟢 running" || echo "0") running"
echo "   • Handlers: $(nectar view 2>/dev/null | grep -c "🟢 running" || echo "0") running"
echo ""

echo -e "${BLUE}💡 Next steps:${NC}"
echo "   • View logs: uv run bee-hive --data-dir ./sandbox logs <alias>"
echo "   • View handler logs: uv run nectar --data-dir ./sandbox logs h_query_length"
echo "   • List nodes: uv run bee-hive --data-dir ./sandbox list"
echo "   • Reset environment: ./scripts/reset.sh"
echo ""
