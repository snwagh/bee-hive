#!/bin/bash
# reset.sh - Reset the entire bee-hive test environment

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔄 Resetting bee-hive environment...${NC}\n"

# Use sandbox for testing (matches test.sh)
BEE_HIVE_DIR="./sandbox"

# Aggressive process cleanup - kill ALL bee-hive related processes
echo -e "${GREEN}0.${NC} Aggressive cleanup of all bee-hive processes..."
killed_count=0

# Kill all HeavyNode processes
if pkill -f "HeavyNode" 2>/dev/null; then
    killed_count=$((killed_count + 1))
    echo "  Killed HeavyNode processes"
fi

# Kill all LightNode processes
if pkill -f "LightNode" 2>/dev/null; then
    killed_count=$((killed_count + 1))
    echo "  Killed LightNode processes"
fi

# Kill all nectar daemon processes
if pkill -f "nectar.*daemon" 2>/dev/null; then
    killed_count=$((killed_count + 1))
    echo "  Killed nectar daemon processes"
fi

# Kill any uv run bee-hive processes
if pkill -f "uv run bee-hive" 2>/dev/null; then
    killed_count=$((killed_count + 1))
    echo "  Killed uv run bee-hive processes"
fi

# Kill any uv run nectar processes
if pkill -f "uv run nectar" 2>/dev/null; then
    killed_count=$((killed_count + 1))
    echo "  Killed uv run nectar processes"
fi

if [ $killed_count -eq 0 ]; then
    echo "  ℹ️  No orphaned processes found"
else
    echo "  ✅ Aggressive cleanup complete"
    # Give processes time to terminate
    sleep 1
fi

# Stop all running nodes (from PID tracking)
echo -e "\n${GREEN}1.${NC} Stopping tracked bee-hive nodes..."
if [ -f "$BEE_HIVE_DIR/node_pids.json" ]; then
    # Extract PIDs from JSON and kill them
    cat "$BEE_HIVE_DIR/node_pids.json" | \
    python3 -c "import sys, json; pids = json.load(sys.stdin).values(); [print(p) for p in pids]" | \
    while read pid; do
        if ps -p "$pid" > /dev/null 2>&1; then
            echo "  Stopping node (PID $pid)..."
            kill "$pid" 2>/dev/null || true
        fi
    done
    echo "  ✅ Nodes stopped"
else
    echo "  ℹ️  No running nodes found"
fi

# Stop all running handlers (from PID tracking)
echo -e "\n${GREEN}2.${NC} Stopping tracked nectar handlers..."
if [ -f "$BEE_HIVE_DIR/nectar/handler_pids.json" ]; then
    # Extract PIDs from JSON and kill them
    cat "$BEE_HIVE_DIR/nectar/handler_pids.json" | \
    python3 -c "import sys, json; pids = json.load(sys.stdin).values(); [print(p) for p in pids]" | \
    while read pid; do
        if ps -p "$pid" > /dev/null 2>&1; then
            echo "  Stopping handler (PID $pid)..."
            kill "$pid" 2>/dev/null || true
        fi
    done
    echo "  ✅ Handlers stopped"
else
    echo "  ℹ️  No running handlers found"
fi

# Stop docker compose
echo -e "\n${GREEN}3.${NC} Stopping docker compose..."
if docker ps | grep -q bee-hive-server; then
    docker-compose down
    echo "  ✅ Docker containers stopped"
else
    echo "  ℹ️  Docker container not running"
fi

# Remove NATS data
echo -e "\n${GREEN}4.${NC} Removing NATS data..."
if [ -d "./nats-data" ]; then
    rm -rf ./nats-data
    echo "  ✅ NATS data removed"
else
    echo "  ℹ️  No NATS data found"
fi

# Remove entire sandbox directory (includes test bee-hive data)
echo -e "\n${GREEN}5.${NC} Removing sandbox directory..."
if [ -d "./sandbox" ]; then
    rm -rf ./sandbox
    echo "  ✅ Sandbox removed (including $BEE_HIVE_DIR)"
else
    echo "  ℹ️  No sandbox found"
fi

echo -e "\n${GREEN}✅ Reset complete!${NC}"
echo -e "   You can now run ${YELLOW}./scripts/test.sh${NC} to start fresh\n"
