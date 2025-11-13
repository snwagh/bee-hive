#!/bin/bash
# attach_handlers.sh - Launch and attach handlers to nodes

set -e

# Shell functions for sandbox isolation
bhive() { uv run bee-hive --data-dir ./sandbox "$@"; }
nectar() { uv run nectar --data-dir ./sandbox "$@"; }

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔗 Setting up handlers...${NC}\n"

# Use existing handler from example_handlers folder
HANDLER_FILE="example_handlers/handler_query_length.py"

if [ ! -f "$HANDLER_FILE" ]; then
    echo -e "${RED}❌ Handler file not found: $HANDLER_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}1.${NC} Using handler: $HANDLER_FILE"

# Test the handler
echo -e "\n${GREEN}2.${NC} Testing handler..."
nectar test "$HANDLER_FILE" | grep -E "(✅|❌)" || true

# Launch handler
echo -e "\n${GREEN}3.${NC} Launching handler daemon..."
HANDLER_NAME="h_query_length"

# Check if handler is already running
if nectar view 2>/dev/null | grep -q "$HANDLER_NAME.*running"; then
    echo "  ℹ️  Handler '$HANDLER_NAME' already running, reusing it..."
else
    # Check if handler exists but stopped
    if nectar view 2>/dev/null | grep -q "$HANDLER_NAME"; then
        echo "  ℹ️  Handler exists but stopped, cleaning up..."

        # Remove handler metadata manually
        echo "     Removing handler metadata..."
        python3 << EOF
import json
from pathlib import Path

handlers_file = Path('./sandbox/nectar/handlers.json')

if handlers_file.exists():
    handlers = json.loads(handlers_file.read_text())
    if '$HANDLER_NAME' in handlers:
        del handlers['$HANDLER_NAME']
        handlers_file.write_text(json.dumps(handlers, indent=2))
        print("     ✅ Removed handler metadata")
EOF
        sleep 0.5
    fi

    # Launch new handler
    nectar launch "$HANDLER_FILE" "$HANDLER_NAME"

    # Small delay for daemon to start
    sleep 1
fi

# Attach handler to all nodes
echo -e "\n${GREEN}4.${NC} Attaching handler to nodes..."

# Get list of all registered nodes (macOS-compatible)
NODES=($(bhive list 2>/dev/null | grep '  @' | sed -E 's/^[^@]*@([a-zA-Z0-9_-]+).*/\1/' || true))

if [ ${#NODES[@]} -eq 0 ]; then
    echo -e "${YELLOW}  ⚠️  No nodes found. Run ./scripts/start_nodes.sh first${NC}"
    exit 1
fi

for alias in "${NODES[@]}"; do
    echo "  Attaching to @$alias..."
    nectar attach "$HANDLER_NAME" "$alias" 2>&1 | grep -E "(✅|❌|already)" || echo "    ✅ Attached"
done

echo -e "\n${GREEN}✅ Handlers configured!${NC}\n"

# Show handler status
echo -e "${YELLOW}📋 Handler status:${NC}"
nectar view

echo -e "\n${BLUE}💡 Next step: Run ${YELLOW}./scripts/test.sh${BLUE} to submit test computations${NC}\n"
