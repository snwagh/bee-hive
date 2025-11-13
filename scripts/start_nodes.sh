#!/bin/bash
# start_nodes.sh - Register and start bee-hive nodes for testing

set -e

# Shell function for sandbox isolation
bhive() { uv run bee-hive --data-dir ./sandbox "$@"; }

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🚀 Starting bee-hive nodes...${NC}\n"

# Array of nodes to create: "alias:email:type:password"
NODES=(
    "alice:alice@test.com:heavy:alice-password"
    "bob:bob@test.com:heavy:bob-password"
    "charlie:charlie@test.com:heavy:charlie-password"
    "dave:dave@test.com:light:dave-password"
    "eve:eve@test.com:light:eve-password"
)

echo -e "${BLUE}ℹ️  Registering ${#NODES[@]} nodes with unique passwords${NC}\n"

# Register each node
for node_spec in "${NODES[@]}"; do
    IFS=':' read -r alias email node_type password <<< "$node_spec"

    echo -e "${GREEN}Registering${NC} @$alias ($node_type)..."

    bhive register \
        --alias "$alias" \
        --email "$email" \
        --node-type "$node_type" \
        --password "$password" 2>&1 | grep -E "(✅|⚠️|❌)" || echo "  ✅ Registered"

    # Small delay to avoid overwhelming NATS
    sleep 0.5
done

echo -e "\n${GREEN}✅ All nodes started!${NC}\n"

# Show registered nodes
echo -e "${YELLOW}📋 Registered nodes:${NC}"
bhive list

echo -e "\n${BLUE}💡 Previous step: ${YELLOW}./scripts/start_nats.sh${NC}"
echo -e "${BLUE}💡 Next step: ${YELLOW}./scripts/attach_handlers.sh${BLUE} to attach handlers${NC}\n"
