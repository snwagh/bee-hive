#!/bin/bash
# start_nats.sh - Start NATS server via docker-compose

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🚀 Starting NATS Server...${NC}\n"

if docker ps | grep -q bee-hive-server; then
    echo -e "  ${BLUE}ℹ️  NATS server already running${NC}"
else
    echo "  🐳 Starting docker-compose..."
    docker-compose up -d

    echo "  ⏳ Waiting for NATS to be ready..."
    sleep 3

    echo -e "  ${GREEN}✅ NATS server started${NC}"
fi

echo ""
