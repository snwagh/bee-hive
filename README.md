# Bee-Hive: Distributed LLM Computation Network

A decentralized network system where nodes collaborate to process LLM computations using NATS messaging, end-to-end encryption, and MPC-style secret sharing for aggregation.

## Package Structure

The project is organized as a **uv workspace** with three independent packages:

### 📦 bee-hive-core
Core types and configuration shared across all packages.
- `Computation`: Pydantic model for computation requests
- `ComputationResult`: Pydantic model for computation results
- `IntegerResponse`: Response schema
- Shared constants (MODULUS, NATS config)

**Dependencies**: `pydantic` only

### 🌺 bee-hive-nectar
**Independent handler framework** for writing and testing computation handlers.
- `@handler` decorator for creating computation handlers
- Handler validation and testing utilities (`nectar test`)
- Handler daemon process with file watching
- Complete CLI for handler management (launch, attach, detach, logs)
- **Zero dependencies on flower** (completely decoupled)

**Dependencies**: `bee-hive-core`, `watchdog`, `click`, `loguru`

**CLI**: `nectar` command with 7 subcommands

📖 **[See nectar documentation →](packages/bee-hive-nectar/README.md)**

### 🌸 bee-hive-flower
Network layer with identity management, encryption, and node management.
- Node classes (BaseNode, LightNode, HeavyNode)
- NATS-based P2P communication with E2E encryption
- Identity management and key storage
- File-based computation dispatch (writes `.pending`, reads `.complete`)
- CLI for node management
- **No dependency on nectar** (handlers attached at runtime)

**Dependencies**: `bee-hive-core`, `nats-py`, `cryptography`, `loguru`, `msgpack`, `click`

**CLI**: `bee-hive` command with 6 subcommands

📖 **[See flower documentation →](packages/bee-hive-flower/README.md)**

## Architecture Highlights

### Complete Decoupling
- **Handlers are independent services**: Run in separate processes with their own dependencies
- **File-based communication**: Flower nodes write `.pending` files, handlers write `.complete` files
- **Multi-alias support**: One handler can serve multiple nodes simultaneously
- **Dynamic attachment**: Attach/detach handlers without restarting nodes

### Handler Lifecycle
```
1. Write handler with @handler decorator
2. Test: nectar test my_handler.py
3. Launch: nectar launch my_handler.py handler_name
4. Attach: nectar attach handler_name alice
5. Node writes .pending → Handler processes → Handler writes .complete
```

### Data Directory Architecture

**Production** (`~/.bee-hive`):
- Default behavior when no flag specified
- Persistent data across sessions
- Suitable for long-running production nodes

**Testing** (`./sandbox`):
- Explicit `--data-dir ./sandbox` flag
- Isolated test data in project directory
- Clean separation from production
- Easy to reset with `./scripts/reset.sh`

## Installation

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install Docker Desktop and run the daemon
# Required for NATS server

# Clone the repository
cd bee-hive

# Create virtual environment
uv venv -p 3.12
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install packages in development mode
uv pip install -e packages/bee-hive-flower
uv pip install -e packages/bee-hive-nectar

# bee-hive-core is automatically installed as a dependency
```

## Development & Testing

### Developer Installation

After making changes to the codebase, reinstall packages to pick up modifications:

```bash
# Force reinstall all packages in editable mode
uv pip install --force-reinstall -e packages/*

# This reinstalls:
# - packages/bee-hive-core (shared types and config)
# - packages/bee-hive-nectar (handler framework)
# - packages/bee-hive-flower (network layer and CLI)
```

### Running Integration Tests

The project includes automated integration tests in `./scripts/`:

```bash
# Run full integration test (starts NATS, registers nodes, attaches handlers, runs computations)
./scripts/test.sh

# Expected output:
# - 5 nodes registered (alice, bob, charlie, dave, eve)
# - 1 handler attached to all nodes
# - 2 test computations submitted and verified
```

**Test Environment**: Tests run in isolated `./sandbox` directory (separate from production `~/.bee-hive`) and uses a localhost deployed server.

### Individual Test Scripts

```bash
# 1. Start NATS server (required first)
./scripts/start_nats.sh

# 2. Register test nodes (alice, bob, charlie, dave, eve)
./scripts/start_nodes.sh

# 3. Attach example handler to all nodes
./scripts/attach_handlers.sh

# 4. View node status
uv run bee-hive --data-dir ./sandbox list

# 5. View handler status
uv run nectar --data-dir ./sandbox view
```

### Resetting Test Environment

```bash
# Complete cleanup: stops all processes, removes sandbox, resets NATS
./scripts/reset.sh

# Then start fresh:
./scripts/test.sh
```

### Troubleshooting Tests

**Orphaned Processes**:
```bash
# Check for orphaned node processes
ps aux | grep -E "HeavyNode|LightNode"

# Kill all orphaned processes
./scripts/reset.sh  # Includes aggressive process cleanup
```

**Node Count Issues**:
```bash
# Verify correct node count (should be 5 for tests)
uv run bee-hive --data-dir ./sandbox list | grep -c "🟢 running"

# If incorrect, run reset and restart
./scripts/reset.sh
./scripts/test.sh
```

**NATS Server Issues**:
```bash
# Check NATS server status
docker ps | grep bee-hive-server

# Restart NATS server
docker-compose restart

# Full reset (removes NATS data volume)
./scripts/reset.sh
```

## Integration Quick Start

This section shows how the packages work together in a complete workflow.

### 1. Start NATS Server

```bash
docker-compose up -d
```

### 2. Create a Handler (nectar)

```bash
# Create handler file
cat > my_handler.py <<'EOF'
from nectar import handler, Computation

@handler
def analyze(comp: Computation) -> int:
    return len(comp.query) * 2
EOF

# Test it locally (no network required)
uv run nectar test my_handler.py
# Output: ✅ Handler test passed! Result: 84
```

### 3. Register Nodes (flower)

```bash
# Register a heavy node (aggregator)
uv run bee-hive register
# Enter: heavy, h1, h1@example.com, password

# Register a light node (worker)
uv run bee-hive register
# Enter: light, alice, alice@example.com, password

# List nodes
uv run bee-hive list
# Shows: 2 nodes (h1, alice)
```

### 4. Launch and Attach Handler (nectar)

```bash
# Launch handler as daemon
uv run nectar launch my_handler.py sentiment_v1

# Attach to nodes
uv run nectar attach sentiment_v1 alice
uv run nectar attach sentiment_v1 h1

# View handler status
uv run nectar view
# Shows: sentiment_v1 (running) watching alice, h1
```

### 5. Submit Computation (flower)

```bash
# Submit computation
uv run bee-hive submit "Test query" \
  --proposer alice \
  --aggregators h1 \
  --targets alice,h1 \
  --deadline 30

# Watch handler process it
uv run nectar logs sentiment_v1

# Check results (after deadline)
cat ~/.bee-hive/alice/data/final_*.json
```

## Package Communication Flow

```
User Command
    ↓
┌─────────────────────────────────────────────────────────┐
│ bee-hive submit (flower CLI)                           │
│ - Creates computation                                   │
│ - Sends to aggregator via IPC                          │
└─────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────┐
│ HeavyNode (flower)                                      │
│ - Distributes to targets via NATS                      │
│ - Receives shares from workers                         │
└─────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────┐
│ LightNode (flower)                                      │
│ - Receives computation via NATS                        │
│ - Writes .pending file                                 │
└─────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────┐
│ Handler Daemon (nectar)                                 │
│ - Watches for .pending files                           │
│ - Executes @handler function                           │
│ - Writes .complete file                                │
└─────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────┐
│ LightNode (flower)                                      │
│ - Reads .complete file                                 │
│ - Generates secret shares                              │
│ - Sends shares to aggregators via NATS                 │
└─────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────┐
│ HeavyNode (flower)                                      │
│ - Aggregates shares                                     │
│ - Sends to proposer via NATS                           │
└─────────────────────────────────────────────────────────┘
    ↓
┌─────────────────────────────────────────────────────────┐
│ Proposer (flower)                                       │
│ - Final aggregation                                     │
│ - Writes result to disk                                │
└─────────────────────────────────────────────────────────┘
```

## Key Features

✅ **Complete Decoupling**: Handlers run independently from network layer
✅ **Zero Downtime**: Attach/detach handlers without restarting nodes
✅ **Multi-Alias Support**: One handler can serve multiple nodes
✅ **Local Testing**: Test handlers without running network
✅ **Independent Dependencies**: Each handler can have its own dependencies
✅ **Process Isolation**: Handler crashes don't affect network
✅ **One Handler Per Alias**: Enforced to prevent conflicts
✅ **Graceful Degradation**: Nodes work without handlers (accumulate `.pending` files)
✅ **Cross-Machine Support**: Nodes can run on different physical machines
✅ **E2E Encryption**: Hybrid RSA + AES encryption for all messages

## Architecture Diagram

```
~/.bee-hive/
├── nectar/                    # Independent handler service
│   ├── handlers.json          # Handler metadata
│   ├── handlers/              # IPC sockets
│   │   └── sentiment_v1.sock
│   └── logs/                  # Handler logs
│       └── sentiment_v1.log
│
├── alice/                     # Node data (flower)
│   ├── identities.json        # Node's view of network
│   ├── keys/
│   │   ├── private_key.pem
│   │   └── public_key.pem
│   └── data/
│       ├── local.db
│       ├── node.log
│       ├── computation/       # Handler watches this
│       │   ├── *.pending      # Written by node
│       │   └── *.complete     # Written by handler
│       └── final_*.json       # Aggregated results
│
└── bob/                       # Another node
    └── ...
```

## Examples

See `examples/` directory:
- `example_handlers/handler_query_length.py` - Example handler used in tests
- More examples coming soon

## Documentation

- **README.md** (this file): Integration, testing, and quick start
- **[packages/bee-hive-nectar/README.md](packages/bee-hive-nectar/README.md)**: Nectar-specific documentation
- **[packages/bee-hive-flower/README.md](packages/bee-hive-flower/README.md)**: Flower-specific documentation

## License

MIT
