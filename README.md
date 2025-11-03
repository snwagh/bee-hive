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

## Architecture Highlights

### Complete Decoupling
- **Handlers are independent services**: Run in separate processes with their own dependencies
- **File-based communication**: Nodes write `.pending` files, handlers write `.complete` files
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

## Installation

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

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

## Quick Start

### 1. Test a Handler (No Network Required)

```bash
# Create handler
cat > my_handler.py <<'EOF'
from nectar import handler, Computation

@handler
def analyze(comp: Computation) -> int:
    return len(comp.query) * 2
EOF

# Test it
uv run nectar test my_handler.py
# Output: ✅ Handler test passed! Result: 42
```

### 2. Run the Full System

**Start NATS server:**
```bash
docker-compose up -d
```

**Register nodes:**
```bash
# Register a heavy node
uv run bee-hive register
# Enter: heavy, h1, h1@example.com, password

# Register a light node
uv run bee-hive register
# Enter: light, alice, alice@example.com, password

# List nodes
uv run bee-hive list
# Shows nodes with handler info
```

**Launch and attach handler:**
```bash
# Launch handler daemon
uv run nectar launch my_handler.py sentiment_v1

# Attach to node
uv run nectar attach sentiment_v1 alice

# View handler status
uv run nectar view
# Shows: sentiment_v1 (running) watching alice
```

**Submit computation:**
```bash
# Submit computation
uv run bee-hive submit "Test query" \
  --proposer alice \
  --aggregators h1 \
  --targets alice,h1 \
  --deadline 30

# Watch handler logs
uv run nectar logs sentiment_v1

# Check results
cat ~/.bee-hive/alice/data/final_*.json
```

## CLI Commands

### bee-hive (Node Management)
```bash
uv run bee-hive list         # List nodes with handler info
uv run bee-hive register     # Register new node (interactive)
uv run bee-hive submit       # Submit computation
uv run bee-hive logs <alias> # View node logs
uv run bee-hive peers <alias> # Show known peers (debugging)
uv run bee-hive deregister   # Remove node (password required)
```

### nectar (Handler Management)
```bash
uv run nectar test <file>           # Test handler locally
uv run nectar launch <file> <name>  # Launch handler daemon
uv run nectar attach <name> <alias> # Attach to node (one per alias)
uv run nectar detach <name> <alias> # Detach from node
uv run nectar view                  # List all handlers
uv run nectar logs <name>           # Stream handler logs
uv run nectar stop <name>           # Stop handler daemon
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

## Examples

See `examples/` directory:
- `example_handler.py` - Example custom handler with external dependencies
- `test_handler.py` - Standalone testing without network

## Documentation

- **README.md** (this file): Quick start and package overview
- **claude.md**: Complete system design, architecture details, and comprehensive documentation

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
├── alice/                     # Node data
│   ├── identities.json
│   ├── keys/
│   └── data/
│       ├── computation/       # Handler watches this
│       │   ├── *.pending      # Written by node
│       │   └── *.complete     # Written by handler
│       └── final_*.json
│
└── bob/                       # Another node
    └── ...
```

## License

MIT
