# 🌺 Bee-Hive Nectar: Computation Handler Framework

Independent handler framework for writing and testing computation handlers. Nectar is completely decoupled from the network layer (flower), allowing handlers to run as separate processes with their own dependencies.

## Features

✅ **Zero Dependencies on Flower**: Handlers run independently from network layer
✅ **Local Testing**: Test handlers without running network
✅ **Process Isolation**: Each handler runs as its own daemon process
✅ **Multi-Alias Support**: One handler can serve multiple nodes simultaneously
✅ **Dynamic Attachment**: Attach/detach handlers without restarting nodes
✅ **Independent Dependencies**: Each handler can have its own dependencies
✅ **File-Based Communication**: Watches for `.pending` files, writes `.complete` files

## Installation

```bash
# Install nectar (automatically installs bee-hive-core)
uv pip install -e packages/bee-hive-nectar

# Or install all packages
uv pip install -e packages/*
```

## Quick Start

### 1. Write a Handler

```python
# my_handler.py
from nectar import handler, Computation

@handler
def analyze(comp: Computation) -> int:
    """Process computation and return integer result."""
    # Access full computation context
    query_length = len(comp.query)
    proposer = comp.proposer

    # Your custom logic here
    return query_length * 2
```

### 2. Test Locally (No Network Required)

```bash
uv run nectar test my_handler.py

# Output:
# 🧪 Testing handler: my_handler.py
# ✅ Handler loaded successfully
# 📝 Creating mock computation...
# 🔄 Executing handler...
# ✅ Result: 84
# ⏱️  Execution time: 0.002s
# ✅ Handler test passed!
```

### 3. Launch as Daemon

```bash
uv run nectar launch my_handler.py my_handler_v1

# Output:
# ✅ Handler launched: my_handler_v1 (PID 12346)
#    Handler file: /path/to/my_handler.py
#    Status: running
#    Watching: (none - use 'nectar attach' to add aliases)
#    Logs: nectar logs my_handler_v1
```

### 4. Attach to Node(s)

```bash
# Attach to one node
uv run nectar attach my_handler_v1 alice
# ✅ Attached handler 'my_handler_v1' to alias 'alice'

# Attach to another node (same handler serves both)
uv run nectar attach my_handler_v1 bob
# ✅ Attached handler 'my_handler_v1' to alias 'bob'

# View status
uv run nectar view
# Shows: my_handler_v1 (running) watching alice, bob
```

## CLI Commands

### `nectar test <handler_file>`
Test a handler with mock computation (no network required).

```bash
uv run nectar test my_handler.py
```

**What it does**:
- Loads handler from file
- Creates mock `Computation` object
- Executes handler function
- Reports result and execution time
- Validates handler can be loaded and executed

**Use case**: Development and debugging

---

### `nectar launch <handler_file> <name>`
Launch handler as background daemon process.

```bash
uv run nectar launch my_handler.py sentiment_v1
```

**What it does**:
- Validates handler file can be loaded
- Creates handler metadata entry
- Starts background daemon process
- Sets up IPC socket for control commands
- Creates log file

**Requirements**:
- Handler file must exist and be valid
- Handler name must be unique (not already running)

---

### `nectar attach <name> <alias>`
Attach running handler to a node.

```bash
uv run nectar attach sentiment_v1 alice
```

**What it does**:
- Validates handler is running
- Validates node exists (checks `~/.bee-hive/{alias}/data/computation/`)
- Enforces **one handler per alias** rule
- Tells daemon to start watching node's directory
- Handler begins processing `.pending` files for that node

**Important**: Only one handler can be attached to each alias (enforced)

---

### `nectar detach <name> <alias>`
Detach handler from a node.

```bash
uv run nectar detach sentiment_v1 alice
```

**What it does**:
- Tells daemon to stop watching node's directory
- Handler continues running (can still watch other nodes)
- Node accumulates `.pending` files (no processing until reattached)

---

### `nectar view`
List all handlers with status and attachments.

```bash
uv run nectar view
```

**Output**:
```
╔══════════════════════════════════════════════════════════════╗
║                     Nectar Handlers                           ║
╚══════════════════════════════════════════════════════════════╝

  🟢 running  sentiment_v1 (PID 12346)
           Handler: /path/to/my_handler.py
           Watching: alice, bob
           Started: 2025-01-15 14:30:45

  ⚫ stopped  query_length
           Handler: /path/to/simple.py
           Watching: (none)

Total: 2 handler(s), 1 running
```

---

### `nectar logs <name>`
Stream handler logs in real-time.

```bash
uv run nectar logs sentiment_v1
```

**What it does**:
- Streams log file using `tail -f`
- Shows handler activity, errors, and processing
- Press Ctrl+C to exit

**Log location**: `~/.bee-hive/nectar/logs/{name}.log`

---

### `nectar stop <name>`
Stop running handler gracefully.

```bash
uv run nectar stop sentiment_v1
```

**What it does**:
- Sends shutdown command via IPC (graceful)
- Falls back to SIGTERM if IPC fails
- Force kills with SIGKILL if needed (after timeout)
- Updates handler metadata to stopped state

## Handler Architecture

### File-Based Communication

Handlers watch node directories for `.pending` files and write `.complete` files:

```
~/.bee-hive/alice/data/computation/
├── comp_abc123.pending      # Written by flower node
├── comp_abc123.complete     # Written by nectar handler
├── comp_def456.pending
└── comp_def456.complete
```

**Flow**:
1. Flower node writes `{comp_id}.pending` with computation data
2. Handler daemon detects new file via watchdog
3. Handler reads `.pending`, executes `@handler` function
4. Handler writes `{comp_id}.complete` with result
5. Flower node reads `.complete` and sends shares to aggregators

### Process Management

Each handler runs as an independent daemon process:

```
~/.bee-hive/nectar/
├── handlers.json              # Handler metadata
├── handlers/                  # IPC sockets
│   ├── sentiment_v1.sock
│   └── query_length.sock
└── logs/                      # Handler logs
    ├── sentiment_v1.log
    └── query_length.log
```

**Process lifecycle**:
- `launch` → Creates daemon process with PID tracking
- `attach` → Tells daemon to watch node directory
- `detach` → Tells daemon to stop watching directory
- `stop` → Graceful shutdown via IPC → SIGTERM → SIGKILL

### Handler Rules

1. **One handler per alias**: Cannot attach multiple handlers to same node (enforced)
2. **Multi-alias support**: One handler CAN be attached to many nodes
3. **Independent management**: Handlers and nodes managed separately
4. **Graceful degradation**: Nodes work without handlers (accumulate `.pending` files)

## Handler Examples

### Simple Handler

```python
from nectar import handler, Computation

@handler
def query_length(comp: Computation) -> int:
    """Return query length."""
    return len(comp.query)
```

### Handler with External Dependencies

```python
from nectar import handler, Computation
import requests  # External dependency - totally fine!

@handler
def sentiment_analysis(comp: Computation) -> int:
    """Analyze sentiment using external API."""
    response = requests.get(
        "https://api.example.com/sentiment",
        params={"text": comp.query}
    )

    # Return integer score
    return response.json()["score"]
```

### Handler with Computation Context

```python
from nectar import handler, Computation

@handler
def contextual_handler(comp: Computation) -> int:
    """Use full computation context."""
    # Access all computation fields
    query = comp.query
    proposer = comp.proposer
    aggregators = comp.aggregators
    targets = comp.targets
    deadline = comp.deadline
    timestamp = comp.timestamp
    metadata = comp.metadata

    # Your logic here
    score = len(query) * len(targets)
    return score
```

## Troubleshooting

### Handler won't launch
```bash
# Check if handler file is valid
uv run nectar test my_handler.py

# Check if handler name already exists
uv run nectar view
```

### Can't attach handler
```bash
# Check if handler is running
uv run nectar view

# Check if node exists
ls ~/.bee-hive/alice/data/computation/

# Check if another handler is already attached
uv run bee-hive list  # Shows handler info for each node
```

### Handler not processing files
```bash
# Check handler logs
uv run nectar logs my_handler_name

# Check if handler is attached to the right alias
uv run nectar view

# Check for .pending files
ls ~/.bee-hive/alice/data/computation/*.pending
```

## Data Directory Support

Nectar supports the `--data-dir` flag for testing:

```bash
# Production (default ~/.bee-hive)
uv run nectar view

# Testing (explicit ./sandbox)
uv run nectar --data-dir ./sandbox view
```

This allows complete isolation between production and test environments.

## Documentation

- **Package README** (this file): Nectar-specific documentation
- **Root README**: Integration and testing

## License

MIT
