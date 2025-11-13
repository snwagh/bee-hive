# 🌸 Bee-Hive Flower: Network Layer

Network layer with identity management, encryption, and node management. Flower handles all peer-to-peer communication, identity management, and computation coordination.

## Features

✅ **NATS-Based P2P Communication**: Secure messaging with end-to-end encryption
✅ **Identity Management**: RSA-2048 key generation and persistent peer discovery
✅ **Hybrid Encryption**: RSA for key exchange, AES-256 for data
✅ **Node Types**: Heavy (aggregators) and Light (workers) nodes
✅ **MPC-Style Aggregation**: Privacy-preserving secret sharing
✅ **Cross-Machine Support**: Nodes can run on different physical machines
✅ **File-Based Computation Dispatch**: Writes `.pending` files for handler processing

## Installation

```bash
# Install flower (automatically installs bee-hive-core)
uv pip install -e packages/bee-hive-flower

# Or install all packages
uv pip install -e packages/*

# Requires NATS server
docker-compose up -d
```

## Quick Start

### 1. Register a Node

```bash
uv run bee-hive register

# Interactive prompts:
# Node type (heavy/light): heavy
# Alias: alice
# Email: alice@example.com
# Password: ********

# Output:
# ✅ Alias '@alice' is available!
# [Identity] Generating cryptographic keypair for @alice...
# [Identity] Keys stored in: ~/.bee-hive/alice/keys
# ✅ Alias registered in network registry
# ✅ Node 'alice' started successfully (PID 12345)
```

**What this does**:
- Validates alias uniqueness across entire network
- Generates RSA-2048 keypair
- Creates identity in `~/.bee-hive/{alias}/`
- Starts node daemon process
- Registers with NATS network

### 2. List Nodes

```bash
uv run bee-hive list

# Output:
# ╔═══════════════════════════════════════════════════╗
# ║         Registered Nodes on This Machine         ║
# ╚═══════════════════════════════════════════════════╝
#
#   🟢 running  @alice
#            Type: heavy
#            Email: alice@example.com
#            Known peers: 3
#            Handler: ✅ sentiment_v1 (running)
#
# Total: 1 node(s)
```

### 3. Submit Computation

```bash
uv run bee-hive submit "Your query text" \
  --proposer alice \
  --aggregators h1,h2 \
  --targets alice,bob,h1,h2 \
  --deadline 30

# Output:
# ✅ Computation submitted successfully
#    ID: comp_1234567890
#    Proposer: alice
#    Aggregators: h1, h2
#    Targets: alice, bob, h1, h2
#    Deadline: 30 seconds
```

## CLI Commands

### `bee-hive register`
Interactive node registration.

```bash
uv run bee-hive register
```

**What it does**:
- Prompts for node type (heavy/light), alias, email, password
- Validates alias uniqueness across entire network (not just local)
- Generates RSA-2048 keypair with file permission protection
- Creates identity directory `~/.bee-hive/{alias}/`
- Stores keys in `~/.bee-hive/{alias}/keys/`
- Creates `identities.json` with local identity
- Starts node daemon process
- Registers with NATS network

**Requirements**:
- NATS server must be running
- Alias must be unique across network
- Password minimum 8 characters (optional for testing)

**Files created**:
```
~/.bee-hive/alice/
├── identities.json           # Node's view of network
├── keys/
│   ├── private_key.pem      # RSA-2048 private key (0600)
│   └── public_key.pem       # RSA-2048 public key (0644)
└── data/
    ├── local.db             # SQLite database
    ├── node.log             # Node logs
    ├── computation/         # Handler watches this
    └── final_*.json         # Aggregated results
```

---

### `bee-hive list`
List all registered nodes on this machine.

```bash
uv run bee-hive list
```

**Output includes**:
- Node status (running/stopped)
- Node type (heavy/light)
- Email address
- Known peer count
- Attached handler (if any)

**Example output**:
```
  🟢 running  @alice
           Type: heavy
           Email: alice@example.com
           Known peers: 4
           Handler: ✅ sentiment_v1 (running)

  ⚫ stopped  @bob
           Type: light
           Email: bob@example.com
           Handler: (none - attach with 'nectar attach')
```

---

### `bee-hive submit <query>`
Submit computation to network.

```bash
uv run bee-hive submit "What is your secret value" \
  --proposer alice \
  --aggregators h1,h2 \
  --targets alice,bob,charlie \
  --deadline 30
```

**Arguments**:
- `query`: Text query to process
- `--proposer`: Node that receives final result
- `--aggregators`: Comma-separated list of heavy nodes (receive shares)
- `--targets`: Comma-separated list of nodes to execute query
- `--deadline`: Seconds to wait for results (default: 30)

**What it does**:
- Validates proposer identity exists locally
- Creates unique computation ID
- Sends computation to first aggregator via IPC
- Returns computation ID for tracking

---

### `bee-hive logs <alias>`
View node logs in real-time.

```bash
uv run bee-hive logs alice
```

**What it does**:
- Streams log file using `tail -f`
- Shows node activity, peer discovery, computation flow
- Press Ctrl+C to exit

**Log location**: `~/.bee-hive/{alias}/data/node.log`

**Useful for**:
- Debugging network connectivity
- Monitoring computation flow
- Investigating decryption errors

---

### `bee-hive peers <alias>`
Show known peers for a node (debugging).

```bash
uv run bee-hive peers alice
```

**What it does**:
- Displays local identity
- Lists all discovered peers
- Shows public key previews
- Shows last seen timestamps

**Output**:
```
╔═══════════════════════════════════════════════════╗
║         Known Peers for @alice                   ║
╚═══════════════════════════════════════════════════╝

Local Identity:
  Alias: alice
  Type: local
  Node Type: heavy
  Email: alice@example.com

Peer Identities (4):

  🟢 bob (heavy)
    Last seen: 2025-01-15 14:30:45
    Public key (first 60 chars): LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K...
```

**Use case**: Debugging decryption errors and peer discovery issues

---

### `bee-hive deregister <alias>`
Remove node and all data (destructive).

```bash
uv run bee-hive deregister alice
```

**What it does**:
- Prompts for password verification
- Warns if handler is attached
- Stops node process (SIGTERM → SIGKILL)
- Removes entire `~/.bee-hive/{alias}/` directory
- Cleans up PID registry
- Requires explicit confirmation

**⚠️ Warning**: This permanently deletes all node data including:
- Identity and keys
- Computation history
- Results
- Logs

## Node Architecture

### Node Types

**Heavy Nodes** (`HeavyNode`):
- Act as aggregators (receive shares from workers)
- Can also execute computations (inherit from `LightNode`)
- Coordinate computation distribution
- Sum shares and send to proposer
- Discover other heavy nodes for coordination

**Light Nodes** (`LightNode`):
- Execute computations (call handler)
- Generate secret shares (MPC-style)
- Send shares to aggregators
- Can propose computations

### Computation Flow

```
1. Proposal Phase
   User → bee-hive submit → Proposer node → First aggregator

2. Broadcast Phase
   First aggregator → Target nodes (point-to-point)

3. Execution Phase
   Target nodes → Write .pending file → Handler processes → .complete file

4. Secret Sharing
   Target nodes → Generate shares (modulo 2^32)
   Number of shares = Number of aggregators

5. Distribution
   Target nodes → Send one share to each aggregator (encrypted)

6. Local Aggregation
   Aggregators → Sum received shares (modulo 2^32)

7. Return Phase
   Aggregators → Send aggregated values to proposer (encrypted)

8. Final Aggregation
   Proposer → Sum all aggregated values (modulo 2^32)
   Proposer → Write final result to disk
```

### Identity Management

Each node maintains `~/.bee-hive/{alias}/identities.json`:

```json
{
  "alice": {
    "type": "local",
    "alias": "alice",
    "email": "alice@example.com",
    "password_hash": "...",
    "public_key": "...",
    "node_type": "heavy"
  },
  "bob": {
    "type": "peer",
    "alias": "bob",
    "public_key": "...",
    "node_type": "light",
    "first_seen": 1234567890.123,
    "last_seen": 1234567900.456
  }
}
```

**Benefits**:
- **Persistent peer discovery**: Peers survive node restarts
- **Cross-machine support**: Nodes on different machines
- **Clean separation**: Node-level vs machine-level concerns

### Encryption

**Hybrid Encryption** (RSA + AES):

1. **Key Exchange**: RSA-2048 public keys exchanged via NATS
2. **Message Encryption**:
   - Generate random AES-256 key per message
   - Encrypt data with AES-CBC
   - Encrypt AES key with recipient's RSA public key
   - Send encrypted data + encrypted key + IV
3. **Message Decryption**:
   - Decrypt AES key with own RSA private key
   - Decrypt data with AES key

**Security**:
- Per-message encryption (new AES key each time)
- RSA-2048 keys (4096-bit security)
- AES-256 (military-grade encryption)
- File permissions (0600 for private keys)

### Peer-to-Peer Communication

**Point-to-point channels** (no broadcast for computation data):

```
# Computation Messages
comp.proposal.{aggregator_id}     - Send to specific aggregator
comp.broadcast.{target_id}        - Send to specific target
comp.result.{aggregator_id}       - Send share to aggregator
comp.final.{proposer_id}          - Send result to proposer

# Infrastructure Messages (shared channels)
node.register                     - Announce presence + public key
node.discover.*                   - Peer discovery
```

## Configuration

All configuration in `bee-hive-core/src/bee_hive_core/config.py`:

```python
DEFAULT_NATS_URL = "nats://localhost:4222"  # NATS server endpoint
REGISTRY_BUCKET_NAME = "node_registry"      # KV bucket name
REGISTRY_TTL = 3600                         # Alias TTL (1 hour)
HEARTBEAT_INTERVAL = 600                    # Heartbeat every 10 min
PEER_REFRESH_INTERVAL = 30                  # Refresh peers every 30s
MODULUS = 2**32                             # Secret sharing modulus
```

To use remote NATS server:
```python
DEFAULT_NATS_URL = "nats://20.81.248.221:4222"
```

## Data Directory Support

Flower supports the `--data-dir` flag for testing:

```bash
# Production (default ~/.bee-hive)
uv run bee-hive register
uv run bee-hive list

# Testing (explicit ./sandbox)
uv run bee-hive --data-dir ./sandbox register
uv run bee-hive --data-dir ./sandbox list
```

**Benefits**:
- Complete isolation between production and test
- Easy cleanup with `./scripts/reset.sh`
- Multiple test environments possible

## Troubleshooting

### Registration fails: "Alias already exists"
```bash
# Check if alias is taken on network
uv run bee-hive register  # Will validate before creating

# Use different alias or deregister existing node
uv run bee-hive deregister alice
```

### Registration fails: "Network unreachable"
```bash
# Check NATS server is running
docker ps | grep bee-hive-server

# Start NATS server
docker-compose up -d

# Check NATS connectivity
docker logs bee-hive-server
```

### Decryption errors
```bash
# Check peer public keys
uv run bee-hive peers alice

# Likely causes:
# 1. Peer re-registered with new keys (key rotation)
# 2. Node restarted and lost peer keys (should reload from identities.json)

# Fix: Restart both nodes to re-exchange keys
uv run bee-hive deregister alice
uv run bee-hive deregister bob
uv run bee-hive register  # Re-register both
```

### Node not processing computations
```bash
# Check if handler is attached
uv run bee-hive list  # Shows handler info

# Check node logs
uv run bee-hive logs alice

# Check for .pending files
ls ~/.bee-hive/alice/data/computation/*.pending
```

## Documentation

- **Package README** (this file): Flower-specific documentation
- **Root README**: Integration and testing

## License

MIT
