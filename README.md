# Bee-Hive Network

Distributed LLM computation system with end-to-end encryption and MPC-style aggregation.

## Quick Start

See `claude.md` for full documentation.

### CLI Commands

```bash
# List all nodes on this machine
uv run bee-hive list

# Register a new node
uv run bee-hive register

# View node's known peers (debugging)
uv run bee-hive peers <alias>

# Submit computation
uv run bee-hive submit "query" --proposer <alias> --aggregators <list> --targets <list> --deadline 30

# View logs
uv run bee-hive logs <alias>

# Deregister node
uv run bee-hive deregister <alias>
```