#!/usr/bin/env python3
"""
Bee-Hive Network CLI
Unified command-line interface for managing nodes and submitting computations.
"""
import asyncio
import json
import sys
import os
import getpass
import subprocess
from pathlib import Path
from typing import Dict
import click

# Import the shared identity module
from flower.identity import IdentityManager
from bee_hive_core.config import DEFAULT_NATS_URL, REGISTRY_BUCKET_NAME, REGISTRY_TTL, NATS_CONNECT_TIMEOUT


class NodeManager:
    """Manages node processes."""

    def __init__(self, base_dir: str = None):
        # Data is now stored in base_dir/{alias}/data/
        if base_dir is None:
            base_dir = str(Path.home() / ".bee-hive")
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.pids_file = self.base_dir / "node_pids.json"

    def is_running(self, alias: str) -> bool:
        """Check if node is running."""
        pids = self._load_pids()
        if alias in pids:
            pid = pids[alias]
            try:
                # Check if process exists
                import os
                os.kill(pid, 0)
                return True
            except (OSError, ProcessLookupError):
                # Process doesn't exist, clean up
                del pids[alias]
                self._save_pids(pids)
        return False

    def start_node(self, identity: Dict, nats_url: str = DEFAULT_NATS_URL):
        """Start a node process in the background."""
        alias = identity["alias"]
        node_type = identity["node_type"]
        # Data directory is now ~/.bee-hive/{alias}/data/
        node_data_dir = self.base_dir / alias / "data"
        node_data_dir.mkdir(parents=True, exist_ok=True)

        # Get key paths using static method
        private_key_path, public_key_path = IdentityManager.get_key_paths_for_alias(alias, self.base_dir)

        click.echo(f"🚀 Starting {node_type} node '{alias}'...")

        # Build command to start node
        import sys
        python_exe = sys.executable

        # Get the directory containing the source files
        src_dir = Path(__file__).parent

        # Start process in background
        cmd = [
            python_exe,
            "-c",
            f"""
import json
from pathlib import Path
from flower.{node_type}_node import {node_type.capitalize()}Node
import asyncio

# Initialize node
node = {node_type.capitalize()}Node(
    node_id='{alias}',
    nats_url='{nats_url}',
    data_dir='{node_data_dir}',
    private_key_path='{private_key_path}',
    public_key_path='{public_key_path}'
)

# Run node
asyncio.run(node.run())
"""
        ]

        # Start detached process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True
        )

        # Save PID
        pids = self._load_pids()
        pids[alias] = process.pid
        self._save_pids(pids)

        # Give it a moment to start
        import time
        time.sleep(2)

        if self.is_running(alias):
            click.echo(f"✅ Node '{alias}' started successfully (PID: {process.pid})")
            click.echo(f"   Data directory: {node_data_dir}")
            click.echo(f"   Socket: /tmp/flower-node-{alias}.sock")
        else:
            click.echo(f"❌ Failed to start node '{alias}'")
            # Clean up PID
            pids = self._load_pids()
            if alias in pids:
                del pids[alias]
                self._save_pids(pids)

    def stop_node(self, alias: str) -> bool:
        """Stop a running node process."""
        pids = self._load_pids()

        if alias not in pids:
            return False

        pid = pids[alias]

        try:
            import os
            import signal
            import time

            # Try graceful shutdown first (SIGTERM)
            os.kill(pid, signal.SIGTERM)

            # Wait up to 5 seconds for graceful shutdown
            for _ in range(50):
                try:
                    os.kill(pid, 0)  # Check if still running
                    time.sleep(0.1)
                except (OSError, ProcessLookupError):
                    # Process terminated
                    break
            else:
                # Force kill if still running
                try:
                    os.kill(pid, signal.SIGKILL)
                    time.sleep(0.5)
                except (OSError, ProcessLookupError):
                    pass

            # Clean up PID
            del pids[alias]
            self._save_pids(pids)

            # Clean up socket file
            socket_path = Path(f"/tmp/flower-node-{alias}.sock")
            if socket_path.exists():
                socket_path.unlink()

            return True

        except (OSError, ProcessLookupError):
            # Process doesn't exist, clean up PID anyway
            del pids[alias]
            self._save_pids(pids)
            return False

    def remove_node_data(self, alias: str):
        """Remove computation data for a node."""
        # Data directory is now ~/.bee-hive/{alias}/data/
        node_data_dir = self.base_dir / alias / "data"
        if node_data_dir.exists():
            import shutil
            shutil.rmtree(node_data_dir)
            click.echo(f"[NodeManager] Removed computation data for {alias}")

    def _load_pids(self) -> Dict:
        """Load process IDs."""
        if self.pids_file.exists():
            return json.loads(self.pids_file.read_text())
        return {}

    def _save_pids(self, pids: Dict):
        """Save process IDs."""
        self.pids_file.parent.mkdir(exist_ok=True)
        self.pids_file.write_text(json.dumps(pids, indent=2))


@click.group()
@click.option('--data-dir',
              default=str(Path.home() / '.bee-hive'),
              help='Data directory (default: ~/.bee-hive)')
@click.pass_context
def cli(ctx, data_dir):
    """Bee-Hive Network - Decentralized LLM Computation System"""
    ctx.ensure_object(dict)
    ctx.obj['data_dir'] = data_dir


@cli.command()
@click.option('--nats-url', default=DEFAULT_NATS_URL,
              help='NATS server URL')
@click.option('--alias', help='Node alias (for non-interactive mode)')
@click.option('--email', help='Email address (for non-interactive mode)')
@click.option('--node-type', type=click.Choice(['heavy', 'light'], case_sensitive=False),
              help='Node type (for non-interactive mode)')
@click.option('--password', help='Password (for non-interactive mode)')
@click.pass_context
def register(ctx, nats_url, alias, email, node_type, password):
    """Register a new node on the network."""

    # Interactive mode if any required option is missing
    interactive_mode = not (alias and email and node_type and password)

    if interactive_mode:
        click.echo("╔═══════════════════════════════════════════════════╗")
        click.echo("║         Bee-Hive Network Registration             ║")
        click.echo("╚═══════════════════════════════════════════════════╝\n")

    # Collect information (interactive or use provided flags)
    if not node_type:
        node_type = click.prompt(
            "Node type",
            type=click.Choice(['heavy', 'light'], case_sensitive=False),
            default='light'
        )

    if not alias:
        alias = click.prompt("Alias (node name)")

    if not email:
        email = click.prompt("Email")

    if not password:
        password = getpass.getpass("Password (min 8 characters): ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            click.echo("❌ Passwords do not match", err=True)
            sys.exit(1)

    try:
        data_dir = ctx.obj['data_dir']

        # Check if node already exists locally
        if IdentityManager.node_exists(alias, data_dir):
            click.echo(f"\n⚠️  Node '{alias}' already exists on this machine.")

            # Try to verify with provided password
            try:
                identity_mgr = IdentityManager(alias=alias, base_dir=data_dir)
                identity = identity_mgr.verify_identity(password)
                click.echo(f"✅ Verified identity: @{alias}")

                # Check if node is running
                node_mgr = NodeManager(base_dir=data_dir)
                if node_mgr.is_running(alias):
                    click.echo(f"✅ Node '{alias}' is already running on the network")
                else:
                    click.echo(f"⚠️  Node '{alias}' is not running")
                    # Auto-start in non-interactive mode, otherwise ask
                    should_start = not interactive_mode or click.confirm("Start the node?", default=True)
                    if should_start:
                        node_mgr.start_node(identity, nats_url)

            except ValueError as e:
                click.echo(f"❌ {e}", err=True)
                sys.exit(1)

            return

        # Check if alias is already taken on the network
        click.echo(f"\n🔍 Checking if '@{alias}' is available on the network...")

        try:
            alias_available = asyncio.run(check_alias_available_on_network(alias, nats_url))
        except RuntimeError as e:
            click.echo(f"\n❌ Registration failed: Cannot connect to network", err=True)
            click.echo(f"   {e}", err=True)
            click.echo(f"\n💡 Make sure the NATS server is running:", err=True)
            click.echo(f"   • Local: docker-compose up -d", err=True)
            click.echo(f"   • Remote: Check connection to {nats_url}", err=True)
            sys.exit(1)

        if not alias_available:
            click.echo(f"\n❌ Registration failed: Alias '@{alias}' is already taken on the network", err=True)
            click.echo(f"   Each node must have a unique alias across the entire network", err=True)
            click.echo(f"   Please choose a different alias", err=True)
            sys.exit(1)

        click.echo(f"✅ Alias '@{alias}' is available!")

        # Create new identity (no alias in constructor for creation)
        identity_mgr = IdentityManager(base_dir=data_dir)
        identity = identity_mgr.create_identity(alias, email, password, node_type)

        # Register in NATS KV store
        click.echo(f"📝 Registering alias in network registry...")
        try:
            from datetime import datetime
            metadata = {
                "alias": alias,
                "node_type": node_type,
                "registered_at": datetime.utcnow().timestamp()
            }
            asyncio.run(register_alias_in_registry(alias, nats_url, metadata))
            click.echo(f"✅ Alias registered in network registry")
        except Exception as e:
            # Rollback local identity if network registration fails
            import shutil
            node_dir = Path(data_dir) / alias
            if node_dir.exists():
                shutil.rmtree(node_dir)
            click.echo(f"❌ Failed to register on network: {e}", err=True)
            click.echo(f"   Local identity has been rolled back", err=True)
            sys.exit(1)

        # Start node
        click.echo()
        node_mgr = NodeManager(base_dir=data_dir)
        node_mgr.start_node(identity, nats_url)

        click.echo()
        click.echo("╔═══════════════════════════════════════════════════╗")
        click.echo("║              Registration Complete                ║")
        click.echo("╠═══════════════════════════════════════════════════╣")
        click.echo(f"║ Alias:      @{alias:<39} ║")
        click.echo(f"║ Type:       {node_type:<40} ║")
        click.echo(f"║ Status:     Connected to network{' '*18} ║")
        click.echo("╟───────────────────────────────────────────────────╢")
        click.echo("║ Next steps:                                       ║")
        click.echo("║  • Use 'bee-hive submit' to create computations   ║")
        click.echo("║  • View results in ~/.bee-hive/<alias>/data/      ║")
        click.echo("╚═══════════════════════════════════════════════════╝")

    except ValueError as e:
        click.echo(f"❌ {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('query')
@click.option('--proposer', required=True, help='Proposer node alias')
@click.option('--aggregators', help='Comma-separated list of heavy node aliases')
@click.option('--targets', help='Comma-separated list of target node aliases')
@click.option('--deadline', default=30, help='Deadline in seconds')
@click.pass_context
def submit(ctx, query, proposer, aggregators, targets, deadline):
    """Submit a computation to the network."""

    data_dir = ctx.obj['data_dir']

    # Verify proposer node exists
    if not IdentityManager.node_exists(proposer, data_dir):
        click.echo(f"❌ Proposer node '{proposer}' not found on this machine", err=True)
        click.echo(f"   Run 'bee-hive register' first to create the node", err=True)
        sys.exit(1)

    # Check if node is running
    node_mgr = NodeManager(base_dir=data_dir)
    if not node_mgr.is_running(proposer):
        click.echo(f"❌ Node '{proposer}' is not running", err=True)
        click.echo(f"   Run 'bee-hive register' to start the node", err=True)
        sys.exit(1)

    # Parse lists
    aggregator_list = [a.strip() for a in aggregators.split(',')] if aggregators else []
    target_list = [t.strip() for t in targets.split(',')] if targets else []

    # Send command to node via IPC
    command = {
        'type': 'submit',
        'data': {
            'query': query,
            'aggregators': aggregator_list,
            'targets': target_list,
            'deadline': deadline
        }
    }

    try:
        result = asyncio.run(send_ipc_command(proposer, command))

        if 'error' in result:
            click.echo(f"❌ Error: {result['error']}", err=True)
            sys.exit(1)

        click.echo("✅ Computation submitted")
        click.echo(f"   ID: {result.get('id', 'unknown')}")
        click.echo(f"   Proposer: {proposer}")
        if 'heavy_nodes' in result:
            click.echo(f"   Aggregators: {', '.join(result['heavy_nodes'])}")
        click.echo(f"   Deadline: {deadline}s")
        click.echo(f"\n💡 Results will be saved to: {data_dir}/{proposer}/data/")

    except Exception as e:
        click.echo(f"❌ Failed to submit: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('alias')
@click.pass_context
def peers(ctx, alias):
    """Show known peers for a node (useful for debugging)."""

    data_dir = ctx.obj['data_dir']

    # Check if node exists
    if not IdentityManager.node_exists(alias, data_dir):
        click.echo(f"❌ Node '{alias}' not found", err=True)
        sys.exit(1)

    identity_mgr = IdentityManager(alias=alias, base_dir=data_dir)

    # Get local identity
    local_identity = identity_mgr.get_local_identity()
    click.echo(f"\n╔═══════════════════════════════════════════════════╗")
    click.echo(f"║         Peer Information for @{alias:<24} ║")
    click.echo(f"╚═══════════════════════════════════════════════════╝\n")

    click.echo(f"Local Identity:")
    click.echo(f"  Alias: {local_identity['alias']}")
    click.echo(f"  Type: {local_identity['node_type']}")
    click.echo(f"  Public Key (first 60 chars): {local_identity['public_key'][:60]}...")

    # Get peer identities
    peers = identity_mgr.list_peer_identities()

    if not peers:
        click.echo(f"\n⚠️  No peers discovered yet")
        click.echo(f"   Wait for periodic peer refresh (happens every 30 seconds)")
    else:
        click.echo(f"\nKnown Peers ({len(peers)}):")
        for peer_alias, peer_info in peers.items():
            import datetime
            last_seen = datetime.datetime.fromtimestamp(peer_info.get('last_seen', 0))
            click.echo(f"\n  • {peer_alias} ({peer_info.get('node_type', 'unknown')})")
            click.echo(f"    First seen: {datetime.datetime.fromtimestamp(peer_info.get('first_seen', 0)).strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo(f"    Last seen: {last_seen.strftime('%Y-%m-%d %H:%M:%S')}")
            click.echo(f"    Public key (first 60 chars): {peer_info['public_key'][:60]}...")


@cli.command()
@click.pass_context
def list(ctx):
    """List all registered nodes on this machine."""

    data_dir = ctx.obj['data_dir']

    nodes = IdentityManager.list_local_nodes(data_dir)

    if not nodes:
        click.echo("No nodes registered on this machine")
        click.echo("\n💡 Use 'bee-hive register' to create a new node")
        return

    click.echo("╔═══════════════════════════════════════════════════╗")
    click.echo("║         Registered Nodes on This Machine         ║")
    click.echo("╚═══════════════════════════════════════════════════╝\n")

    node_mgr = NodeManager(base_dir=data_dir)

    # Load handler information
    handlers_file = Path(data_dir) / "nectar" / "handlers.json"
    handlers_data = {}
    if handlers_file.exists():
        try:
            handlers_data = json.loads(handlers_file.read_text())
        except:
            pass

    for node in nodes:
        alias = node["alias"]
        node_type = node["node_type"]
        running = node_mgr.is_running(alias)
        status = "🟢 running" if running else "⚫ stopped"

        click.echo(f"  {status}  @{alias}")
        click.echo(f"           Type: {node_type}")
        click.echo(f"           Email: {node.get('email', 'N/A')}")

        # Show peer count if running
        if running:
            try:
                identity_mgr = IdentityManager(alias=alias, base_dir=data_dir)
                peer_count = len(identity_mgr.list_peer_identities())
                click.echo(f"           Known peers: {peer_count}")
            except:
                pass

        # Show handler info for this alias
        handler_name = None
        handler_status = None
        for h_name, h_data in handlers_data.items():
            if alias in h_data.get("attached_aliases", []):
                handler_name = h_name
                handler_status = h_data.get("status", "unknown")
                break

        if handler_name:
            handler_icon = "✅" if handler_status == "running" else "⚠️"
            click.echo(f"           Handler: {handler_icon} {handler_name} ({handler_status})")
        else:
            click.echo(f"           Handler: (none - attach with 'nectar attach')")

        click.echo()

    click.echo(f"Total: {len(nodes)} node(s)")
    click.echo(f"\n💡 To manage computation handlers: nectar view")


@cli.command()
@click.argument('alias')
@click.pass_context
def logs(ctx, alias):
    """View logs for a running node (tail -f)."""

    data_dir = ctx.obj['data_dir']

    # Check if node exists
    if not IdentityManager.node_exists(alias, data_dir):
        click.echo(f"❌ Node '{alias}' not found", err=True)
        sys.exit(1)

    # Check if log file exists
    log_file = Path(data_dir) / alias / "data" / "node.log"
    if not log_file.exists():
        click.echo(f"❌ Log file not found: {log_file}", err=True)
        click.echo(f"   Node may not have been started yet", err=True)
        sys.exit(1)

    click.echo(f"📜 Viewing logs for node '{alias}' (Ctrl+C to exit)")
    click.echo(f"   Log file: {log_file}\n")

    try:
        # Run tail -f on the log file
        subprocess.run(['tail', '-f', str(log_file)])
    except KeyboardInterrupt:
        click.echo("\n\n👋 Log viewing stopped")
    except FileNotFoundError:
        click.echo("\n❌ 'tail' command not found on this system", err=True)
        sys.exit(1)


@cli.command()
@click.argument('alias')
@click.option('--password', help='Password (for non-interactive mode)')
@click.option('--yes', '-y', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def deregister(ctx, alias, password, yes):
    """Deregister a node from the network and remove all data."""

    data_dir = ctx.obj['data_dir']

    # Interactive mode if password or confirmation not provided
    interactive_mode = not password or not yes

    if interactive_mode:
        click.echo("╔═══════════════════════════════════════════════════╗")
        click.echo("║         Bee-Hive Network Deregistration           ║")
        click.echo("╚═══════════════════════════════════════════════════╝\n")

    # Check if node exists
    if not IdentityManager.node_exists(alias, data_dir):
        click.echo(f"❌ Node '{alias}' not found", err=True)
        sys.exit(1)

    # Get password for verification
    if not password:
        password = getpass.getpass(f"Password for @{alias}: ")

    # Verify password BEFORE showing destructive operation warnings
    try:
        identity_mgr = IdentityManager(alias=alias, base_dir=data_dir)
        identity_mgr.verify_identity(password)
    except ValueError as e:
        click.echo(f"\n❌ {e}", err=True)
        sys.exit(1)

    # Check for attached handlers (only show warning in interactive mode)
    if interactive_mode:
        handlers_file = Path(data_dir) / "nectar" / "handlers.json"
        if handlers_file.exists():
            try:
                handlers_data = json.loads(handlers_file.read_text())
                for h_name, h_data in handlers_data.items():
                    if alias in h_data.get("attached_aliases", []):
                        click.echo(f"\n⚠️  WARNING: Handler '{h_name}' is attached to this node.")
                        click.echo(f"   Consider detaching it first with: nectar detach {h_name} {alias}")
                        click.echo(f"   (Handler will continue running but won't process this node's computations)")
                        break
            except:
                pass

        # Show what will be deleted
        click.echo(f"\n⚠️  WARNING: This will permanently delete:")
        click.echo(f"   • Identity and cryptographic keys ({data_dir}/{alias}/keys/)")
        click.echo(f"   • Computation data ({data_dir}/{alias}/data/)")
        click.echo(f"   • Stop running node process")

    if not yes and not click.confirm("\nAre you sure you want to continue?", default=False):
        click.echo("Deregistration cancelled")
        return

    try:
        node_mgr = NodeManager(base_dir=data_dir)

        # Stop node if running
        if node_mgr.is_running(alias):
            click.echo(f"\n🛑 Stopping node '{alias}'...")
            if node_mgr.stop_node(alias):
                click.echo(f"✅ Node '{alias}' stopped")
            else:
                click.echo(f"⚠️  Node '{alias}' may not have stopped cleanly")
        else:
            click.echo(f"\nℹ️  Node '{alias}' is not running")

        # Remove from network registry
        click.echo(f"📝 Removing alias from network registry...")
        asyncio.run(deregister_alias_from_registry(alias, nats_url=DEFAULT_NATS_URL))
        click.echo(f"✅ Removed from network registry")

        # Remove entire node directory (includes keys, data, identities.json)
        click.echo(f"🗑️  Removing node directory...")
        import shutil
        node_dir = Path(data_dir) / alias
        if node_dir.exists():
            shutil.rmtree(node_dir)
            click.echo(f"✅ Removed {node_dir}")

        click.echo()
        click.echo("╔═══════════════════════════════════════════════════╗")
        click.echo("║         Deregistration Complete                   ║")
        click.echo("╠═══════════════════════════════════════════════════╣")
        click.echo(f"║ Node '{alias}' has been removed from the network  ║")
        click.echo(f"║ All data and keys have been deleted               ║")
        click.echo("╚═══════════════════════════════════════════════════╝")

    except ValueError as e:
        click.echo(f"\n❌ {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n❌ Error: {e}", err=True)
        sys.exit(1)


async def check_alias_available_on_network(alias: str, nats_url: str) -> bool:
    """Check if an alias is available using NATS KV store.

    Returns True if alias is available, False if already taken.
    Raises RuntimeError if network is unreachable.
    """
    import nats
    import msgpack

    try:
        # Connect to NATS
        nc = await nats.connect(nats_url, connect_timeout=NATS_CONNECT_TIMEOUT)
        js = nc.jetstream()

        # Get or create node registry KV bucket
        try:
            kv = await js.key_value(REGISTRY_BUCKET_NAME)
        except:
            # Create if doesn't exist
            kv = await js.create_key_value(
                bucket=REGISTRY_BUCKET_NAME,
                description="Network-wide node alias registry",
                ttl=REGISTRY_TTL,  # Auto-expire after configured TTL (nodes must heartbeat)
            )

        # Check if alias exists
        try:
            entry = await kv.get(alias)
            if entry:
                await nc.close()
                return False  # Alias taken
        except:
            # Key doesn't exist - available!
            pass

        await nc.close()
        return True  # Available

    except Exception as e:
        raise RuntimeError(f"Cannot connect to NATS network at {nats_url}: {e}")


async def register_alias_in_registry(alias: str, nats_url: str, metadata: dict):
    """Register alias in NATS KV store after local identity creation."""
    import nats
    import msgpack

    nc = await nats.connect(nats_url, connect_timeout=NATS_CONNECT_TIMEOUT)
    js = nc.jetstream()

    # Get or create KV bucket
    try:
        kv = await js.key_value(REGISTRY_BUCKET_NAME)
    except:
        kv = await js.create_key_value(
            bucket=REGISTRY_BUCKET_NAME,
            description="Network-wide node alias registry",
            ttl=REGISTRY_TTL,
        )

    # Store alias with metadata (using create for atomicity)
    try:
        await kv.create(alias, msgpack.packb(metadata))
    except:
        # If create fails, key already exists - use put to update
        await kv.put(alias, msgpack.packb(metadata))

    await nc.close()


async def deregister_alias_from_registry(alias: str, nats_url: str):
    """Remove alias from NATS KV registry during deregistration."""
    import nats

    try:
        nc = await nats.connect(nats_url, connect_timeout=NATS_CONNECT_TIMEOUT)
        js = nc.jetstream()
        kv = await js.key_value(REGISTRY_BUCKET_NAME)
        await kv.delete(alias)
        await nc.close()
    except:
        pass  # Best effort cleanup


async def send_ipc_command(node_alias: str, command: dict):
    """Send command to node via Unix socket."""
    socket_path = Path(f"/tmp/flower-node-{node_alias}.sock")

    if not socket_path.exists():
        raise RuntimeError(f"Node '{node_alias}' socket not found")

    reader, writer = await asyncio.open_unix_connection(str(socket_path))

    try:
        writer.write(json.dumps(command).encode())
        await writer.drain()

        data = await reader.read(65536)
        return json.loads(data.decode())
    finally:
        writer.close()
        await writer.wait_closed()


if __name__ == '__main__':
    cli()
