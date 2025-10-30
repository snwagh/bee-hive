#!/usr/bin/env python3
"""
Bee-Hive Network CLI
Unified command-line interface for managing nodes and submitting computations.
"""
import asyncio
import json
import sys
import getpass
import subprocess
from pathlib import Path
from typing import Dict
import click

# Import the shared identity module
from identity import IdentityManager


class NodeManager:
    """Manages node processes."""

    def __init__(self):
        # Data is now stored in ~/.bee-hive/{alias}/data/
        self.base_dir = Path.home() / ".bee-hive"
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

    def start_node(self, identity: Dict, nats_url: str = "nats://20.81.248.221:4222"):
        """Start a node process in the background."""
        alias = identity["alias"]
        node_type = identity["node_type"]
        # Data directory is now ~/.bee-hive/{alias}/data/
        node_data_dir = self.base_dir / alias / "data"
        node_data_dir.mkdir(parents=True, exist_ok=True)

        # Get key paths using static method
        private_key_path, public_key_path = IdentityManager.get_key_paths_for_alias(alias)

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
import sys
sys.path.insert(0, '{src_dir}')
from {node_type}_node import {node_type.capitalize()}Node
import asyncio

node = {node_type.capitalize()}Node(
    node_id='{alias}',
    nats_url='{nats_url}',
    data_dir='{node_data_dir}',
    private_key_path='{private_key_path}',
    public_key_path='{public_key_path}'
)
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
def cli():
    """Bee-Hive Network - Decentralized LLM Computation System"""
    pass


@cli.command()
@click.option('--nats-url', default='nats://20.81.248.221:4222',
              help='NATS server URL')
def register(nats_url):
    """Register a new node on the network."""

    click.echo("╔═══════════════════════════════════════════════════╗")
    click.echo("║         Bee-Hive Network Registration             ║")
    click.echo("╚═══════════════════════════════════════════════════╝\n")

    # Collect information
    node_type = click.prompt(
        "Node type",
        type=click.Choice(['heavy', 'light'], case_sensitive=False),
        default='light'
    )

    alias = click.prompt("Alias (node name)")

    email = click.prompt("Email")

    password = getpass.getpass("Password (min 8 characters): ")
    password_confirm = getpass.getpass("Confirm password: ")

    if password != password_confirm:
        click.echo("❌ Passwords do not match", err=True)
        sys.exit(1)

    try:
        # Check if node already exists locally
        if IdentityManager.node_exists(alias):
            click.echo(f"\n⚠️  Node '{alias}' already exists on this machine.")

            # Try to verify with provided password
            try:
                identity_mgr = IdentityManager(alias=alias)
                identity = identity_mgr.verify_identity(password)
                click.echo(f"✅ Verified identity: @{alias}")

                # Check if node is running
                node_mgr = NodeManager()
                if node_mgr.is_running(alias):
                    click.echo(f"✅ Node '{alias}' is already running on the network")
                else:
                    click.echo(f"⚠️  Node '{alias}' is not running")
                    if click.confirm("Start the node?", default=True):
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
        identity_mgr = IdentityManager()
        identity = identity_mgr.create_identity(alias, email, password, node_type)

        # Start node
        click.echo()
        node_mgr = NodeManager()
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
def submit(query, proposer, aggregators, targets, deadline):
    """Submit a computation to the network."""

    # Verify proposer node exists
    if not IdentityManager.node_exists(proposer):
        click.echo(f"❌ Proposer node '{proposer}' not found on this machine", err=True)
        click.echo(f"   Run 'bee-hive register' first to create the node", err=True)
        sys.exit(1)

    # Check if node is running
    node_mgr = NodeManager()
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
        click.echo(f"\n💡 Results will be saved to: ~/.bee-hive/{proposer}/data/")

    except Exception as e:
        click.echo(f"❌ Failed to submit: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('alias')
def peers(alias):
    """Show known peers for a node (useful for debugging)."""

    # Check if node exists
    if not IdentityManager.node_exists(alias):
        click.echo(f"❌ Node '{alias}' not found", err=True)
        sys.exit(1)

    identity_mgr = IdentityManager(alias=alias)

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
def list():
    """List all registered nodes on this machine."""

    nodes = IdentityManager.list_local_nodes()

    if not nodes:
        click.echo("No nodes registered on this machine")
        click.echo("\n💡 Use 'bee-hive register' to create a new node")
        return

    click.echo("╔═══════════════════════════════════════════════════╗")
    click.echo("║         Registered Nodes on This Machine         ║")
    click.echo("╚═══════════════════════════════════════════════════╝\n")

    node_mgr = NodeManager()

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
                identity_mgr = IdentityManager(alias=alias)
                peer_count = len(identity_mgr.list_peer_identities())
                click.echo(f"           Known peers: {peer_count}")
            except:
                pass

        click.echo()

    click.echo(f"Total: {len(nodes)} node(s)")


@cli.command()
@click.argument('alias')
def logs(alias):
    """View logs for a running node (tail -f)."""

    # Check if node exists
    if not IdentityManager.node_exists(alias):
        click.echo(f"❌ Node '{alias}' not found", err=True)
        sys.exit(1)

    # Check if log file exists
    log_file = Path.home() / ".bee-hive" / alias / "data" / "node.log"
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
def deregister(alias):
    """Deregister a node from the network and remove all data."""

    click.echo("╔═══════════════════════════════════════════════════╗")
    click.echo("║         Bee-Hive Network Deregistration           ║")
    click.echo("╚═══════════════════════════════════════════════════╝\n")

    # Check if node exists
    if not IdentityManager.node_exists(alias):
        click.echo(f"❌ Node '{alias}' not found", err=True)
        sys.exit(1)

    # Get password for verification
    password = getpass.getpass(f"Password for @{alias}: ")

    # Verify password BEFORE showing destructive operation warnings
    try:
        identity_mgr = IdentityManager(alias=alias)
        identity_mgr.verify_identity(password)
    except ValueError as e:
        click.echo(f"\n❌ {e}", err=True)
        sys.exit(1)

    # Show what will be deleted
    click.echo(f"\n⚠️  WARNING: This will permanently delete:")
    click.echo(f"   • Identity and cryptographic keys (~/.bee-hive/{alias}/keys/)")
    click.echo(f"   • Computation data (~/.bee-hive/{alias}/data/)")
    click.echo(f"   • Stop running node process")

    if not click.confirm("\nAre you sure you want to continue?", default=False):
        click.echo("Deregistration cancelled")
        return

    try:
        node_mgr = NodeManager()

        # Stop node if running
        if node_mgr.is_running(alias):
            click.echo(f"\n🛑 Stopping node '{alias}'...")
            if node_mgr.stop_node(alias):
                click.echo(f"✅ Node '{alias}' stopped")
            else:
                click.echo(f"⚠️  Node '{alias}' may not have stopped cleanly")
        else:
            click.echo(f"\nℹ️  Node '{alias}' is not running")

        # Remove entire node directory (includes keys, data, identities.json)
        click.echo(f"🗑️  Removing node directory...")
        import shutil
        node_dir = Path.home() / ".bee-hive" / alias
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
    """Check if an alias is already taken on the network.

    Returns True if alias is available, False if already taken.
    Raises RuntimeError if network is unreachable.
    """
    import nats
    import msgpack

    try:
        # Connect to NATS temporarily
        nc = await nats.connect(nats_url, connect_timeout=5)

        # Subscribe to a temporary inbox for responses
        responses = []

        async def response_handler(msg):
            try:
                data = msgpack.unpackb(msg.data)
                for node_info in data:
                    if node_info.get('node_id') == alias:
                        responses.append(node_info)
            except:
                pass

        # Create temporary subscription
        inbox = nc.new_inbox()
        sub = await nc.subscribe(inbox, cb=response_handler)

        # Send discovery request for all node types
        await nc.publish("node.discover.heavy", msgpack.packb({}), reply=inbox)
        await nc.publish("node.discover.light", msgpack.packb({}), reply=inbox)

        # Wait for responses (2 seconds should be enough)
        await asyncio.sleep(2)

        # Cleanup
        await sub.unsubscribe()
        await nc.close()

        # If we got any responses with this alias, it's taken
        return len(responses) == 0

    except Exception as e:
        # Network is unreachable - fail registration
        raise RuntimeError(f"Cannot connect to NATS network at {nats_url}: {e}")


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
