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

    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self.pids_file = Path.home() / ".bee-hive" / "node_pids.json"

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
        node_data_dir = self.data_dir / alias
        node_data_dir.mkdir(exist_ok=True)

        # Get key paths from identity
        identity_mgr = IdentityManager()
        private_key_path, public_key_path = identity_mgr.get_key_paths(alias)

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
        node_data_dir = self.data_dir / alias
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

    # Create identity
    identity_mgr = IdentityManager()

    try:
        # Check if already exists
        if identity_mgr.identity_exists(alias):
            click.echo(f"\n⚠️  Identity '{alias}' already exists.")

            # Try to verify with provided password
            try:
                identity = identity_mgr.verify_identity(alias, password)
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

        # Create new identity
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
        click.echo("║  • View results in ./data/<alias>/                ║")
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

    # Verify proposer identity exists
    identity_mgr = IdentityManager()
    if not identity_mgr.identity_exists(proposer):
        click.echo(f"❌ Proposer identity '{proposer}' not found on this machine", err=True)
        click.echo(f"   Run 'bee-hive register' first to create identity", err=True)
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
        click.echo(f"\n💡 Results will be saved to: ./data/{proposer}/")

    except Exception as e:
        click.echo(f"❌ Failed to submit: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('alias')
def deregister(alias):
    """Deregister a node from the network and remove all data."""

    click.echo("╔═══════════════════════════════════════════════════╗")
    click.echo("║         Bee-Hive Network Deregistration           ║")
    click.echo("╚═══════════════════════════════════════════════════╝\n")

    # Check if identity exists
    identity_mgr = IdentityManager()
    if not identity_mgr.identity_exists(alias):
        click.echo(f"❌ Identity '{alias}' not found", err=True)
        sys.exit(1)

    # Get password for verification
    password = getpass.getpass(f"Password for @{alias}: ")

    # Verify password BEFORE showing destructive operation warnings
    try:
        identity_mgr.verify_identity(alias, password)
    except ValueError as e:
        click.echo(f"\n❌ {e}", err=True)
        sys.exit(1)

    # Show what will be deleted
    click.echo(f"\n⚠️  WARNING: This will permanently delete:")
    click.echo(f"   • Identity and cryptographic keys (~/.bee-hive/{alias}/)")
    click.echo(f"   • Computation data (./data/{alias}/)")
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

        # Remove computation data
        click.echo(f"🗑️  Removing computation data...")
        node_mgr.remove_node_data(alias)

        # Delete identity and keys (password already verified above)
        click.echo(f"🗑️  Removing identity and keys...")
        identity_mgr.delete_identity(alias, password)

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
