#!/usr/bin/env python3
"""Nectar CLI - Handler service management"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import click

from bee_hive_core.types import Computation, IntegerResponse
from nectar.loader import load_handler_from_file
from nectar.manager import HandlerManager
from nectar.ipc import send_command


@click.group()
def main():
    """Nectar - Computation Handler Manager"""
    pass


@main.command()
@click.argument('handler_file')
def test(handler_file):
    """
    Test a handler file with a mock computation.

    Example:
        nectar test my_handler.py
    """
    click.echo(f"\n🧪 Testing handler: {handler_file}\n")

    # Validate handler file exists
    handler_path = Path(handler_file).resolve()
    if not handler_path.exists():
        click.echo(f"❌ Handler file not found: {handler_path}", err=True)
        sys.exit(1)

    # Load handler
    try:
        handler_func = load_handler_from_file(str(handler_path))
        click.echo("✅ Handler loaded successfully")
    except Exception as e:
        click.echo(f"❌ Failed to load handler: {e}", err=True)
        sys.exit(1)

    # Create mock computation
    click.echo("📝 Creating mock computation...\n")
    from datetime import datetime

    mock_comp = Computation(
        comp_id="test-" + str(int(datetime.utcnow().timestamp())),
        query="What is the sentiment of this test query?",
        proposer="test-node",
        aggregators=["test-heavy1", "test-heavy2"],
        targets=["test-light1", "test-light2"],
        deadline=30,
        timestamp=datetime.utcnow().timestamp(),
        metadata={"test": True}
    )

    click.echo("Mock Computation:")
    click.echo(f"  comp_id: {mock_comp.comp_id}")
    click.echo(f"  query: \"{mock_comp.query}\"")
    click.echo(f"  proposer: {mock_comp.proposer}")
    click.echo(f"  timestamp: {mock_comp.timestamp}\n")

    # Execute handler
    click.echo("🔄 Executing handler...")
    try:
        start_time = time.time()
        result = handler_func(mock_comp)
        execution_time = time.time() - start_time

        click.echo(f"✅ Result: {result}")
        click.echo(f"⏱️  Execution time: {execution_time:.3f}s\n")
        click.echo("✅ Handler test passed!")
    except Exception as e:
        click.echo(f"❌ Handler execution failed: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@main.command()
@click.argument('handler_file')
@click.argument('name')
def launch(handler_file, name):
    """
    Launch a handler as a background daemon.

    Example:
        nectar launch my_handler.py sentiment_v1
    """
    manager = HandlerManager()

    # Validate handler file
    handler_path = Path(handler_file).resolve()
    if not handler_path.exists():
        click.echo(f"❌ Handler file not found: {handler_path}", err=True)
        sys.exit(1)

    # Validate handler can be loaded
    try:
        load_handler_from_file(str(handler_path))
    except Exception as e:
        click.echo(f"❌ Invalid handler file: {e}", err=True)
        sys.exit(1)

    # Check if handler already exists
    if manager.get_handler(name):
        click.echo(f"❌ Handler '{name}' already exists", err=True)
        click.echo(f"   Use 'nectar stop {name}' to stop it first", err=True)
        sys.exit(1)

    # Create handler entry
    try:
        handler = manager.create_handler(name, str(handler_path))
    except Exception as e:
        click.echo(f"❌ Failed to create handler: {e}", err=True)
        sys.exit(1)

    # Launch daemon process
    socket_path = manager.get_socket_path(name)
    log_path = manager.get_log_path(name)

    # Use current Python interpreter to run the daemon
    daemon_script = Path(__file__).parent / "daemon.py"

    cmd = [
        sys.executable,
        "-c",
        f"""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path("{daemon_script.parent}").parent))
from nectar.daemon import HandlerDaemon

daemon = HandlerDaemon(
    "{name}",
    "{handler_path}",
    Path("{socket_path}"),
    Path("{log_path}")
)
asyncio.run(daemon.run())
"""
    ]

    try:
        # Start process in background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

        # Give it a moment to start
        time.sleep(0.5)

        # Check if process is still running
        if process.poll() is not None:
            click.echo(f"❌ Handler failed to start", err=True)
            click.echo(f"   Check logs: nectar logs {name}", err=True)
            sys.exit(1)

        # Update handler status
        manager.set_running(name, process.pid)

        click.echo(f"✅ Handler launched: {name} (PID {process.pid})")
        click.echo(f"   Handler file: {handler_path}")
        click.echo(f"   Status: running")
        click.echo(f"   Watching: (none - use 'nectar attach' to add aliases)")
        click.echo(f"   Logs: nectar logs {name}")

    except Exception as e:
        click.echo(f"❌ Failed to launch handler: {e}", err=True)
        manager.delete_handler(name)
        sys.exit(1)


@main.command()
@click.argument('name')
def stop(name):
    """
    Stop a running handler.

    Example:
        nectar stop sentiment_v1
    """
    manager = HandlerManager()
    handler = manager.get_handler(name)

    if not handler:
        click.echo(f"❌ Handler '{name}' not found", err=True)
        sys.exit(1)

    if handler["status"] != "running":
        click.echo(f"⚠️  Handler '{name}' is not running")
        sys.exit(0)

    pid = handler["pid"]
    click.echo(f"Stopping handler: {name} (PID {pid})")

    # Try graceful shutdown via IPC
    try:
        socket_path = manager.get_socket_path(name)
        if socket_path.exists():
            asyncio.run(send_command(socket_path, {"action": "shutdown"}))
            click.echo("Sent shutdown command...")

            # Wait for process to stop
            for i in range(10):
                time.sleep(0.5)
                try:
                    os.kill(pid, 0)
                except (OSError, ProcessLookupError):
                    # Process stopped
                    manager.set_stopped(name)
                    click.echo(f"✅ Handler stopped gracefully")
                    return
    except Exception as e:
        click.echo(f"⚠️  IPC shutdown failed: {e}")

    # Try SIGTERM
    try:
        os.kill(pid, signal.SIGTERM)
        click.echo("Sent SIGTERM...")

        # Wait up to 3 seconds
        for i in range(6):
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
            except (OSError, ProcessLookupError):
                manager.set_stopped(name)
                click.echo(f"✅ Handler stopped")
                return
    except (OSError, ProcessLookupError):
        manager.set_stopped(name)
        click.echo(f"✅ Handler stopped")
        return

    # Force kill with SIGKILL
    try:
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.5)
        manager.set_stopped(name)
        click.echo(f"⚠️  Handler force-killed")
    except (OSError, ProcessLookupError):
        manager.set_stopped(name)
        click.echo(f"✅ Handler stopped")


@main.command()
def view():
    """List all handlers and their status"""
    manager = HandlerManager()
    handlers = manager.list_handlers()

    if not handlers:
        click.echo("\nNo handlers configured.")
        click.echo("Launch a handler with: nectar launch <handler_file> <name>\n")
        return

    click.echo("\n╔══════════════════════════════════════════════════════════════╗")
    click.echo("║                     Nectar Handlers                           ║")
    click.echo("╚══════════════════════════════════════════════════════════════╝\n")

    running_count = 0
    for name, handler in handlers.items():
        # Check if actually running
        is_running = manager.is_running(name)
        status = "running" if is_running else "stopped"

        if is_running:
            running_count += 1
            status_icon = "🟢"
            status_text = f"{status} (PID {handler['pid']})"
        else:
            status_icon = "⚫"
            status_text = status

        click.echo(f"  {status_icon} {status_text}  {name}")
        click.echo(f"           Handler: {handler['handler_file']}")

        if handler['attached_aliases']:
            aliases_str = ", ".join(handler['attached_aliases'])
            click.echo(f"           Watching: {aliases_str}")
        else:
            click.echo(f"           Watching: (none)")

        if is_running and handler.get('started_at'):
            from datetime import datetime
            started = datetime.fromtimestamp(handler['started_at'])
            click.echo(f"           Started: {started.strftime('%Y-%m-%d %H:%M:%S')}")

        click.echo()

    click.echo(f"Total: {len(handlers)} handler(s), {running_count} running\n")


@main.command()
@click.argument('name')
@click.argument('alias')
def attach(name, alias):
    """
    Attach a handler to an alias (node).

    Example:
        nectar attach sentiment_v1 alice
    """
    manager = HandlerManager()
    handler = manager.get_handler(name)

    if not handler:
        click.echo(f"❌ Handler '{name}' not found", err=True)
        click.echo(f"   Launch it first with: nectar launch <handler_file> {name}", err=True)
        sys.exit(1)

    if not manager.is_running(name):
        click.echo(f"❌ Handler '{name}' is not running", err=True)
        click.echo(f"   Start it with: nectar launch {handler['handler_file']} {name}", err=True)
        sys.exit(1)

    # Validate alias directory exists
    alias_dir = Path.home() / ".bee-hive" / alias / "data" / "computation"
    if not alias_dir.exists():
        click.echo(f"❌ Alias '{alias}' not found", err=True)
        click.echo(f"   Register it with: bee-hive register", err=True)
        sys.exit(1)

    # Check if already attached
    try:
        manager.attach_alias(name, alias, str(alias_dir))
    except ValueError as e:
        click.echo(f"❌ {e}", err=True)
        sys.exit(1)

    # Send attach command to daemon
    try:
        socket_path = manager.get_socket_path(name)
        response = asyncio.run(send_command(socket_path, {
            "action": "attach",
            "path": str(alias_dir),
            "alias": alias
        }))

        if response.get("status") == "ok":
            click.echo(f"✅ Attached handler '{name}' to alias '{alias}'")
            click.echo(f"   Now watching: {alias_dir}")
        else:
            click.echo(f"❌ Failed to attach: {response.get('message')}", err=True)
            # Rollback metadata
            manager.detach_alias(name, alias)
            sys.exit(1)

    except Exception as e:
        click.echo(f"❌ Failed to communicate with handler: {e}", err=True)
        # Rollback metadata
        manager.detach_alias(name, alias)
        sys.exit(1)


@main.command()
@click.argument('name')
@click.argument('alias')
def detach(name, alias):
    """
    Detach a handler from an alias.

    Example:
        nectar detach sentiment_v1 alice
    """
    manager = HandlerManager()
    handler = manager.get_handler(name)

    if not handler:
        click.echo(f"❌ Handler '{name}' not found", err=True)
        sys.exit(1)

    # Get the watch dir before detaching
    if alias not in handler['attached_aliases']:
        click.echo(f"⚠️  Handler '{name}' is not attached to alias '{alias}'")
        sys.exit(0)

    idx = handler['attached_aliases'].index(alias)
    watch_dir = handler['watch_dirs'][idx]

    # Send detach command to daemon if running
    if manager.is_running(name):
        try:
            socket_path = manager.get_socket_path(name)
            response = asyncio.run(send_command(socket_path, {
                "action": "detach",
                "path": watch_dir
            }))

            if response.get("status") != "ok":
                click.echo(f"⚠️  Daemon response: {response.get('message')}")

        except Exception as e:
            click.echo(f"⚠️  Failed to communicate with handler: {e}")

    # Update metadata
    manager.detach_alias(name, alias)
    click.echo(f"✅ Detached handler '{name}' from alias '{alias}'")


@main.command()
@click.argument('name')
def logs(name):
    """
    View handler logs (tail -f).

    Example:
        nectar logs sentiment_v1
    """
    manager = HandlerManager()
    handler = manager.get_handler(name)

    if not handler:
        click.echo(f"❌ Handler '{name}' not found", err=True)
        sys.exit(1)

    log_path = manager.get_log_path(name)

    if not log_path.exists():
        click.echo(f"⚠️  No logs found for handler '{name}'")
        click.echo(f"   Expected: {log_path}")
        sys.exit(0)

    click.echo(f"Streaming logs for handler '{name}' (Ctrl+C to exit)...\n")

    try:
        # Use tail -f to stream logs
        subprocess.run(["tail", "-f", str(log_path)])
    except KeyboardInterrupt:
        click.echo("\n\n✅ Stopped streaming logs")
    except FileNotFoundError:
        click.echo("❌ 'tail' command not found", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
