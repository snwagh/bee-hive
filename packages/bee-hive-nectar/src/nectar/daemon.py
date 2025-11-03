"""Handler daemon process - watches directories and executes handlers"""

import asyncio
import json
import signal
import sys
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent
from loguru import logger

from bee_hive_core.types import Computation, ComputationResult, IntegerResponse
from nectar.loader import load_handler_from_file
from nectar.ipc import start_ipc_server


class HandlerDaemon:
    """Daemon process that watches directories and executes handler"""

    def __init__(self, name: str, handler_file: str, socket_path: Path, log_path: Path):
        self.name = name
        self.handler_file = handler_file
        self.socket_path = socket_path
        self.log_path = log_path
        self.handler_func = None
        self.watch_dirs = []
        self.observer = Observer()
        self.shutdown_event = asyncio.Event()
        self.ipc_server = None

        # Configure logging
        logger.remove()  # Remove default handler
        logger.add(
            str(log_path),
            format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
            level="INFO"
        )
        logger.add(sys.stderr, level="ERROR")  # Also log errors to stderr

    def load_handler(self):
        """Load handler function from file"""
        try:
            self.handler_func = load_handler_from_file(self.handler_file)
            logger.info(f"Handler loaded successfully from {self.handler_file}")
        except Exception as e:
            logger.error(f"Failed to load handler: {e}")
            raise

    def add_watch_dir(self, path: str, alias: str) -> None:
        """Add directory to watch list"""
        watch_path = Path(path)
        if not watch_path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

        if path in self.watch_dirs:
            logger.warning(f"Already watching: {path}")
            return

        # Create event handler for this directory
        event_handler = PendingFileHandler(self, alias)
        self.observer.schedule(event_handler, str(watch_path), recursive=False)
        self.watch_dirs.append(path)
        logger.info(f"Now watching: {path} (alias: {alias})")

    def remove_watch_dir(self, path: str) -> None:
        """Remove directory from watch list"""
        if path not in self.watch_dirs:
            logger.warning(f"Not watching: {path}")
            return

        # Watchdog doesn't provide easy way to unschedule by path
        # We need to restart the observer with the updated list
        self.watch_dirs.remove(path)
        logger.info(f"Stopped watching: {path}")

        # Restart observer with remaining directories
        self.observer.stop()
        self.observer.join()
        self.observer = Observer()

        # Re-schedule remaining directories
        # Note: We've lost the alias mapping, but that's okay for stop operation
        for watch_path in self.watch_dirs:
            event_handler = PendingFileHandler(self, "unknown")
            self.observer.schedule(event_handler, watch_path, recursive=False)

        self.observer.start()

    def process_pending_file(self, file_path: Path, alias: str):
        """Process a .pending file"""
        try:
            comp_id = file_path.stem
            logger.info(f"Processing computation: {comp_id} (alias: {alias})")

            # Read computation
            comp_data = json.loads(file_path.read_text())
            comp = Computation(**comp_data)

            # Execute handler
            start_time = datetime.utcnow().timestamp()
            result_value = self.handler_func(comp)
            execution_time = datetime.utcnow().timestamp() - start_time

            logger.info(f"Handler returned: {result_value} (alias: {alias}, comp: {comp_id})")

            # Write .complete file
            complete_file = file_path.with_suffix('.complete')
            result = ComputationResult(
                comp_id=comp_id,
                result=IntegerResponse(value=result_value),
                status="success",
                error=None,
                execution_time=execution_time
            )
            complete_file.write_text(result.model_dump_json(indent=2))
            logger.info(f"Completed: {comp_id} → {complete_file.name}")

            # Clean up .pending file
            file_path.unlink()

        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            # Write error result
            try:
                comp_id = file_path.stem
                complete_file = file_path.with_suffix('.complete')
                result = ComputationResult(
                    comp_id=comp_id,
                    result=None,
                    status="error",
                    error=str(e),
                    execution_time=None
                )
                complete_file.write_text(result.model_dump_json(indent=2))
                file_path.unlink()
            except Exception as cleanup_error:
                logger.error(f"Failed to write error result: {cleanup_error}")

    async def handle_ipc_command(self, command: dict) -> dict:
        """Handle IPC commands from CLI"""
        action = command.get("action")

        try:
            if action == "attach":
                path = command["path"]
                alias = command["alias"]
                self.add_watch_dir(path, alias)
                return {"status": "ok", "message": f"Attached to {alias}"}

            elif action == "detach":
                path = command["path"]
                self.remove_watch_dir(path)
                return {"status": "ok", "message": "Detached"}

            elif action == "shutdown":
                logger.info("Received shutdown command")
                asyncio.create_task(self.shutdown())
                return {"status": "ok", "message": "Shutting down"}

            elif action == "status":
                return {
                    "status": "ok",
                    "watching": self.watch_dirs,
                    "handler": self.handler_file
                }

            else:
                return {"status": "error", "message": f"Unknown action: {action}"}

        except Exception as e:
            logger.error(f"Error handling command {action}: {e}")
            return {"status": "error", "message": str(e)}

    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down handler daemon...")
        self.observer.stop()
        self.observer.join()

        if self.ipc_server:
            self.ipc_server.close()
            await self.ipc_server.wait_closed()

        # Remove socket file
        if self.socket_path.exists():
            self.socket_path.unlink()

        self.shutdown_event.set()
        logger.info("Handler daemon stopped")

    async def run(self):
        """Main run loop"""
        logger.info(f"Starting handler daemon: {self.name}")

        # Load handler function
        self.load_handler()

        # Start IPC server
        self.ipc_server = await start_ipc_server(
            self.socket_path,
            self.handle_ipc_command
        )
        logger.info(f"IPC server listening on: {self.socket_path}")

        # Start file observer
        self.observer.start()
        logger.info("File observer started")

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))

        logger.info(f"Handler daemon ready: {self.name}")

        # Wait for shutdown
        await self.shutdown_event.wait()


class PendingFileHandler(FileSystemEventHandler):
    """Watchdog event handler for .pending files"""

    def __init__(self, daemon: HandlerDaemon, alias: str):
        super().__init__()
        self.daemon = daemon
        self.alias = alias

    def on_created(self, event: FileCreatedEvent):
        """Handle file creation events"""
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        if file_path.suffix == '.pending':
            # Process in the daemon's context
            self.daemon.process_pending_file(file_path, self.alias)
