"""Handler metadata and process management"""

import json
import signal
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class HandlerManager:
    """Manages handler metadata and process tracking"""

    def __init__(self):
        self.base_dir = Path.home() / ".bee-hive" / "nectar"
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.handlers_dir = self.base_dir / "handlers"
        self.handlers_dir.mkdir(exist_ok=True)

        self.logs_dir = self.base_dir / "logs"
        self.logs_dir.mkdir(exist_ok=True)

        self.handlers_file = self.base_dir / "handlers.json"
        self.pids_file = self.base_dir / "handler_pids.json"

    def _load_handlers(self) -> Dict:
        """Load handlers metadata"""
        if not self.handlers_file.exists():
            return {}
        return json.loads(self.handlers_file.read_text())

    def _save_handlers(self, handlers: Dict) -> None:
        """Save handlers metadata"""
        self.handlers_file.write_text(json.dumps(handlers, indent=2))

    def _load_pids(self) -> Dict:
        """Load handler PIDs"""
        if not self.pids_file.exists():
            return {}
        return json.loads(self.pids_file.read_text())

    def _save_pids(self, pids: Dict) -> None:
        """Save handler PIDs"""
        self.pids_file.write_text(json.dumps(pids, indent=2))

    def create_handler(self, name: str, handler_file: str) -> Dict:
        """Create new handler entry"""
        handlers = self._load_handlers()

        if name in handlers:
            raise ValueError(f"Handler '{name}' already exists")

        handler_file_path = Path(handler_file).resolve()

        handler = {
            "name": name,
            "handler_file": str(handler_file_path),
            "status": "stopped",
            "pid": None,
            "watch_dirs": [],
            "attached_aliases": [],
            "created_at": datetime.utcnow().timestamp(),
            "started_at": None,
            "ipc_socket": str(self.handlers_dir / f"{name}.sock"),
            "log_file": str(self.logs_dir / f"{name}.log")
        }

        handlers[name] = handler
        self._save_handlers(handlers)
        return handler

    def get_handler(self, name: str) -> Optional[Dict]:
        """Get handler by name"""
        handlers = self._load_handlers()
        return handlers.get(name)

    def list_handlers(self) -> Dict:
        """List all handlers"""
        return self._load_handlers()

    def update_handler(self, name: str, updates: Dict) -> None:
        """Update handler metadata"""
        handlers = self._load_handlers()
        if name not in handlers:
            raise ValueError(f"Handler '{name}' not found")

        handlers[name].update(updates)
        self._save_handlers(handlers)

    def delete_handler(self, name: str) -> None:
        """Delete handler entry"""
        handlers = self._load_handlers()
        if name not in handlers:
            raise ValueError(f"Handler '{name}' not found")

        del handlers[name]
        self._save_handlers(handlers)

    def set_running(self, name: str, pid: int) -> None:
        """Mark handler as running"""
        self.update_handler(name, {
            "status": "running",
            "pid": pid,
            "started_at": datetime.utcnow().timestamp()
        })

        # Update PIDs file
        pids = self._load_pids()
        pids[name] = pid
        self._save_pids(pids)

    def set_stopped(self, name: str) -> None:
        """Mark handler as stopped"""
        self.update_handler(name, {
            "status": "stopped",
            "pid": None,
            "started_at": None
        })

        # Update PIDs file
        pids = self._load_pids()
        if name in pids:
            del pids[name]
            self._save_pids(pids)

    def attach_alias(self, name: str, alias: str, watch_dir: str) -> None:
        """Attach handler to an alias"""
        handler = self.get_handler(name)
        if not handler:
            raise ValueError(f"Handler '{name}' not found")

        if alias in handler["attached_aliases"]:
            raise ValueError(f"Handler '{name}' is already attached to alias '{alias}'")

        # Check if any other handler is attached to this alias
        handlers = self._load_handlers()
        for h_name, h_data in handlers.items():
            if h_name != name and alias in h_data["attached_aliases"]:
                raise ValueError(
                    f"Alias '{alias}' is already attached to handler '{h_name}'. "
                    f"Detach it first with: nectar detach {h_name} {alias}"
                )

        handler["attached_aliases"].append(alias)
        handler["watch_dirs"].append(watch_dir)
        self.update_handler(name, {
            "attached_aliases": handler["attached_aliases"],
            "watch_dirs": handler["watch_dirs"]
        })

    def detach_alias(self, name: str, alias: str) -> None:
        """Detach handler from an alias"""
        handler = self.get_handler(name)
        if not handler:
            raise ValueError(f"Handler '{name}' not found")

        if alias not in handler["attached_aliases"]:
            raise ValueError(f"Handler '{name}' is not attached to alias '{alias}'")

        # Find and remove the watch_dir for this alias
        idx = handler["attached_aliases"].index(alias)
        handler["attached_aliases"].remove(alias)
        handler["watch_dirs"].pop(idx)

        self.update_handler(name, {
            "attached_aliases": handler["attached_aliases"],
            "watch_dirs": handler["watch_dirs"]
        })

    def is_running(self, name: str) -> bool:
        """Check if handler process is running"""
        handler = self.get_handler(name)
        if not handler or handler["status"] != "running":
            return False

        pid = handler["pid"]
        if not pid:
            return False

        try:
            # Send signal 0 to check if process exists
            import os
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            # Process doesn't exist, update status
            self.set_stopped(name)
            return False

    def get_handler_for_alias(self, alias: str) -> Optional[str]:
        """Get handler name attached to an alias"""
        handlers = self._load_handlers()
        for name, handler in handlers.items():
            if alias in handler["attached_aliases"]:
                return name
        return None

    def get_socket_path(self, name: str) -> Path:
        """Get IPC socket path for handler"""
        return self.handlers_dir / f"{name}.sock"

    def get_log_path(self, name: str) -> Path:
        """Get log file path for handler"""
        return self.logs_dir / f"{name}.log"
