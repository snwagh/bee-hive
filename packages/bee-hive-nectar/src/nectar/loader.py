"""Dynamic handler loading from Python files"""

import sys
import importlib.util
from pathlib import Path
from typing import Callable
from nectar.decorator import HandlerRegistry
from bee_hive_core.types import Computation


def load_handler_from_file(handler_path: str) -> Callable[[Computation], int]:
    """
    Dynamically load handler from Python file.

    Args:
        handler_path: Path to Python file with @handler decorator

    Returns:
        Handler function

    Raises:
        FileNotFoundError: If handler file doesn't exist
        ValueError: If no handler found or multiple handlers defined
    """
    path = Path(handler_path).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Handler file not found: {path}")

    # Load module dynamically
    spec = importlib.util.spec_from_file_location("user_handler", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"Cannot load module from {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["user_handler"] = module

    # Clear registry before loading
    registry = HandlerRegistry.get_instance()
    registry._handler = None

    # Execute module (this will trigger @handler decorator)
    spec.loader.exec_module(module)

    # Get registered handler
    handler_func = registry.get_handler()
    if handler_func is None:
        raise ValueError(f"No @handler decorated function found in {path}")

    return handler_func


def load_default_handler() -> Callable[[Computation], int]:
    """Load built-in default handler"""
    from nectar.handlers.default import default_handler
    return default_handler
