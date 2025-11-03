"""Handler decorator for nectar computation framework"""

from typing import Callable, Optional
from functools import wraps
import inspect
from bee_hive_core.types import Computation


class HandlerRegistry:
    """Global registry for handlers"""
    _instance = None
    _handler: Optional[Callable] = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, func: Callable):
        """Register a handler function"""
        self._handler = func

    def get_handler(self) -> Optional[Callable]:
        """Get the registered handler"""
        return self._handler


def handler(func: Callable[[Computation], int]) -> Callable:
    """
    Decorator for computation handlers.

    Handler must accept a Computation object and return an int.
    The return value will be automatically wrapped in the appropriate schema.

    Usage:
        from nectar import handler, Computation

        @handler
        def my_handler(computation: Computation) -> int:
            # Access all computation details
            print(f"Query: {computation.query}")
            print(f"Proposer: {computation.proposer}")
            print(f"Deadline: {computation.deadline}s")

            # Your logic here
            return 42

    Future: Will support returning pydantic models matching response_schema
    """
    # Validate signature
    sig = inspect.signature(func)
    params = list(sig.parameters.values())

    if len(params) != 1:
        raise TypeError(
            f"Handler must accept exactly 1 parameter (Computation), got {len(params)}"
        )

    # Check return type annotation
    return_type = sig.return_annotation
    if return_type not in (int, inspect.Parameter.empty):
        raise TypeError(
            f"Handler must return int (for now), got {return_type}"
        )

    # Register handler
    registry = HandlerRegistry.get_instance()
    registry.register(func)

    @wraps(func)
    def wrapper(computation: Computation) -> int:
        return func(computation)

    return wrapper
