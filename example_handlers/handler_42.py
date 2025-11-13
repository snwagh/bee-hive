"""Example custom handler for bee-hive-nectar"""

from nectar import handler, Computation

@handler
def basic_handler(computation: Computation) -> int:
    """
    Example handler that returns 42.
    """
    return 42