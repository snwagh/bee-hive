"""Default handler for nectar"""

import random
from nectar import handler, Computation


@handler
def default_handler(computation: Computation) -> int:
    """
    Default handler: returns random value 0-100.

    The handler receives full computation context:
    - computation.query: The query string
    - computation.comp_id: Unique computation ID
    - computation.proposer: Who proposed this
    - computation.aggregators: List of aggregator nodes
    - computation.targets: List of target nodes
    - computation.deadline: Time limit in seconds
    - computation.metadata: Additional context
    """
    return random.randint(0, 100)
