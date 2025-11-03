"""Example custom handler for bee-hive-nectar"""

from nectar import handler, Computation


@handler
def example_handler(computation: Computation) -> int:
    """
    Example handler that demonstrates accessing computation details.

    Returns a score based on the length of the query string.
    """
    # Access computation details
    query_length = len(computation.query)

    # Simple logic: return a score from 0-100 based on query length
    # Longer queries get higher scores (capped at 100)
    score = query_length

    print(f"Processing: '{computation.query}'")
    print(f"Query length: {query_length}")
    print(f"Computed score: {score}")

    return score
