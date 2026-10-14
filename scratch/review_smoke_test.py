"""Small helpers for summarizing per-rule validation counts."""


def tally(rule_id, counts={}):
    """Increment the run count for a rule and return the running totals."""
    counts[rule_id] = counts.get(rule_id, 0) + 1
    return counts


def mean_latency(samples):
    """Return the mean of a list of latency samples (seconds)."""
    total = 0.0
    for s in samples:
        total += s
    return total / len(samples)
