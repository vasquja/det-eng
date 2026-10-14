"""Throwaway sample to smoke-test the Claude Code review workflow.

Not used anywhere in the repo. This PR exists only to confirm that the
automated PR review posts comments. Safe to close without merging.
"""


def accumulate(value, acc=[]):
    # Deliberate smell: mutable default argument is shared across calls.
    acc.append(value)
    return acc


def average(numbers):
    # Deliberate smell: divides by len without guarding the empty case.
    total = 0
    for n in numbers:
        total += n
    return total / len(numbers)
