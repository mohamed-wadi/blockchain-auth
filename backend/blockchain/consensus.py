"""
consensus.py — Proof-of-Stake consensus helpers.
Provides weighted voting and leader election for the 5-node network.
"""
import time


def weighted_vote(node_results: list[dict]) -> tuple[bool, float]:
    """
    Weighted consensus: each node vote is weighted by its stake.
    Returns (passed: bool, weighted_percentage: float).
    Threshold: 70%.
    """
    total_stake = sum(n["stake"] for n in node_results)
    if total_stake == 0:
        return False, 0.0
    confirmed_stake = sum(
        n["stake"] for n in node_results if n.get("confirmed")
    )
    pct = (confirmed_stake / total_stake) * 100
    return pct >= 70, round(pct, 2)


def elect_leader(nodes: list) -> object:
    """Select node with highest stake as PoS leader."""
    return max(nodes, key=lambda n: n.stake)


def check_fork(chains: list[list]) -> bool:
    """
    Detect a fork: all nodes should have the same last block hash.
    Returns True if a fork is detected.
    """
    if not chains:
        return False
    last_hashes = {c[-1].hash for c in chains if c}
    return len(last_hashes) > 1


def finality_score(node_results: list[dict]) -> dict:
    """Return breakdown used for the jury demo."""
    total = len(node_results)
    confirmed = sum(1 for n in node_results if n.get("confirmed"))
    return {
        "total_nodes": total,
        "confirmed": confirmed,
        "rejected": total - confirmed,
        "percentage": round((confirmed / total) * 100, 1) if total else 0,
        "timestamp": time.time(),
    }
