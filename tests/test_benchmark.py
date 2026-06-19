"""Regression guard: the benchmark metrics must not silently degrade."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "benchmark"))

from run import evaluate  # noqa: E402


def test_metrics_hold():
    r = evaluate()
    assert r["n"] >= 100
    assert r["precision"] >= 0.95, r["precision"]
    assert r["recall"] >= 0.88, r["recall"]
    assert r["fpr"] <= 0.02, r["fpr"]
    assert r["latency_p95_ms"] < 5.0  # sub-5ms per scenario


def test_all_categories_handled_except_known_evasion():
    r = evaluate()
    for cat, (ok, tot) in r["cats"].items():
        if cat == "exfil-xor-evasion":
            assert ok == 0, "XOR evasion is the documented recall ceiling; if it's caught, update the docs."
        else:
            assert ok == tot, f"{cat} regressed: {ok}/{tot}"
