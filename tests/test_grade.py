from zugawatch.anomaly import Finding, Severity
from zugawatch.grade import grade
from zugawatch.pinning import Drift, DriftKind


def test_clean_is_A():
    g = grade([], [])
    assert g.letter == "A" and g.score == 100 and g.passing


def test_one_high_finding_drops_below_A():
    g = grade([Finding("SENT001", Severity.HIGH, "exfil")], [])
    assert g.score == 75 and g.letter == "B"


def test_rug_pull_drift_penalised_like_high():
    g = grade([], [Drift("t", DriftKind.MUTATED)])
    assert g.score == 75


def test_multiple_highs_fail():
    findings = [Finding(f"SENT{n}", Severity.HIGH, "x") for n in range(3)]
    g = grade(findings, [])
    assert g.letter in ("D", "F") and not g.passing


def test_score_floors_at_zero():
    findings = [Finding("x", Severity.HIGH, "x") for _ in range(10)]
    assert grade(findings, []).score == 0
