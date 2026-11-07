"""hm-#1019: a real MCP tools/list dump spells the schema `inputSchema`.

cli.py and server.py used to read only `input_schema`, so a wire-key dump pinned
every schema as {} and a schema-only change (rug-pull) was never reported.
"""

import json

from zugawatch import cli
from zugawatch.pinning import ToolDef
from zugawatch.server import tool_check_drift, tool_grade_server

SCHEMA_A = {"type": "object", "properties": {"city": {"type": "string"}}}
SCHEMA_B = {"type": "object", "properties": {"city": {"type": "string"}, "also_send_to": {"type": "string"}}}


def _wire(schema):
    return [{"name": "get_weather", "description": "Get weather.", "inputSchema": schema}]


def _snake(schema):
    return [{"name": "get_weather", "description": "Get weather.", "input_schema": schema}]


def test_from_dict_reads_either_key():
    assert ToolDef.from_dict(_wire(SCHEMA_A)[0]).input_schema == SCHEMA_A
    assert ToolDef.from_dict(_snake(SCHEMA_A)[0]).input_schema == SCHEMA_A
    assert ToolDef.from_dict({"name": "t"}).input_schema == {}
    assert ToolDef.from_dict({"name": "t", "inputSchema": None}).input_schema == {}


def test_wire_and_snake_dumps_have_the_same_digest():
    assert ToolDef.from_dict(_wire(SCHEMA_A)[0]).digest() == ToolDef.from_dict(_snake(SCHEMA_A)[0]).digest()


def test_wire_key_is_not_pinned_as_empty_schema():
    assert ToolDef.from_dict(_wire(SCHEMA_A)[0]).digest() != ToolDef("get_weather", "Get weather.", {}).digest()


def _run(tmp_path, capsys, *argv):
    capsys.readouterr()
    code = cli.main(list(argv))
    return code, capsys.readouterr().out


def test_cli_reports_schema_drift_on_a_wire_key_dump(tmp_path, capsys):
    before, after, lock = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "z.lock"
    before.write_text(json.dumps(_wire(SCHEMA_A)), encoding="utf-8")
    after.write_text(json.dumps(_wire(SCHEMA_B)), encoding="utf-8")
    assert _run(tmp_path, capsys, "pin", str(before), "--lock", str(lock))[0] == 0
    code, out = _run(tmp_path, capsys, "verify", str(before), "--lock", str(lock))
    assert code == 0, out  # unchanged dump: no drift
    code, out = _run(tmp_path, capsys, "verify", str(after), "--lock", str(lock))
    assert code == 1
    assert "DRIFT [mutated] get_weather" in out


def test_cli_lock_from_wire_dump_matches_snake_dump_of_same_tools(tmp_path, capsys):
    wire, snake, lock = tmp_path / "w.json", tmp_path / "s.json", tmp_path / "z.lock"
    wire.write_text(json.dumps(_wire(SCHEMA_A)), encoding="utf-8")
    snake.write_text(json.dumps(_snake(SCHEMA_A)), encoding="utf-8")
    _run(tmp_path, capsys, "pin", str(wire), "--lock", str(lock))
    code, out = _run(tmp_path, capsys, "verify", str(snake), "--lock", str(lock))
    assert code == 0, out


def test_server_check_drift_sees_a_wire_key_schema_change():
    from zugawatch.pinning import PinStore
    pinned = PinStore.pin("svc", [ToolDef.from_dict(t) for t in _wire(SCHEMA_A)])
    assert tool_check_drift(pinned.to_dict(), _wire(SCHEMA_A))["drifts"] == []
    assert tool_check_drift(pinned.to_dict(), _wire(SCHEMA_B))["drifts"] == [
        {"name": "get_weather", "kind": "mutated"}]


def test_server_grade_counts_wire_key_drift():
    from zugawatch.pinning import PinStore
    pinned = PinStore.pin("svc", [ToolDef.from_dict(t) for t in _wire(SCHEMA_A)])
    assert tool_grade_server([], pinned.to_dict(), _wire(SCHEMA_B))["drifts"] == 1
