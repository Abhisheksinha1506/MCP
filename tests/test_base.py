import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

import pytest

from dialtone_watcher.collector.base import Collector
from dialtone_watcher.normalizer import normalize_snapshot
from dialtone_watcher.privacy import hostname_hash, redact
from dialtone_watcher.schema import Finding, Process, Snapshot
from dialtone_watcher.store import SnapshotStore


@pytest.fixture
def raw():
    return json.loads((Path(__file__).parent / "fixtures/snapshot.json").read_text())


@pytest.mark.parametrize("home", [
    "/Users/fixtureperson", "/home/fixtureperson",
    r"C:\Users\fixtureperson", "C:/Users/fixtureperson",
])
def test_home_paths_redacted_everywhere(home):
    data = {"path": home + "/app", "notes": ["Denied: " + home + "/app"],
            "nested": {"username": "fixtureperson", "args": ["private"]}}
    result = redact(data)
    encoded = json.dumps(result)
    assert "fixtureperson" not in encoded
    assert home not in encoded
    assert result["path"] == "~/app"
    assert result["nested"] == {}


def test_account_and_sensitive_fields():
    result = redact({"message": "Account fixtureperson denied", "cmdline": "private",
                     "file_contents": "secret", "hostname": "private"}, username="fixtureperson")
    assert result == {"message": "Account [redacted] denied"}


@pytest.mark.parametrize("platform", ["macos", "windows", "linux"])
def test_normalization(raw, platform):
    raw["os"] = platform
    snapshot = normalize_snapshot(**raw)
    output = snapshot.to_dict()
    assert output["os"] == platform
    assert output["hostname_hash"] == hostname_hash("private-machine")
    assert len(output["hostname_hash"]) == 64
    assert snapshot.processes[0].cpu_percent == 1.5
    assert snapshot.visibility_notes == raw["visibility_notes"]
    assert snapshot.connections[0].resolved_domain is None
    encoded = json.dumps(output)
    for private in ("fixtureperson", "private-machine", "cmdline", "secret", "/Users/"):
        assert private not in encoded


def test_defaults_and_unknown_trust(raw):
    raw["processes"] = [{"name": "minimal", "trust_signal": "invented", "contents": "secret"}]
    snapshot = normalize_snapshot(**raw)
    assert snapshot.processes[0].trust_signal == "unknown"
    assert snapshot.processes[0].mem_mb == 0
    assert snapshot.id
    assert snapshot.created_at.endswith("+00:00")
    with pytest.raises(ValueError):
        normalize_snapshot(os="unsupported", hostname="host", privilege_level="unknown")


def test_store_roundtrip_and_append_only(tmp_path, raw):
    path = tmp_path / "snapshots.sqlite"
    first = normalize_snapshot(**raw, snapshot_id="first", created_at="2026-01-01T00:00:00+00:00")
    second = normalize_snapshot(**raw, snapshot_id="second", created_at="2026-01-02T00:00:00+00:00")
    with SnapshotStore(path) as store:
        assert store.latest() is None
        assert store.get("missing") is None
        store.save(second)
        store.save(first)
        assert store.latest() == second.to_dict()
        assert store.get("first") == first.to_dict()
        assert store.get("' OR 1=1 --") is None
        with pytest.raises(sqlite3.IntegrityError):
            store.save(first)
        assert store.get("first") == first.to_dict()
    assert b"fixtureperson" not in path.read_bytes()
    with SnapshotStore(path) as reopened:
        assert reopened.latest()["id"] == "second"


def test_direct_schema_cannot_bypass_storage_redaction(tmp_path):
    snapshot = Snapshot("direct", "2026-01-01", "linux", hostname_hash("host"), "standard",
                        processes=[Process("Example", "/home/fixtureperson/example")])
    with SnapshotStore(tmp_path / "direct.sqlite") as store:
        store.save(snapshot)
        assert store.get("direct")["processes"][0]["exe_path"] == "~/example"


def test_collector_contract_is_abstract():
    with pytest.raises(TypeError):
        Collector()
    assert Collector.__abstractmethods__ == {
        "list_processes", "list_connections", "get_publisher", "get_trust_signal",
        "startup_items", "privilege_status"}


def test_finding_has_plain_language_fields():
    finding = Finding("unusual", "Example", "info", "Publisher is unavailable.",
                      "Review its origin before changing anything.", ["linux"])
    assert asdict(finding)["reason"]


@pytest.mark.parametrize("home", ["/root", "/home/fixtureperson"])
def test_explicit_home_boundary(home):
    assert redact(home + "/bin/example", username="root", home=home) == "~/bin/example"
    if home == "/root":
        assert redact("/rooted/example", username="root", home=home) == "/rooted/example"
    assert redact({"path": home, "args": ["secret"]}, username="root", home=home) == {"path": "~"}
