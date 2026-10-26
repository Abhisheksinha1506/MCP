"""Build safe snapshots from metadata without importing any platform adapter."""
from dataclasses import fields
from datetime import datetime, timezone
from uuid import uuid4
from .privacy import hostname_hash, redact
from .schema import Connection, Process, Snapshot, StartupItem


def _record(cls, raw):
    allowed = {f.name for f in fields(cls)}
    data = redact({key: value for key, value in raw.items() if key in allowed})
    if cls is Process and data.get("trust_signal", "unknown") not in {
        "verified", "unsigned", "package_owned", "unknown"
    }:
        data["trust_signal"] = "unknown"
    return cls(**data)


def normalize_snapshot(*, os: str, hostname: str, privilege_level: str,
                       processes=(), connections=(), startup_items=(),
                       visibility_notes=(), snapshot_id=None, created_at=None) -> Snapshot:
    if os not in {"macos", "windows", "linux"}:
        raise ValueError("Unsupported operating system")
    return Snapshot(
        id=snapshot_id or str(uuid4()),
        created_at=created_at or datetime.now(timezone.utc).isoformat(),
        os=os, hostname_hash=hostname_hash(hostname),
        privilege_level=redact(privilege_level),
        visibility_notes=redact(list(visibility_notes)),
        processes=[_record(Process, p) for p in processes],
        connections=[_record(Connection, c) for c in connections],
        startup_items=[_record(StartupItem, s) for s in startup_items],
    )
