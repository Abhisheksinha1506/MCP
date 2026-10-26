"""OS-independent, explicit metadata schema."""
from dataclasses import asdict, dataclass, field
from typing import Literal
from .privacy import redact

OS = Literal["macos", "windows", "linux"]
TrustSignal = Literal["verified", "unsigned", "package_owned", "unknown"]


@dataclass
class Process:
    name: str
    exe_path: str = ""
    publisher: str | None = None
    trust_signal: TrustSignal = "unknown"
    sha256: str | None = None
    cpu_percent: float = 0.0
    mem_mb: float = 0.0
    started_at: str | None = None
    parent: str | None = None


@dataclass
class Connection:
    process_name: str
    remote_host: str
    remote_port: int
    protocol: str
    resolved_domain: str | None = None  # Only locally available; never resolve via DNS.


@dataclass
class StartupItem:
    name: str
    kind: str
    path: str = ""
    enabled: bool | None = None
    source: str = ""
    run_at_load: bool | None = None
    keep_alive: bool | dict[str, bool] | None = None


@dataclass
class Finding:
    type: Literal["junk", "telemetry", "unusual"]
    subject: str
    severity: Literal["info", "low", "medium"]
    reason: str
    suggested_action: str
    platforms: list[str]
    rule_id: str = ""
    confidence: Literal["high", "medium", "low"] = "low"
    evidence: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return redact(asdict(self))


@dataclass
class Snapshot:
    id: str
    created_at: str
    os: OS
    hostname_hash: str
    privilege_level: str
    visibility_notes: list[str] = field(default_factory=list)
    processes: list[Process] = field(default_factory=list)
    connections: list[Connection] = field(default_factory=list)
    startup_items: list[StartupItem] = field(default_factory=list)

    def to_dict(self) -> dict:
        return redact(asdict(self))
