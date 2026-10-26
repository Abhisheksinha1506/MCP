"""Collectors return metadata only: never command lines or file contents."""
from abc import ABC, abstractmethod
from typing import Any


class Collector(ABC):
    """Read-only OS adapter. Record per-process visibility failures in notes.

    Process and connection dictionaries follow schema.py. Startup items use
    name, kind, path, enabled, and source. Privilege status uses level,
    visibility_notes and guidance. No method may perform DNS/network lookups.
    Trust signals: verified, unsigned, package_owned, unknown.
    """

    @abstractmethod
    def list_processes(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def list_connections(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def get_publisher(self, exe_path: str) -> str | None: ...

    @abstractmethod
    def get_trust_signal(self, exe_path: str) -> str: ...

    @abstractmethod
    def startup_items(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def privilege_status(self) -> dict[str, Any]: ...
