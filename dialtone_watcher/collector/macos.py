"""Read-only macOS metadata collection; no command lines or DNS resolution."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import plistlib
import socket
import stat
import subprocess
import time
from xml.parsers.expat import ExpatError

import psutil

from .base import Collector
from ..privacy import redact

_PROCESS_ERRORS = (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess)


class MacOSCollector(Collector):
    """One instance per snapshot; caches and visibility counts have that lifetime."""

    def __init__(self, *, startup_dirs=None, max_hash_bytes=200 * 1024 * 1024,
                 max_binaries=100, timeout=3, inspection_seconds=10):
        self.startup_dirs = startup_dirs if startup_dirs is not None else [
            Path.home() / 'Library/LaunchAgents', Path('/Library/LaunchAgents'),
            Path('/Library/LaunchDaemons')]
        self.max_hash_bytes = max_hash_bytes
        self.max_binaries = max_binaries
        self.timeout = timeout
        self.inspection_seconds = inspection_seconds
        self._inspection_elapsed = 0.0
        self._failures = Counter()
        self._signatures = {}
        self._hashes = {}

    def _note(self, source, reason):
        self._failures[(source, reason)] += 1

    def _call(self, process, method, default, source):
        try:
            return getattr(process, method)()
        except _PROCESS_ERRORS as exc:
            self._note(source, type(exc).__name__)
            return default

    def _signature(self, path):
        if not path:
            return None, 'unknown'
        if path in self._signatures:
            return self._signatures[path]
        publisher = None
        result = (None, 'unknown')
        self._signatures[path] = result
        if len(self._signatures) > self.max_binaries or self._inspection_elapsed >= self.inspection_seconds:
            self._note('signature inspection', 'snapshot inspection budget exceeded')
            return result
        before = time.monotonic()
        try:
            signed = subprocess.run(
                ['/usr/bin/codesign', '-dv', '--verbose=2', path],
                capture_output=True, text=True, timeout=self.timeout, check=False)
            lines = (signed.stderr + '\n' + signed.stdout).splitlines()
            authority = next((s.partition('=')[2].strip() for s in lines
                              if s.startswith('Authority=')), None)
            team = next((s.partition('=')[2].strip() for s in lines
                         if s.startswith('TeamIdentifier=')), None)
            publisher = authority or (team if team not in (None, '', 'not set') else None)
            if signed.returncode and any('code object is not signed at all' in s for s in lines):
                result = (None, 'unsigned')
            elif signed.returncode == 0 and publisher:
                # Deny direct network and all service lookups: fail closed if
                # Gatekeeper needs a daemon that might perform online checks.
                assessed = subprocess.run([
                    '/usr/bin/sandbox-exec', '-p',
                    '(version 1)(allow default)(deny network*)(deny mach-lookup)',
                    '/usr/sbin/spctl', '--assess', '--type', 'execute', '--no-cache', path],
                    capture_output=True, text=True, timeout=self.timeout, check=False)
                result = (publisher, 'verified' if assessed.returncode == 0 else 'unknown')
                if assessed.returncode != 0:
                    self._note('trust assessment', 'offline sandbox assessment unavailable or denied')
            else:
                self._note('signature inspection', 'unsigned or unrecognized metadata')
        except (OSError, subprocess.TimeoutExpired):
            result = (publisher, 'unknown')
            self._note('signature inspection', 'tool unavailable or timed out')
        finally:
            self._inspection_elapsed += time.monotonic() - before
        result = (redact(result[0]), result[1])
        self._signatures[path] = result
        return result

    def get_publisher(self, exe_path):
        return self._signature(exe_path)[0]

    def get_trust_signal(self, exe_path):
        return self._signature(exe_path)[1]

    def _sha256(self, path):
        if not path:
            return None
        if path in self._hashes:
            return self._hashes[path]
        self._hashes[path] = None
        if len(self._hashes) > self.max_binaries:
            self._note('executable hashing', 'snapshot inspection budget exceeded')
            return None
        try:
            if not stat.S_ISREG(os.stat(path).st_mode):
                self._note('executable hashing', 'not a regular file')
                return None
            with open(path, 'rb') as stream:
                if os.fstat(stream.fileno()).st_size > self.max_hash_bytes:
                    self._note('executable hashing', 'file exceeds size limit')
                    return None
                digest = hashlib.sha256()
                total = 0
                while chunk := stream.read(1024 * 1024):
                    total += len(chunk)
                    if total > self.max_hash_bytes:
                        self._note('executable hashing', 'file exceeds size limit')
                        return None
                    digest.update(chunk)
                self._hashes[path] = digest.hexdigest()
        except OSError:
            self._note('executable hashing', 'file unreadable or disappeared')
        return self._hashes[path]

    def _processes(self):
        try:
            yield from psutil.process_iter()
        except (*_PROCESS_ERRORS, OSError) as exc:
            self._note('process enumeration', type(exc).__name__)

    def list_processes(self):
        rows = []
        for process in self._processes():
            name = self._call(process, 'name', None, 'process names')
            if name is None:
                continue
            path = self._call(process, 'exe', '', 'executable paths')
            memory = self._call(process, 'memory_info', None, 'process memory')
            started = self._call(process, 'create_time', None, 'process start times')
            parent = self._call(process, 'parent', None, 'parent processes')
            parent_name = self._call(parent, 'name', None, 'parent names') if parent else None
            rows.append(redact(dict(
                name=name, exe_path=path, publisher=self.get_publisher(path),
                trust_signal=self.get_trust_signal(path), sha256=self._sha256(path),
                cpu_percent=self._call(process, 'cpu_percent', 0.0, 'process CPU'),
                mem_mb=memory.rss / (1024 * 1024) if memory else 0.0,
                started_at=datetime.fromtimestamp(started, timezone.utc).isoformat() if started else None,
                parent=parent_name)))
        return rows

    def list_connections(self):
        rows = []
        for process in self._processes():
            name = self._call(process, 'name', None, 'connection process names')
            if name is None:
                continue
            method = 'net_connections' if hasattr(process, 'net_connections') else 'connections'
            for connection in self._call(process, method, [], 'per-process connections'):
                if not connection.raddr:
                    continue
                if connection.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                rows.append(redact(dict(
                    process_name=name, remote_host=connection.raddr[0],
                    remote_port=connection.raddr[1],
                    protocol='tcp' if connection.type == socket.SOCK_STREAM else 'udp',
                    resolved_domain=None)))
        return rows

    def startup_items(self):
        rows = []
        for directory in self.startup_dirs:
            try:
                paths = [p for p in Path(directory).iterdir() if p.suffix == '.plist']
            except OSError:
                self._note('startup directories', 'directory unreadable')
                continue
            for path in paths:
                try:
                    if path.resolve().is_relative_to('/System'):
                        self._note('startup plists', 'System path excluded')
                        continue
                    with path.open('rb') as stream:
                        data = plistlib.load(stream)
                    if not isinstance(data, dict):
                        raise ValueError('plist must be a dictionary')
                    program = data.get('Program')
                    if not isinstance(program, str):
                        args = data.get('ProgramArguments', [])
                        program = args[0] if isinstance(args, list) and args and isinstance(args[0], str) else ''
                    label = data.get('Label', path.stem)
                    run = data.get('RunAtLoad') if isinstance(data.get('RunAtLoad'), bool) else None
                    keep = data.get('KeepAlive')
                    # Preserve scheduling conditions, never command arguments.
                    keep = keep if isinstance(keep, bool) else {
                        k: v for k, v in keep.items() if isinstance(v, bool)
                    } if isinstance(keep, dict) else None
                    rows.append(redact(dict(name=label if isinstance(label, str) else path.stem,
                        kind='launchd', path=program, source=str(path),
                        enabled=not bool(data.get('Disabled', False)),
                        run_at_load=run, keep_alive=keep)))
                except (OSError, ValueError, plistlib.InvalidFileException, TypeError, OverflowError, ExpatError):
                    self._note('startup plists', 'file unreadable or malformed')
        return rows

    def privilege_status(self):
        root = os.geteuid() == 0
        notes = [f'{count} {source} operations limited: {reason}.'
                 for (source, reason), count in sorted(self._failures.items())]
        if not root:
            notes.append('Not running as root: protected process metadata and per-process connections may be hidden.')
        notes.append('Login items and /System startup definitions are not inspected in this milestone.')
        notes.append('CPU percentages are nonblocking first samples and may be zero.')
        return redact(dict(level='root' if root else 'standard', visibility_notes=notes,
            guidance='For broader process and connection visibility, run manually with sudo using a trusted local environment. '
                     'Root does not bypass all macOS privacy restrictions. Full Disk Access in System Settings > Privacy & Security '
                     'may help with protected startup files; vanished processes cannot be recovered.'))
