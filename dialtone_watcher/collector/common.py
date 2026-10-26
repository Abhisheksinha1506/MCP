"""OS-independent bounded executable hashing, shared by local collectors."""
import hashlib
import os
import stat


class ExecutableHasher:
    def __init__(self, note, *, max_bytes=200 * 1024 * 1024, max_binaries=100):
        self.note = note
        self.max_bytes = max_bytes
        self.max_binaries = max_binaries
        self.cache = {}

    def hash(self, path):
        if not path:
            return None
        if path in self.cache:
            return self.cache[path]
        self.cache[path] = None
        if is_network_path(path):
            self.note('executable hashing', 'network or device path skipped')
            return None
        if len(self.cache) > self.max_binaries:
            self.note('executable hashing', 'snapshot binary budget exceeded')
            return None
        try:
            # Opening nonblocking before fstat closes the stat/open FIFO race.
            descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    self.note('executable hashing', 'not a regular file')
                    return None
                if info.st_size > self.max_bytes:
                    self.note('executable hashing', 'file exceeds size limit')
                    return None
                digest = hashlib.sha256()
                size = 0
                while chunk := stream.read(1024 * 1024):
                    size += len(chunk)
                    if size > self.max_bytes:
                        self.note('executable hashing', 'file exceeds size limit')
                        return None
                    digest.update(chunk)
                self.cache[path] = digest.hexdigest()
        except OSError:
            self.note('executable hashing', 'file unreadable or disappeared')
        return self.cache[path]


def is_network_path(path):
    """UNC/extended UNC and device namespaces must not be opened for inspection."""
    value = str(path).replace('/', '\\')
    return value.startswith('\\\\')


class ProcessReader:
    """Common psutil metadata reads; no arguments, account names or DNS queries."""

    def __init__(self, note):
        self.note = note

    def processes(self):
        import psutil
        try:
            yield from psutil.process_iter()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError) as exc:
            self.note('process enumeration', type(exc).__name__)

    def call(self, process, method, default, source):
        import psutil
        try:
            return getattr(process, method)()
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError) as exc:
            self.note(source, type(exc).__name__)
            return default

    def timestamp(self, value):
        from datetime import datetime, timezone
        if value is None:
            return None
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            self.note('process start times', 'timestamp unavailable')
            return None

    def connections(self):
        import socket
        rows = []
        for process in self.processes():
            name = self.call(process, 'name', None, 'connection process names')
            if name is None:
                continue
            method = 'net_connections' if hasattr(process, 'net_connections') else 'connections'
            for connection in self.call(process, method, [], 'per-process connections'):
                if connection.family not in (socket.AF_INET, socket.AF_INET6) or not connection.raddr:
                    continue
                rows.append(dict(process_name=name, remote_host=connection.raddr[0],
                    remote_port=connection.raddr[1],
                    protocol='tcp' if connection.type == socket.SOCK_STREAM else 'udp', resolved_domain=None))
        from ..privacy import redact
        return redact(rows)
