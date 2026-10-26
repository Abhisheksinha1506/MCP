"""Plain Python snapshot entry point; does not persist or expose MCP tools."""
import socket
import sys

from .normalizer import normalize_snapshot


def select_collector():
    if sys.platform == 'darwin':
        from .collector.macos import MacOSCollector
        return MacOSCollector()
    if sys.platform.startswith('linux'):
        from .collector.linux import LinuxCollector
        return LinuxCollector()
    if sys.platform == 'win32':
        from .collector.windows import WindowsCollector
        return WindowsCollector()
    raise NotImplementedError('Unsupported operating system')


def take_snapshot(collector=None):
    adapter = collector if collector is not None else select_collector()
    processes = adapter.list_processes()
    connections = adapter.list_connections()
    startup_items = adapter.startup_items()
    status = adapter.privilege_status()
    return normalize_snapshot(os=adapter.os, hostname=socket.gethostname(),
        privilege_level=status['level'], processes=processes, connections=connections,
        startup_items=startup_items,
        visibility_notes=[*status['visibility_notes'], status.get('guidance', '')])


if __name__ == '__main__':
    import json
    import time
    started = time.monotonic()
    snapshot = take_snapshot()
    print(json.dumps({
        'processes': len(snapshot.processes),
        'connections': len(snapshot.connections),
        'startup_items': len(snapshot.startup_items),
        'visibility_notes': len(snapshot.visibility_notes),
        'elapsed_seconds': round(time.monotonic() - started, 2),
    }))
