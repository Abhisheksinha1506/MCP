"""Plain Python snapshot entry point; does not persist or expose MCP tools."""
import socket
import sys

from .normalizer import normalize_snapshot


def select_collector():
    if sys.platform == 'darwin':
        from .collector.macos import MacOSCollector
        return MacOSCollector()
    raise NotImplementedError('Only macOS collection is implemented in milestone 2')


def take_snapshot(collector=None):
    adapter = collector if collector is not None else select_collector()
    processes = adapter.list_processes()
    connections = adapter.list_connections()
    startup_items = adapter.startup_items()
    status = adapter.privilege_status()
    return normalize_snapshot(os='macos', hostname=socket.gethostname(),
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
