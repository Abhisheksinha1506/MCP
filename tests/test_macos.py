import getpass
import hashlib
import json
from pathlib import Path
import plistlib
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import psutil
import pytest

from dialtone_watcher.collector.macos import MacOSCollector
from dialtone_watcher.snapshot import select_collector, take_snapshot


@pytest.fixture(autouse=True)
def mock_non_native_privileges(monkeypatch):
    if sys.platform != 'darwin':
        import os
        monkeypatch.setattr(os, 'geteuid', lambda: 501, raising=False)


def completed(code=0, stderr='Authority=Example Publisher\nTeamIdentifier=EXAMPLE\n'):
    return subprocess.CompletedProcess([], code, '', stderr)


def fake_process():
    p = Mock()
    p.name.return_value = 'Python'
    p.exe.return_value = ''
    p.memory_info.return_value = SimpleNamespace(rss=1048576)
    p.create_time.return_value = 1700000000
    p.parent.return_value = None
    p.cpu_percent.return_value = 0.0
    p.net_connections.return_value = [SimpleNamespace(raddr=('192.0.2.1', 443),
        family=socket.AF_INET, type=socket.SOCK_STREAM)]
    return p


@pytest.mark.parametrize('responses,expected,publisher', [
    ([completed(), completed(0, '')], 'verified', 'Example Publisher'),
    ([completed(1, 'code object is not signed at all')], 'unsigned', None),
    ([FileNotFoundError()], 'unknown', None),
    ([subprocess.TimeoutExpired('codesign', 3)], 'unknown', None),
    ([completed(0, 'unrecognized output')], 'unknown', None),
    ([completed(), completed(3, 'rejected')], 'unknown', 'Example Publisher'),
    ([completed(0, 'TeamIdentifier=EXAMPLE') , completed(0, '')], 'verified', 'EXAMPLE'),
    ([completed(), subprocess.TimeoutExpired('spctl', 3)], 'unknown', 'Example Publisher'),
])
def test_signatures(monkeypatch, responses, expected, publisher):
    run = Mock(side_effect=responses)
    monkeypatch.setattr(subprocess, 'run', run)
    c = MacOSCollector()
    assert c.get_trust_signal('/Applications/Example') == expected
    assert c.get_publisher('/Applications/Example') == publisher
    assert run.call_count == len(responses)
    for call in run.call_args_list:
        assert isinstance(call.args[0], list)
        assert call.kwargs['timeout'] == 3
        assert not call.kwargs.get('shell', False)
    if len(responses) == 2:
        assert '(deny network*)' in run.call_args_list[1].args[0][2]
        assert '(deny mach-lookup)' in run.call_args_list[1].args[0][2]


@pytest.mark.parametrize('error', [psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess])
def test_partial_snapshot(monkeypatch, error):
    blocked = fake_process()
    blocked.name.side_effect = error(999)
    partial = fake_process()
    partial.exe.side_effect = error(998)
    partial.net_connections.side_effect = error(998)
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([blocked, partial]))
    result = take_snapshot(MacOSCollector(startup_dirs=[])).to_dict()
    assert len(result['processes']) == 1
    assert result['connections'] == []
    assert any(error.__name__ in note for note in result['visibility_notes'])
    assert any('per-process connections' in note for note in result['visibility_notes'])
    blocked.cmdline.assert_not_called()
    partial.cmdline.assert_not_called()


def test_connections_and_legacy_fallback(monkeypatch):
    p = fake_process()
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    assert MacOSCollector().list_connections()[0]['remote_host'] == '192.0.2.1'
    del p.net_connections
    p.connections.return_value = []
    assert MacOSCollector().list_connections() == []
    p.connections.assert_called_once_with()


def test_plists(tmp_path):
    fixture = Path(__file__).parent / 'fixtures/agent.plist'
    (tmp_path / 'agent.plist').write_bytes(fixture.read_bytes())
    (tmp_path / 'broken.plist').write_text('broken')
    c = MacOSCollector(startup_dirs=[tmp_path])
    rows = c.startup_items()
    assert len(rows) == 1
    assert rows[0]['path'] == '~/Applications/Example'
    assert rows[0]['run_at_load'] is True
    assert rows[0]['keep_alive'] == {'SuccessfulExit': False}
    assert 'private-argument' not in json.dumps(rows)
    assert any('malformed' in s for s in c.privilege_status()['visibility_notes'])


def test_hash_size_cache_and_budget(tmp_path):
    executable = tmp_path / 'binary'
    executable.write_bytes(b'example')
    c = MacOSCollector()
    assert c._sha256(str(executable)) == hashlib.sha256(b'example').hexdigest()
    assert c._sha256(str(executable)) == hashlib.sha256(b'example').hexdigest()
    small = MacOSCollector(max_hash_bytes=1)
    assert small._sha256(str(executable)) is None
    assert any('size limit' in n for n in small.privilege_status()['visibility_notes'])
    assert MacOSCollector(max_binaries=0)._sha256(str(executable)) is None
    assert c._sha256(str(tmp_path / 'missing')) is None


def test_privileges(monkeypatch):
    import dialtone_watcher.collector.macos as module
    monkeypatch.setattr(module.os, 'geteuid', lambda: 0, raising=False)
    assert MacOSCollector().privilege_status()['level'] == 'root'
    monkeypatch.setattr(module.os, 'geteuid', lambda: 501)
    status = MacOSCollector().privilege_status()
    assert status['level'] == 'standard'
    assert 'sudo' in status['guidance']


def test_selection(monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'darwin')
    assert isinstance(select_collector(), MacOSCollector)
    monkeypatch.setattr(sys, 'platform', 'freebsd')
    with pytest.raises(NotImplementedError):
        select_collector()


def test_snapshot_privacy(monkeypatch):
    p = fake_process()
    p.exe.return_value = '/Users/fixtureperson/Example'
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    monkeypatch.setattr(subprocess, 'run', Mock(return_value=completed(1, 'code object is not signed at all')))
    data = json.dumps(take_snapshot(MacOSCollector(startup_dirs=[])).to_dict())
    for forbidden in ('fixtureperson', '/Users/', '/home/', getpass.getuser()):
        assert forbidden not in data


@pytest.mark.skipif(sys.platform != 'darwin', reason='macOS integration only')
def test_real_snapshot():
    import os
    result = take_snapshot().to_dict()
    assert result['processes']
    from dialtone_watcher.privacy import redact
    current = psutil.Process(os.getpid())
    assert any(p['name'] == redact(current.name()) and p['exe_path'] == redact(current.exe())
               for p in result['processes'])
    assert result['os'] == 'macos'
    assert isinstance(result['connections'], list)
    assert isinstance(result['startup_items'], list)
    assert result['visibility_notes']
    assert len(result['hostname_hash']) == 64
    encoded = json.dumps(result)
    assert getpass.getuser() not in encoded
    assert str(Path.home()) not in encoded
    assert '/Users/' not in encoded


@pytest.mark.parametrize('method', ['exe', 'memory_info', 'create_time', 'parent', 'cpu_percent'])
@pytest.mark.parametrize('error', [psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess])
def test_individual_process_calls(monkeypatch, method, error):
    p = fake_process()
    getattr(p, method).side_effect = error(999)
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c = MacOSCollector(startup_dirs=[])
    assert len(c.list_processes()) == 1
    assert any(error.__name__ in n for n in c.privilege_status()['visibility_notes'])


def test_enumeration_failure(monkeypatch):
    def denied():
        raise PermissionError('do not expose this private diagnostic')
    monkeypatch.setattr(psutil, 'process_iter', denied)
    result = take_snapshot(MacOSCollector(startup_dirs=[])).to_dict()
    assert result['processes'] == []
    assert any('process enumeration' in n for n in result['visibility_notes'])
    assert 'private diagnostic' not in json.dumps(result)


def test_unreadable_and_invalid_xml_plists(monkeypatch, tmp_path):
    path = tmp_path / 'bad.plist'
    path.write_text('<?xml version="1.0"?><plist><dict>')
    c = MacOSCollector(startup_dirs=[tmp_path])
    assert c.startup_items() == []
    assert c.privilege_status()['visibility_notes']
    original = Path.open
    def denied(self, *args, **kwargs):
        if self == path:
            raise PermissionError('private diagnostic')
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', denied)
    assert c.startup_items() == []


def test_signature_time_budget(monkeypatch):
    run = Mock()
    monkeypatch.setattr(subprocess, 'run', run)
    c = MacOSCollector(inspection_seconds=0)
    assert c.get_trust_signal('/Example') == 'unknown'
    run.assert_not_called()
