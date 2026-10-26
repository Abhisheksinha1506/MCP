import ctypes
import getpass
import importlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import psutil
import pytest

from dialtone_watcher.collector.common import ExecutableHasher
from dialtone_watcher.collector.windows import WindowsCollector, _SIGNATURE_SCRIPT, _TASK_SCRIPT, _cn
from dialtone_watcher.privacy import redact
from dialtone_watcher.snapshot import select_collector, take_snapshot

FIXTURES = Path(__file__).parent / 'fixtures/windows'


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


def result(data=None, code=0, stdout=None):
    return subprocess.CompletedProcess([], code, stdout if stdout is not None else json.dumps(data), '')


def fake_process(path=r'C:\Program Files\Example\client.exe'):
    p = Mock()
    p.name.return_value = 'Example.exe'
    p.exe.return_value = path
    p.memory_info.return_value = SimpleNamespace(rss=1048576)
    p.create_time.return_value = 1700000000
    p.parent.return_value = None
    p.cpu_percent.return_value = 0.0
    p.net_connections.return_value = [SimpleNamespace(raddr=('192.0.2.1', 443),
        family=socket.AF_INET, type=socket.SOCK_STREAM)]
    return p


@pytest.fixture
def isolated(monkeypatch):
    monkeypatch.setattr(shutil, 'which', lambda name: None)
    monkeypatch.setattr(subprocess, 'run', Mock(side_effect=AssertionError('Unexpected OS tool')))
    monkeypatch.setattr(ctypes, 'windll', SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: 0)), raising=False)
    monkeypatch.setattr(psutil, 'win_service_iter', lambda: iter([]), raising=False)
    monkeypatch.setitem(sys.modules, 'winreg', None)
    return dict(startup_dirs=[])


def powershell(monkeypatch, response):
    monkeypatch.setattr(shutil, 'which', lambda name: 'powershell.exe' if name == 'powershell.exe' else None)
    run = Mock(side_effect=response) if isinstance(response, Exception) else Mock(return_value=response)
    monkeypatch.setattr(subprocess, 'run', run)
    return run


def test_signature_batch(isolated, monkeypatch):
    records = load('signatures.json')
    run = powershell(monkeypatch, result(records))
    c = WindowsCollector(**isolated)
    paths = [r['Path'] for r in records]
    c._inspect_signatures(paths + paths)
    assert [c.get_trust_signal(p) for p in paths] == ['verified', 'unsigned', 'unknown']
    assert c.get_publisher(paths[0]) == 'Example Publisher'
    assert c.get_publisher(paths[1]) is None
    assert c.get_trust_signal(paths[0].upper()) == 'verified'
    assert run.call_count == 1
    args = run.call_args.args[0]
    assert args[:4] == ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command']
    assert args[-1] == _SIGNATURE_SCRIPT
    assert all(p not in args[-1] for p in paths)
    assert json.loads(run.call_args.kwargs['input']) == paths
    assert not run.call_args.kwargs.get('shell', False)
    assert run.call_args.kwargs['timeout'] == 10
    assert c._signature_calls == 1
    assert c._signature_seconds >= 0
    assert any('HashMismatch' in n for n in c.privilege_status()['visibility_notes'])


@pytest.mark.parametrize('status,trust', [('Valid', 'verified'), ('NotSigned', 'unsigned'),
    ('HashMismatch', 'unknown'), ('UnknownError', 'unknown'), ('NotTrusted', 'unknown'),
    ('OfflineRequired', 'unknown'), ('private-token', 'unknown')])
def test_status_mapping(isolated, monkeypatch, status, trust):
    path = r'C:\Example.exe'
    powershell(monkeypatch, result({'Path': path, 'Status': status, 'Subject': 'CN=Example'}))
    c = WindowsCollector(**isolated)
    assert c.get_trust_signal(path) == trust
    notes = json.dumps(c.privilege_status())
    if trust == 'unknown' and status != 'private-token':
        assert status in notes
    assert 'private-token' not in notes


@pytest.mark.parametrize('failure', [FileNotFoundError(), PermissionError(),
    subprocess.TimeoutExpired('powershell', 10), result(code=1), result(stdout='malformed'),
    result(stdout='null'), result([None, {'Path': 42}])])
def test_signature_failures(isolated, monkeypatch, failure):
    run = powershell(monkeypatch, failure)
    c = WindowsCollector(**isolated)
    assert c.get_trust_signal(r'C:\Example.exe') == 'unknown'
    assert c.get_publisher(r'C:\Example.exe') is None
    assert run.call_count == 1
    assert any('signature inspection operations limited' in n for n in c.privilege_status()['visibility_notes'])


def test_no_powershell(isolated):
    c = WindowsCollector(**isolated)
    assert c.get_trust_signal(r'C:\Example.exe') == 'unknown'
    assert any('PowerShell unavailable' in n for n in c.privilege_status()['visibility_notes'])


def test_offline_gate_and_literal_path():
    assert _SIGNATURE_SCRIPT.index('if (-not $offline)') < _SIGNATURE_SCRIPT.index('Get-AuthenticodeSignature')
    assert '-LiteralPath $path' in _SIGNATURE_SCRIPT
    assert 'GetAllNetworkInterfaces' in _SIGNATURE_SCRIPT
    assert 'OperationalStatus' in _SIGNATURE_SCRIPT
    assert 'MSFT_TaskLogonTrigger' in _TASK_SCRIPT and 'MSFT_TaskBootTrigger' in _TASK_SCRIPT
    assert 'Actions' not in _TASK_SCRIPT and 'Principal' not in _TASK_SCRIPT


def test_signature_batch_budget(isolated, monkeypatch):
    run = powershell(monkeypatch, result([]))
    c = WindowsCollector(**isolated, max_binaries=100)
    c._inspect_signatures([rf'C:\Tools\p{i}.exe' for i in range(101)])
    assert run.call_count == 4
    assert [len(json.loads(call.kwargs['input'])) for call in run.call_args_list] == [32, 32, 32, 4]
    assert any('binary budget' in n for n in c.privilege_status()['visibility_notes'])
    run.reset_mock()
    c = WindowsCollector(**isolated, inspection_seconds=0)
    assert c.get_trust_signal(r'C:\Example.exe') == 'unknown'
    run.assert_not_called()


@pytest.mark.parametrize('subject,expected', [('CN=Example, O=Org', 'Example'),
    ('CN="Example, Inc.", O=Org', 'Example, Inc.'), (r'CN=Example\, Inc., O=Org', 'Example, Inc.'),
    ('O=Org', None), (None, None)])
def test_subject_cn(subject, expected):
    assert _cn(subject) == expected


@pytest.mark.parametrize('error', [psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess])
def test_partial_snapshot(isolated, monkeypatch, error):
    blocked = fake_process()
    blocked.name.side_effect = error(999)
    partial = fake_process()
    partial.exe.side_effect = error(998)
    partial.net_connections.side_effect = error(998)
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([blocked, partial]))
    data = take_snapshot(WindowsCollector(**isolated)).to_dict()
    assert data['os'] == 'windows'
    assert len(data['processes']) == 1
    assert data['connections'] == []
    assert any(error.__name__ in n for n in data['visibility_notes'])
    assert any('per-process connections' in n for n in data['visibility_notes'])
    partial.cmdline.assert_not_called()
    partial.username.assert_not_called()


@pytest.mark.parametrize('method', ['memory_info', 'create_time', 'parent', 'cpu_percent'])
@pytest.mark.parametrize('error', [psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess])
def test_per_process_calls(isolated, monkeypatch, method, error):
    p = fake_process('')
    getattr(p, method).side_effect = error(999)
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c = WindowsCollector(**isolated)
    assert len(c.list_processes()) == 1
    assert any(error.__name__ in n for n in c.privilege_status()['visibility_notes'])


def test_empty_executable_is_normal(isolated, monkeypatch):
    p = fake_process('')
    p.name.return_value = 'System'
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c = WindowsCollector(**isolated)
    row = c.list_processes()[0]
    assert row['exe_path'] == '' and row['trust_signal'] == 'unknown' and row['sha256'] is None
    assert any('without executable paths retained' in n for n in c.privilege_status()['visibility_notes'])
    assert not any('executable paths operations limited' in n for n in c.privilege_status()['visibility_notes'])


def mock_registry(monkeypatch):
    entries = load('registry.json')
    class Key:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    registry = SimpleNamespace(HKEY_LOCAL_MACHINE='HKLM', HKEY_CURRENT_USER='HKCU',
        KEY_WOW64_64KEY=256, KEY_WOW64_32KEY=512, KEY_READ=1, REG_SZ=1, REG_EXPAND_SZ=2,
        OpenKey=Mock(return_value=Key()), QueryInfoKey=lambda key: (0, len(entries), 0),
        EnumValue=lambda key, index: entries[index])
    monkeypatch.setitem(sys.modules, 'winreg', registry)
    return registry


def test_startup_fixture_snapshot(isolated, monkeypatch, tmp_path):
    registry = mock_registry(monkeypatch)
    run = powershell(monkeypatch, result(load('tasks.json')))
    startup = tmp_path / 'Startup'
    startup.mkdir()
    for name in load('startup.json'):
        (startup / name).write_text('private-token')
    automatic = Mock()
    automatic.start_type.return_value = 'automatic'
    automatic.name.return_value = 'ExampleService'
    manual = Mock()
    manual.start_type.return_value = 'manual'
    monkeypatch.setattr(psutil, 'win_service_iter', lambda: iter([automatic, manual]))
    p = fake_process(r'C:\Users\fixtureperson\Apps\Example.exe')
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c = WindowsCollector(startup_dirs=[startup])
    # Snapshot fixture uses a local mocked hash and signature, not real files/tools.
    c._hasher.hash = Mock(return_value=None)
    c._inspect_signatures = Mock()
    data = take_snapshot(c).to_dict()
    items = data['startup_items']
    assert len([i for i in items if i['kind'] == 'registry']) == 16
    assert len([i for i in items if i['kind'] == 'startup_folder']) == 2
    assert len([i for i in items if i['kind'] == 'scheduled_task']) == 2
    assert len([i for i in items if i['kind'] == 'service']) == 1
    assert len(registry.OpenKey.call_args_list) == 8
    assert {call.args[3] for call in registry.OpenKey.call_args_list} == {257, 513}
    automatic.binpath.assert_not_called()
    automatic.username.assert_not_called()
    assert run.call_count == 1
    assert 'private-token' not in json.dumps(data)
    assert 'fixtureperson' not in json.dumps(data)
    print(json.dumps({key: len(data[key]) for key in
                      ('processes', 'connections', 'startup_items', 'visibility_notes')}))


def test_registry_denied(isolated, monkeypatch):
    registry = mock_registry(monkeypatch)
    registry.OpenKey.side_effect = PermissionError('private-token')
    c = WindowsCollector(**isolated)
    assert c._registry() == []
    assert any('8 startup registry keys' in n for n in c.privilege_status()['visibility_notes'])
    registry.OpenKey.side_effect = FileNotFoundError()
    assert c._registry() == []


def test_registry_value_denied(isolated, monkeypatch):
    registry = mock_registry(monkeypatch)
    registry.EnumValue = Mock(side_effect=[PermissionError('secret'), ('Example', 'secret', 1), ('ignored', 'secret', 3)] * 8)
    c = WindowsCollector(**isolated)
    assert len(c._registry()) == 8
    assert any('8 startup registry values' in n for n in c.privilege_status()['visibility_notes'])


def test_tasks_csv_fallback(isolated, monkeypatch):
    monkeypatch.setattr(shutil, 'which', lambda name: 'schtasks.exe' if name == 'schtasks.exe' else None)
    run = Mock(return_value=result(stdout=(FIXTURES / 'tasks.csv').read_text()))
    monkeypatch.setattr(subprocess, 'run', run)
    c = WindowsCollector(**isolated)
    tasks = c._tasks()
    assert [row['enabled'] for row in tasks] == [True, False]
    assert run.call_args.args[0] == ['schtasks.exe', '/query', '/fo', 'csv', '/v']
    encoded = json.dumps(redact(tasks))
    assert 'fixtureperson' not in encoded and 'private-token' not in encoded


@pytest.mark.parametrize('failure', [PermissionError(), subprocess.TimeoutExpired('schtasks', 10),
    result(code=1), result(stdout='localized,headers\nvalue,value')])
def test_tasks_csv_failed(isolated, monkeypatch, failure):
    monkeypatch.setattr(shutil, 'which', lambda name: 'schtasks.exe' if name == 'schtasks.exe' else None)
    monkeypatch.setattr(subprocess, 'run', Mock(side_effect=failure) if isinstance(failure, Exception) else Mock(return_value=failure))
    c = WindowsCollector(**isolated)
    assert c._tasks() == []
    assert any('scheduled tasks' in n for n in c.privilege_status()['visibility_notes'])


def test_services_partial(isolated, monkeypatch):
    denied = Mock()
    denied.start_type.side_effect = psutil.AccessDenied()
    automatic = Mock()
    automatic.start_type.return_value = 'automatic'
    automatic.name.return_value = 'Example'
    monkeypatch.setattr(psutil, 'win_service_iter', lambda: iter([denied, automatic]))
    c = WindowsCollector(**isolated)
    assert len(c._services()) == 1
    assert any('service unreadable' in n for n in c.privilege_status()['visibility_notes'])


def test_privileges(isolated, monkeypatch):
    c = WindowsCollector(**isolated)
    assert c.privilege_status()['level'] == 'standard'
    monkeypatch.setattr(ctypes.windll.shell32, 'IsUserAnAdmin', lambda: 1)
    assert c.privilege_status()['level'] == 'administrator'
    monkeypatch.delattr(ctypes, 'windll')
    assert c.privilege_status()['level'] == 'unknown'


@pytest.mark.parametrize('path', [r'C:\Users\fixtureperson\bin\a.exe',
    'c:/users/fixtureperson/bin/a.exe', r'c:\uSeRs\fixtureperson\a.exe',
    r'C:\Users\Fixture Person\a.exe', r'\\server\share\fixtureperson\a.exe',
    '//server/share/fixtureperson/a.exe', r'\\server\Users\fixtureperson\a.exe',
    r'\\?\UNC\server\share\fixtureperson\a.exe'])
def test_windows_path_redaction(path):
    data = redact({'path': path, 'nested': [path], 'cmdline': 'secret'}, username='other')
    encoded = json.dumps(data).lower()
    assert 'fixtureperson' not in encoded and 'fixture person' not in encoded
    assert 'server' not in encoded
    assert 'users' not in encoded
    assert 'secret' not in encoded


def test_unc_paths_never_inspected(isolated, monkeypatch):
    run = powershell(monkeypatch, result([]))
    opened = Mock(side_effect=AssertionError('Network path opened'))
    monkeypatch.setattr(os, 'open', opened)
    c = WindowsCollector(startup_dirs=[r'\\server\share\Startup'])
    assert c.get_trust_signal(r'\\server\share\example.exe') == 'unknown'
    assert c._hasher.hash(r'\\server\share\example.exe') is None
    assert c._startup_folders() == []
    run.assert_not_called()
    opened.assert_not_called()


def test_connections_fallback_and_enumeration(isolated, monkeypatch):
    p = fake_process('')
    del p.net_connections
    p.connections.return_value = []
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c = WindowsCollector(**isolated)
    assert c.list_connections() == []
    p.connections.assert_called_once_with()
    monkeypatch.setattr(psutil, 'process_iter', Mock(side_effect=PermissionError('private-token')))
    data = take_snapshot(c).to_dict()
    assert data['processes'] == []
    assert any('process enumeration' in n for n in data['visibility_notes'])
    assert 'private-token' not in json.dumps(data)


def test_selection_and_import(isolated, monkeypatch):
    importlib.reload(importlib.import_module('dialtone_watcher.collector.windows'))
    monkeypatch.setattr(sys, 'platform', 'win32')
    c = select_collector()
    assert c.os == 'windows'


@pytest.mark.windows_integration
@pytest.mark.skipif(sys.platform != 'win32', reason='Windows integration only')
def test_real_windows_snapshot():
    current = psutil.Process(os.getpid())
    data = take_snapshot().to_dict()
    assert data['os'] == 'windows'
    assert data['processes']
    assert any(p['name'] == redact(current.name()) and p['exe_path'] == redact(current.exe())
               for p in data['processes'])
    assert data['privilege_level'] in {'administrator', 'standard', 'unknown'}
    assert isinstance(data['startup_items'], list) and isinstance(data['connections'], list)
    assert data['visibility_notes']
    encoded = json.dumps(data).lower()
    assert getpass.getuser().lower() not in encoded
    assert 'c:\\\\users\\\\' not in encoded and 'c:/users/' not in encoded
    print(json.dumps({key: len(data[key]) for key in
                      ('processes', 'connections', 'startup_items', 'visibility_notes')}))



def test_task_records_partial(isolated, monkeypatch):
    powershell(monkeypatch, result([{'Name': 'Example', 'Source': '\\Example', 'State': []},
                                   {'LimitedCount': 3}, None]))
    c = WindowsCollector(**isolated)
    tasks = c._tasks()
    assert len(tasks) == 1 and tasks[0]['enabled'] is None
    assert any('3 scheduled tasks' in n for n in c.privilege_status()['visibility_notes'])


def test_startup_directory_unreadable(isolated, monkeypatch, tmp_path):
    startup = tmp_path / 'Startup'
    startup.mkdir()
    c = WindowsCollector(startup_dirs=[startup])
    monkeypatch.setattr(Path, 'iterdir', Mock(side_effect=PermissionError('private-token')))
    assert c._startup_folders() == []
    assert any('directory unreadable' in n for n in c.privilege_status()['visibility_notes'])
    assert 'private-token' not in json.dumps(c.privilege_status())


def test_service_enumeration_denied(isolated, monkeypatch):
    monkeypatch.setattr(psutil, 'win_service_iter', Mock(side_effect=psutil.AccessDenied()))
    c = WindowsCollector(**isolated)
    assert c._services() == []
    assert any('enumeration unavailable' in n for n in c.privilege_status()['visibility_notes'])


def test_windows_home_case_boundary():
    data = redact(r'c:\profiles\Fixture Person\app.exe', username='other', home=r'C:\Profiles\Fixture Person')
    assert data == r'~\app.exe'
