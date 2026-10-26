import getpass
import hashlib
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

from dialtone_watcher.collector.linux import LinuxCollector
from dialtone_watcher.privacy import redact
from dialtone_watcher.snapshot import select_collector, take_snapshot

FIXTURES = Path(__file__).parent / 'fixtures/linux'


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    """No unit test reads real Linux configuration or executes OS tools."""
    monkeypatch.setattr(shutil, 'which', lambda name: None)
    monkeypatch.setattr(os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(subprocess, 'run', Mock(side_effect=AssertionError('Unexpected subprocess')))
    return dict(autostart_dirs=[], crontab_path=tmp_path / 'crontab',
                cron_dir=tmp_path / 'cron.d', mounts_path=FIXTURES / 'mounts.txt')


def result(stdout='', code=0, stderr=''):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def process(path='/usr/bin/example'):
    p = Mock()
    p.exe.return_value = path
    p.name.return_value = 'Example'
    p.memory_info.return_value = SimpleNamespace(rss=1048576)
    p.create_time.return_value = 1700000000
    p.parent.return_value = None
    p.cpu_percent.return_value = 0.0
    p.net_connections.return_value = [SimpleNamespace(raddr=('192.0.2.1', 443),
        family=socket.AF_INET, type=socket.SOCK_STREAM)]
    return p


def tool(monkeypatch, manager):
    which = Mock(side_effect=lambda name: '/usr/bin/' + name if name == manager else None)
    monkeypatch.setattr(shutil, 'which', which)
    return which


@pytest.mark.parametrize('manager,publisher', [('dpkg', 'example'), ('rpm', 'example'), ('pacman', 'example')])
def test_package_ownership_batch_cache(isolated, monkeypatch, manager, publisher):
    which = tool(monkeypatch, manager)
    run = Mock(return_value=result((FIXTURES / f'{manager}.txt').read_text()))
    monkeypatch.setattr(subprocess, 'run', run)
    c = LinuxCollector(**isolated)
    c._ownership(['/usr/bin/example', '/usr/bin/python3', '/usr/bin/example'])
    assert c.package_manager == manager
    assert c.get_publisher('/usr/bin/example') == publisher
    assert c.get_trust_signal('/usr/bin/example') == 'package_owned'
    assert c.get_trust_signal('/usr/bin/python3') == 'package_owned'
    assert c._lookup_calls == 1
    assert c._lookup_seconds >= 0
    assert run.call_count == 1
    assert which.call_count == 5  # Detection occurs only at initialization.
    args = run.call_args.args[0]
    assert args[-3:] == ['--', '/usr/bin/example', '/usr/bin/python3']
    assert run.call_args.kwargs['timeout'] == 3
    assert not run.call_args.kwargs.get('shell', False)
    assert run.call_args.kwargs['env']['LC_ALL'] == 'C'


@pytest.mark.parametrize('manager,message', [
    ('dpkg', 'dpkg-query: no path found matching pattern /opt/example'),
    ('rpm', 'file /opt/example is not owned by any package'),
    ('pacman', 'error: No package owns /opt/example'),
])
def test_unowned_is_unknown(isolated, monkeypatch, manager, message):
    tool(monkeypatch, manager)
    monkeypatch.setattr(subprocess, 'run', Mock(return_value=result(code=1, stderr=message)))
    c = LinuxCollector(**isolated)
    assert c.get_publisher('/opt/example') is None
    assert c.get_trust_signal('/opt/example') == 'unknown'
    notes = c.privilege_status()['visibility_notes']
    assert any('not owned by a package' in n for n in notes)
    assert 'malicious' not in json.dumps(notes)


@pytest.mark.parametrize('manager', ['dpkg', 'rpm', 'pacman'])
@pytest.mark.parametrize('failure', [FileNotFoundError(), subprocess.TimeoutExpired('tool', 3),
                                     result('malformed output'), result(code=2, stderr='database unavailable')])
def test_failed_queries(isolated, monkeypatch, manager, failure):
    tool(monkeypatch, manager)
    run = Mock(side_effect=failure) if isinstance(failure, Exception) else Mock(return_value=failure)
    monkeypatch.setattr(subprocess, 'run', run)
    c = LinuxCollector(**isolated)
    assert c.get_trust_signal('/opt/example') == 'unknown'
    assert c.get_publisher('/opt/example') is None
    assert run.call_count == 1
    assert any('package ownership operations limited' in n for n in c.privilege_status()['visibility_notes'])


def test_missing_manager(isolated):
    c = LinuxCollector(**isolated)
    assert c.package_manager is None
    assert c.get_trust_signal('/bin/example') == 'unknown'
    assert any('no supported package manager' in n for n in c.privilege_status()['visibility_notes'])


def test_partial_owned_batch(isolated, monkeypatch):
    tool(monkeypatch, 'dpkg')
    run = Mock(return_value=result('example: /usr/bin/example\n', 1,
                                  'dpkg-query: no path found matching pattern /opt/example'))
    monkeypatch.setattr(subprocess, 'run', run)
    c = LinuxCollector(**isolated)
    c._ownership(['/usr/bin/example', '/opt/example'])
    assert c.get_trust_signal('/usr/bin/example') == 'package_owned'
    assert c.get_trust_signal('/opt/example') == 'unknown'
    assert run.call_count == 1


def test_nonliteral_and_time_budget(isolated, monkeypatch):
    tool(monkeypatch, 'dpkg')
    c = LinuxCollector(**isolated)
    assert c.get_trust_signal('/opt/*') == 'unknown'
    c = LinuxCollector(**isolated, inspection_seconds=0)
    assert c.get_trust_signal('/usr/bin/example') == 'unknown'


@pytest.mark.parametrize('error', [psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess])
def test_snapshot_partial_visibility(isolated, monkeypatch, error):
    blocked = process()
    blocked.name.side_effect = error(999)
    partial = process()
    partial.exe.side_effect = error(998)
    partial.net_connections.side_effect = error(998)
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([blocked, partial]))
    c = LinuxCollector(**isolated)
    snapshot = take_snapshot(c).to_dict()
    assert snapshot['os'] == 'linux'
    assert len(snapshot['processes']) == 1
    assert snapshot['connections'] == []
    assert any(error.__name__ in n for n in snapshot['visibility_notes'])
    assert any('per-process connections' in n for n in snapshot['visibility_notes'])
    assert any('hidepid=2' in n for n in snapshot['visibility_notes'])
    assert any('cannot be counted' in n for n in snapshot['visibility_notes'])
    partial.cmdline.assert_not_called()
    blocked.username.assert_not_called()


@pytest.mark.parametrize('method', ['memory_info', 'create_time', 'parent', 'cpu_percent'])
@pytest.mark.parametrize('error', [psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess])
def test_per_process_errors(isolated, monkeypatch, method, error):
    p = process()
    getattr(p, method).side_effect = error(999)
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c = LinuxCollector(**isolated, max_binaries=0)
    assert len(c.list_processes()) == 1
    assert any(error.__name__ in n for n in c.privilege_status()['visibility_notes'])


def test_kernel_threads(isolated, monkeypatch):
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([process('')]))
    c = LinuxCollector(**isolated)
    assert c.list_processes() == []
    notes = c.privilege_status()['visibility_notes']
    assert any('1 processes without executable paths skipped' in n for n in notes)
    assert not any('executable paths operations limited' in n for n in notes)


def test_connection_protocols_and_fallback(isolated, monkeypatch):
    p = process()
    p.net_connections.return_value += [SimpleNamespace(raddr=('2001:db8::1', 53),
        family=socket.AF_INET6, type=socket.SOCK_DGRAM),
        SimpleNamespace(raddr=(), family=socket.AF_INET, type=socket.SOCK_STREAM),
        SimpleNamespace(raddr='local', family=socket.AF_UNIX, type=socket.SOCK_STREAM)]
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c = LinuxCollector(**isolated)
    assert [r['protocol'] for r in c.list_connections()] == ['tcp', 'udp']
    del p.net_connections
    p.connections.return_value = []
    assert c.list_connections() == []
    p.connections.assert_called_once_with()


def test_enumeration_failure(isolated, monkeypatch):
    def denied():
        raise PermissionError('private diagnostic')
    monkeypatch.setattr(psutil, 'process_iter', denied)
    snapshot = take_snapshot(LinuxCollector(**isolated)).to_dict()
    assert snapshot['processes'] == []
    assert any('process enumeration' in n for n in snapshot['visibility_notes'])
    assert 'private diagnostic' not in json.dumps(snapshot)


def test_startup_fixtures(isolated, monkeypatch, tmp_path):
    monkeypatch.setattr(shutil, 'which', lambda name: '/usr/bin/' + name if name in ('systemctl', 'crontab') else None)
    def run(args, **kwargs):
        return result((FIXTURES / ('systemctl.txt' if 'list-unit-files' in args else 'user.crontab')).read_text())
    mocked = Mock(side_effect=run)
    monkeypatch.setattr(subprocess, 'run', mocked)
    desktop_dir = tmp_path / 'autostart'
    desktop_dir.mkdir()
    shutil.copyfile(FIXTURES / 'example.desktop', desktop_dir / 'example.desktop')
    (desktop_dir / 'conditional.desktop').write_text('[Desktop Entry]\nType=Application\nOnlyShowIn=GNOME;\n')
    cron_dir = isolated['cron_dir']
    cron_dir.mkdir()
    shutil.copyfile(FIXTURES / 'system.crontab', cron_dir / 'example')
    c = LinuxCollector(**{**isolated, 'autostart_dirs': [desktop_dir],
                         'crontab_path': FIXTURES / 'system.crontab'})
    p = process('/home/fixtureperson/bin/example')
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c._hasher.hash = Mock(return_value=None)
    snapshot = take_snapshot(c).to_dict()
    items = snapshot['startup_items']
    assert len([i for i in items if i['kind'] == 'systemd']) == 8
    assert len([i for i in items if i['kind'] == 'cron']) == 6
    assert next(i for i in items if i['name'] == 'example.desktop')['enabled'] is True
    assert next(i for i in items if i['name'] == 'conditional.desktop')['enabled'] is None
    assert {i['source'] for i in items if i['kind'] == 'systemd'} == {'systemd user', 'systemd system'}
    encoded = json.dumps(items)
    for private in ('private-token', 'fixtureperson', '/home/', '/root', 'MAILTO', 'Exec=', '--token'):
        assert private not in encoded
    assert mocked.call_count == 3
    print(json.dumps({key: len(snapshot[key]) for key in
                      ('processes', 'connections', 'startup_items', 'visibility_notes')}))


def test_startup_missing_tools(isolated):
    c = LinuxCollector(**isolated)
    assert c.startup_items() == []
    notes = c.privilege_status()['visibility_notes']
    assert any('systemctl missing' in n for n in notes)
    assert any('crontab tool missing' in n for n in notes)


def test_systemd_crontab_failure(isolated, monkeypatch):
    monkeypatch.setattr(shutil, 'which', lambda name: '/usr/bin/' + name if name in ('systemctl', 'crontab') else None)
    monkeypatch.setattr(subprocess, 'run', Mock(return_value=result(code=1, stderr='private diagnostic')))
    c = LinuxCollector(**isolated)
    assert c.startup_items() == []
    notes = c.privilege_status()['visibility_notes']
    assert any('systemd system' in n for n in notes)
    assert any('systemd user' in n for n in notes)
    assert 'private diagnostic' not in json.dumps(notes)


def test_autostart_override_and_malformed(isolated, tmp_path):
    user = tmp_path / 'user'
    system = tmp_path / 'system'
    user.mkdir()
    system.mkdir()
    (system / 'example.desktop').write_text('[Desktop Entry]\nType=Application\n')
    (user / 'example.desktop').write_text('[Desktop Entry]\nHidden=true\n')
    (user / 'broken.desktop').write_text('invalid')
    c = LinuxCollector(**{**isolated, 'autostart_dirs': [user, system]})
    items = c.startup_items()
    assert len(items) == 1
    assert items[0]['enabled'] is False
    assert any('malformed desktop' in n for n in c.privilege_status()['visibility_notes'])


def test_unreadable_files(isolated, monkeypatch, tmp_path):
    def denied(*args, **kwargs):
        raise PermissionError('private diagnostic')
    c = LinuxCollector(**isolated)
    monkeypatch.setattr(Path, 'read_text', denied)
    monkeypatch.setattr(Path, 'iterdir', denied)
    assert c.startup_items() == []
    assert c._read_hidepid() is None
    notes = c.privilege_status()['visibility_notes']
    assert any('unreadable' in n for n in notes)
    assert 'private diagnostic' not in json.dumps(notes)


def test_hashes(isolated, tmp_path):
    path = tmp_path / 'executable'
    path.write_bytes(b'example')
    c = LinuxCollector(**isolated)
    expected = hashlib.sha256(b'example').hexdigest()
    assert c._sha256(str(path)) == expected
    path.write_bytes(b'changed')
    assert c._sha256(str(path)) == expected
    assert LinuxCollector(**isolated, max_hash_bytes=1)._sha256(str(path)) is None
    assert LinuxCollector(**isolated, max_binaries=0)._sha256(str(path)) is None
    assert c._sha256(str(tmp_path / 'missing')) is None


def test_fifo_hash_does_not_block(isolated, tmp_path):
    if not hasattr(os, 'mkfifo'):
        pytest.skip('FIFO creation unavailable')
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    c = LinuxCollector(**isolated)
    assert c._sha256(str(fifo)) is None
    assert any('not a regular file' in n for n in c.privilege_status()['visibility_notes'])


@pytest.mark.parametrize('home', ['/home/fixtureperson', '/root'])
def test_privacy(isolated, monkeypatch, tmp_path, home):
    p = process(home + '/bin/example')
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    snapshot = take_snapshot(LinuxCollector(**isolated)).to_dict()
    encoded = json.dumps(snapshot)
    assert home not in encoded
    assert 'fixtureperson' not in encoded
    assert snapshot['processes'][0]['exe_path'] == '~/bin/example'


def test_selection(isolated, monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'linux2')
    assert isinstance(select_collector(), LinuxCollector)
    monkeypatch.setattr(sys, 'platform', 'freebsd')
    with pytest.raises(NotImplementedError):
        select_collector()


def test_root_privilege_survives_redaction(isolated, monkeypatch):
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(getpass, 'getuser', lambda: 'root')
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([]))
    data = take_snapshot(LinuxCollector(**isolated)).to_dict()
    assert data['privilege_level'] == 'root'
    assert redact('/root/bin/example') == '~/bin/example'
    assert redact('/rooted/path') == '/rooted/path'
    assert redact({'username': 'root'}) == {}


@pytest.mark.linux_integration
@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux integration only')
def test_real_linux_snapshot():
    c = LinuxCollector()
    current = psutil.Process(os.getpid())
    snapshot = take_snapshot(c).to_dict()
    assert snapshot['os'] == 'linux'
    assert snapshot['processes']
    assert any(p['name'] == redact(current.name()) and p['exe_path'] == redact(current.exe())
               for p in snapshot['processes'])
    assert isinstance(snapshot['connections'], list)
    assert isinstance(snapshot['startup_items'], list)
    assert snapshot['visibility_notes']
    encoded = json.dumps(snapshot)
    for home in ('/home/', '/root/', '/Users/', str(Path.home())):
        if home != '/':
            assert home not in encoded
    if getpass.getuser() != 'root':
        assert getpass.getuser() not in encoded
    expected = os.environ.get('DIALTONE_EXPECT_PACKAGE_MANAGER')
    if expected:
        assert c.package_manager == expected
        # Exercise the actual distro's package database, not just PATH detection.
        assert c.get_trust_signal(shutil.which(expected)) == 'package_owned'
        assert c.get_publisher(shutil.which(expected))
    print(json.dumps({key: len(snapshot[key]) for key in
                      ('processes', 'connections', 'startup_items', 'visibility_notes')}))


@pytest.mark.parametrize('manager', ['dpkg', 'rpm', 'pacman'])
def test_batch_limit_and_count(isolated, monkeypatch, manager):
    tool(monkeypatch, manager)
    run = Mock(return_value=result())
    monkeypatch.setattr(subprocess, 'run', run)
    c = LinuxCollector(**isolated)
    c._ownership([f'/opt/program{i}' for i in range(100)])
    assert c._lookup_calls == 2
    assert [len(call.args[0][call.args[0].index('--') + 1:]) for call in run.call_args_list] == [64, 36]


def test_hidepid_disabled(isolated, tmp_path):
    path = tmp_path / 'mounts'
    path.write_text('proc /proc proc rw,hidepid=0 0 0')
    c = LinuxCollector(**{**isolated, 'mounts_path': path})
    assert c._hidepid == []
    assert not any('proc has hidepid' in n for n in c.privilege_status()['visibility_notes'])


def test_no_crontab_is_not_a_permission_error(isolated, monkeypatch):
    tool(monkeypatch, 'crontab')
    monkeypatch.setattr(subprocess, 'run', Mock(return_value=result(code=1, stderr='no crontab for fixtureperson')))
    c = LinuxCollector(**isolated)
    assert c.startup_items() == []
    assert not any('user crontab operations limited' in n for n in c.privilege_status()['visibility_notes'])


def test_parent_disappeared(isolated, monkeypatch):
    p = process()
    parent = Mock()
    parent.name.side_effect = psutil.NoSuchProcess(999)
    p.parent.return_value = parent
    monkeypatch.setattr(psutil, 'process_iter', lambda: iter([p]))
    c = LinuxCollector(**isolated, max_binaries=0)
    assert c.list_processes()[0]['parent'] is None
    assert any('parent names' in n for n in c.privilege_status()['visibility_notes'])
