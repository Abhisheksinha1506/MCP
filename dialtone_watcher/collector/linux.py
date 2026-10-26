"""Offline Linux collector. Queries local package databases and startup metadata."""
from collections import Counter
import configparser
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time

import psutil

from .base import Collector
from .common import ExecutableHasher
from ..privacy import redact

_PROCESS_ERRORS = (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess)
_PACKAGE = re.compile(r'[A-Za-z0-9][A-Za-z0-9+_.:@~-]*\Z')
_UNIT = re.compile(r'[A-Za-z0-9_@.:\\-]+\.(?:service|socket|timer|path|target|mount|automount|swap)\Z')


class LinuxCollector(Collector):
    """Create one instance per snapshot: caches, budgets and notes are local to it."""

    os = 'linux'

    def __init__(self, *, autostart_dirs=None, crontab_path='/etc/crontab',
                 cron_dir='/etc/cron.d', mounts_path='/proc/self/mounts',
                 max_hash_bytes=200 * 1024 * 1024, max_binaries=100,
                 timeout=3, inspection_seconds=10):
        self.autostart_dirs = list(autostart_dirs) if autostart_dirs is not None else [
            Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config') / 'autostart',
            Path('/etc/xdg/autostart')]
        self.crontab_path = Path(crontab_path)
        self.cron_dir = Path(cron_dir)
        self.mounts_path = Path(mounts_path)
        self.max_hash_bytes = max_hash_bytes
        self.max_binaries = max_binaries
        self.timeout = timeout
        self.inspection_seconds = inspection_seconds
        self._failures = Counter()
        self._owners = {}
        self._hasher = ExecutableHasher(self._note, max_bytes=max_hash_bytes, max_binaries=max_binaries)
        self._lookup_seconds = 0.0
        self._lookup_calls = 0
        self._kernel_threads = set()
        self._tools = {name: shutil.which(name) for name in
                       ('dpkg', 'rpm', 'pacman', 'systemctl', 'crontab')}
        self.package_manager = next((name for name in ('dpkg', 'rpm', 'pacman')
                                     if self._tools[name]), None)
        self._hidepid = self._read_hidepid()
        if self.package_manager is None:
            self._note('package ownership', 'no supported package manager on PATH')

    def _note(self, source, reason, count=1):
        self._failures[(source, reason)] += count

    def _read_text(self, path, source):
        try:
            # Only startup configuration and mount metadata; never returned raw.
            return path.read_text(encoding='utf-8', errors='replace')
        except FileNotFoundError:
            return None
        except OSError:
            self._note(source, 'file unreadable')
            return None

    def _files(self, directory, source):
        try:
            return sorted(Path(directory).iterdir())
        except FileNotFoundError:
            return []
        except OSError:
            self._note(source, 'directory unreadable')
            return []

    def _read_hidepid(self):
        text = self._read_text(self.mounts_path, 'proc mount options')
        if text is None:
            self._note('proc mount options', 'hidepid configuration could not be inspected')
            return None
        modes = set()
        for line in text.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[1] == '/proc' and fields[2] == 'proc':
                modes.update(opt for opt in fields[3].split(',')
                             if opt.startswith('hidepid=') and opt not in ('hidepid=0', 'hidepid=off'))
        return sorted(modes)

    def _run(self, command, source):
        try:
            return subprocess.run(command, capture_output=True, text=True,
                timeout=self.timeout, check=False,
                env={**os.environ, 'LC_ALL': 'C', 'LANG': 'C',
                     'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'})
        except subprocess.TimeoutExpired:
            self._note(source, 'tool timed out')
        except OSError:
            self._note(source, 'tool missing or unavailable')
        return None

    def _ownership(self, paths):
        """Batch up to 64 literal paths: local database queries, never installs."""
        pending = list(dict.fromkeys(p for p in paths if p and p not in self._owners))
        for path in pending:
            self._owners[path] = None
        if self.package_manager is None:
            return
        for start in range(0, len(pending), 64):
            group = pending[start:start + 64]
            if self._lookup_seconds >= self.inspection_seconds:
                self._note('package ownership', 'snapshot time budget exceeded', len(group))
                continue
            # Wildcards have search semantics in dpkg -S even without a shell.
            safe = [p for p in group if p.startswith('/') and not any(c in p for c in '*?[]\n\r')]
            self._note('package ownership', 'nonliteral path skipped', len(group) - len(safe))
            if not safe:
                continue
            manager = self.package_manager
            options = {'dpkg': ['-S'], 'rpm': ['-qf', '--qf', '[%{=NAME}: %{FILENAMES}\n]'],
                       'pacman': ['-Qo']}[manager]
            before = time.monotonic()
            result = self._run([self._tools[manager], *options, '--', *safe], 'package ownership')
            self._lookup_seconds += time.monotonic() - before
            self._lookup_calls += 1
            if result is None:
                continue
            # rpm emits every owned filename so mixed owned/unowned batches
            # retain exact associations without trusting output order.
            if manager == 'rpm':
                self._parse_rpm(result.stdout, safe)
            else:
                for line in result.stdout.splitlines():
                    if manager == 'dpkg':
                        owner, sep, path = line.partition(': ')
                        if sep and path in safe and _PACKAGE.fullmatch(owner):
                            self._owners[path] = owner
                    else:
                        path, sep, owner = line.partition(' is owned by ')
                        parts = owner.rsplit(' ', 1)
                        if sep and path in safe and len(parts) == 2 and _PACKAGE.fullmatch(parts[0]):
                            self._owners[path] = parts[0]
            for path in safe:
                if self._owners[path] is None:
                    # A failed or unrecognized lookup is never evidence of junk.
                    unowned_messages = {
                        'dpkg': f'no path found matching pattern {path}',
                        'rpm': f'file {path} is not owned by any package',
                        'pacman': f'No package owns {path}',
                    }
                    diagnostic = result.stdout + '\n' + result.stderr
                    unowned = result.returncode == 1 and unowned_messages[manager] in diagnostic
                    reason = 'not owned by a package' if unowned else 'ownership unavailable or output unrecognized'
                    self._note('package ownership', reason)

    def _parse_rpm(self, output, paths):
        for line in output.splitlines():
            owner, sep, path = line.partition(': ')
            if sep and path in paths and _PACKAGE.fullmatch(owner):
                self._owners[path] = owner

    def get_publisher(self, exe_path):
        self._ownership([exe_path])
        return redact(self._owners.get(exe_path))

    def get_trust_signal(self, exe_path):
        self._ownership([exe_path])
        return 'package_owned' if self._owners.get(exe_path) else 'unknown'

    def _sha256(self, path):
        return self._hasher.hash(path)

    def _processes(self):
        try:
            yield from psutil.process_iter()
        except (*_PROCESS_ERRORS, OSError) as exc:
            self._note('process enumeration', type(exc).__name__)

    def _call(self, process, method, default, source):
        try:
            return getattr(process, method)()
        except (*_PROCESS_ERRORS, OSError) as exc:
            self._note(source, type(exc).__name__)
            return default

    def list_processes(self):
        pending = []
        for process in self._processes():
            path = self._call(process, 'exe', None, 'executable paths')
            if path == '':
                # psutil returns an empty executable for kernel threads.
                self._kernel_threads.add(process.pid)
                continue
            name = self._call(process, 'name', None, 'process names')
            if name is None:
                continue
            memory = self._call(process, 'memory_info', None, 'process memory')
            started = self._call(process, 'create_time', None, 'process start times')
            parent = self._call(process, 'parent', None, 'parent processes')
            parent_name = self._call(parent, 'name', None, 'parent names') if parent else None
            pending.append(dict(name=name, exe_path=path or '',
                cpu_percent=self._call(process, 'cpu_percent', 0.0, 'process CPU'),
                mem_mb=memory.rss / 1048576 if memory else 0.0,
                started_at=datetime.fromtimestamp(started, timezone.utc).isoformat() if started else None,
                parent=parent_name))
        paths = list(dict.fromkeys(p['exe_path'] for p in pending if p['exe_path']))
        self._ownership(paths[:self.max_binaries])
        for path in paths[self.max_binaries:]:
            if path not in self._owners:
                self._owners[path] = None
                self._note('package ownership', 'snapshot binary budget exceeded')
        for row in pending:
            path = row['exe_path']
            row.update(publisher=self.get_publisher(path), trust_signal=self.get_trust_signal(path),
                       sha256=self._sha256(path))
        return redact(pending)

    def list_connections(self):
        rows = []
        for process in self._processes():
            if self._call(process, 'exe', None, 'connection executable paths') == '':
                self._kernel_threads.add(process.pid)
                continue
            name = self._call(process, 'name', None, 'connection process names')
            if name is None:
                continue
            method = 'net_connections' if hasattr(process, 'net_connections') else 'connections'
            for connection in self._call(process, method, [], 'per-process connections'):
                if connection.family not in (socket.AF_INET, socket.AF_INET6) or not connection.raddr:
                    continue
                rows.append(dict(process_name=name, remote_host=connection.raddr[0],
                    remote_port=connection.raddr[1],
                    protocol='tcp' if connection.type == socket.SOCK_STREAM else 'udp',
                    resolved_domain=None))
        return redact(rows)

    def _systemd(self):
        if not self._tools['systemctl']:
            self._note('systemd startup', 'systemctl missing')
            return []
        rows = []
        for scope in ('system', 'user'):
            result = self._run([self._tools['systemctl'], '--' + scope,
                'list-unit-files', '--state=enabled', '--no-legend', '--no-pager', '--plain'],
                'systemd ' + scope)
            if result is None:
                continue
            if result.returncode != 0:
                self._note('systemd ' + scope, 'unit inventory unavailable; bus or permissions may be limited')
                continue
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'enabled' and _UNIT.fullmatch(parts[0]):
                    rows.append(dict(name=parts[0], kind='systemd', path='', enabled=True,
                                     source='systemd ' + scope))
        return rows

    def _autostart(self):
        rows = []
        # A user file overrides an identically named system file, including Hidden=true.
        seen = set()
        for directory in self.autostart_dirs:
            for path in self._files(directory, 'XDG autostart'):
                if path.suffix != '.desktop' or path.name in seen:
                    continue
                seen.add(path.name)
                text = self._read_text(path, 'XDG autostart')
                if text is None:
                    continue
                parser = configparser.ConfigParser(interpolation=None, strict=False)
                try:
                    parser.read_string(text)
                    entry = parser['Desktop Entry']
                    if entry.get('Type', 'Application') != 'Application':
                        continue
                    hidden = entry.getboolean('Hidden', fallback=False)
                    enabled = not hidden and entry.getboolean('X-GNOME-Autostart-enabled', fallback=True)
                    # Exec strings can embed secrets or shell scripts. Never return them.
                    # Desktop ID is sufficient to identify the startup configuration.
                    conditional = 'OnlyShowIn' in entry or 'NotShowIn' in entry or 'TryExec' in entry
                    rows.append(dict(name=path.name, kind='xdg_autostart', path='',
                        enabled=None if enabled and conditional else enabled, source=str(path)))
                    if conditional:
                        self._note('XDG autostart', 'desktop-specific conditions not evaluated')
                except (configparser.Error, KeyError, ValueError):
                    self._note('XDG autostart', 'malformed desktop entry')
        return rows

    def _cron_rows(self, text, source, *, system=False):
        rows = []
        for line in text.splitlines():
            value = line.strip()
            if not value or value.startswith('#') or re.match(r'[A-Za-z_][A-Za-z0-9_]*\s*=', value):
                continue
            # Validate structure only. Never retain usernames, commands, arguments,
            # environment values or comments, including inline credentials.
            fields = value.split(None, (2 if system else 1) if value.startswith('@') else (6 if system else 5))
            required = (3 if system else 2) if value.startswith('@') else (7 if system else 6)
            if len(fields) < required:
                self._note('cron startup', 'malformed entry skipped')
                continue
            if value.startswith('@') and fields[0] not in {
                '@reboot', '@yearly', '@annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly'}:
                self._note('cron startup', 'unsupported schedule skipped')
                continue
            rows.append(dict(name=f'Scheduled entry {len(rows) + 1}', kind='cron', path='',
                             enabled=True, source=source))
        return rows

    def _cron(self):
        rows = []
        if self._tools['crontab']:
            result = self._run([self._tools['crontab'], '-l'], 'user crontab')
            if result is not None:
                if result.returncode == 0:
                    rows.extend(self._cron_rows(result.stdout, 'user crontab'))
                elif result.returncode == 1 and result.stderr.strip().startswith('no crontab for '):
                    pass
                else:
                    self._note('user crontab', 'inventory unavailable')
        else:
            self._note('user crontab', 'crontab tool missing')
        text = self._read_text(self.crontab_path, 'system crontab')
        if text is not None:
            rows.extend(self._cron_rows(text, str(self.crontab_path), system=True))
        for path in self._files(self.cron_dir, 'cron directories'):
            if not re.fullmatch(r'[A-Za-z0-9_-]+', path.name):
                continue
            text = self._read_text(path, 'cron files')
            if text is not None:
                rows.extend(self._cron_rows(text, str(path), system=True))
        return rows

    def startup_items(self):
        return redact([*self._systemd(), *self._autostart(), *self._cron()])

    def privilege_status(self):
        root = os.geteuid() == 0
        notes = [f'{count} {source} operations limited: {reason}.'
                 for (source, reason), count in sorted(self._failures.items()) if count]
        if self._kernel_threads:
            notes.append(f'{len(self._kernel_threads)} processes without executable paths skipped (normally kernel threads).')
        if self._hidepid:
            notes.append('proc has ' + ', '.join(self._hidepid) +
                         '; other accounts may be hidden. Completely hidden processes cannot be counted.')
        if not root:
            notes.append('Not running as root: other accounts\' processes, connections and protected startup files may be hidden; invisible processes cannot be counted.')
        notes.append(f'Package ownership: {self._lookup_calls} local database queries in {self._lookup_seconds:.3f} seconds.')
        notes.append('CPU percentages are nonblocking first samples and may be zero.')
        notes.append('Startup definitions indicate configuration, not current execution; cron entries include recurring jobs. Only the current account user units and crontab are inspected.')
        return redact(dict(level='root' if root else 'standard', visibility_notes=notes,
            guidance='For broader process and startup visibility, run manually with sudo from a trusted local environment. '
                     'Root may still be limited by proc hidepid, namespaces or security policies. '
                     'An administrator can review proc mount policy; this collector never changes it. '
                     'Run in the desktop login session for user systemd visibility; unavailable tools must be installed separately. '
                     'Exited processes cannot be recovered.'))
