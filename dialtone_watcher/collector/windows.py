"""Read-only Windows metadata. Windows-only imports are lazy; no remote queries."""
from collections import Counter
import csv
import io
import importlib
import json
import ntpath
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import stat
import time

import psutil

from .base import Collector
from .common import ExecutableHasher, ProcessReader, is_network_path
from ..privacy import redact

# Constant program text: executable paths travel only as JSON over stdin.
_SIGNATURE_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$paths = @([Console]::In.ReadToEnd() | ConvertFrom-Json)
$offline = $false
try {
    $active = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
        Where-Object { $_.OperationalStatus -eq 'Up' -and $_.NetworkInterfaceType -ne 'Loopback' })
    $offline = ($active.Count -eq 0)
} catch { $offline = $false }
$results = @(foreach ($path in $paths) {
    if (-not $offline) {
        [pscustomobject]@{ Path=$path; Status='OfflineRequired'; Subject=$null }
        continue
    }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        [pscustomobject]@{ Path=$path; Status=$sig.Status.ToString(); Subject=$sig.SignerCertificate.Subject }
    } catch {
        [pscustomobject]@{ Path=$path; Status='InspectionError'; Subject=$null }
    }
})
ConvertTo-Json -InputObject $results -Depth 3 -Compress
'''

_TASK_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$taskErrors = @()
$items = @(Get-ScheduledTask -ErrorAction SilentlyContinue -ErrorVariable taskErrors | Where-Object {
    @($_.Triggers | Where-Object {
        $_.CimClass.CimClassName -in @('MSFT_TaskLogonTrigger','MSFT_TaskBootTrigger')
    }).Count -gt 0
} | ForEach-Object {
    [pscustomobject]@{ Name=$_.TaskName; Source=$_.TaskPath; State=$_.State.ToString() }
})
if ($taskErrors.Count -gt 0) { $items += [pscustomobject]@{ LimitedCount=$taskErrors.Count } }
ConvertTo-Json -InputObject $items -Depth 3 -Compress
'''

_STATUS = {'Valid', 'NotSigned', 'HashMismatch', 'UnknownError', 'NotTrusted',
           'NotSupportedFileFormat', 'Incompatible', 'InspectionError', 'OfflineRequired'}


def _cn(subject):
    if not isinstance(subject, str):
        return None
    match = re.search(r'(?:^|,\s*)CN\s*=\s*("(?:[^"]|"")*"|(?:\\.|[^,])*)', subject, re.I)
    if not match:
        return None
    value = match[1].strip()
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1].replace('""', '"')
    return re.sub(r'\\(.)', r'\1', value) or None


class WindowsCollector(Collector):
    """One instance per snapshot. Only queries; never elevates or changes settings."""

    os = 'windows'

    def __init__(self, *, startup_dirs=None, timeout=10, max_binaries=100,
                 max_hash_bytes=200 * 1024 * 1024, inspection_seconds=15):
        self.timeout = timeout
        self.max_binaries = max_binaries
        self.inspection_seconds = inspection_seconds
        self._failures = Counter()
        self._signatures = {}
        self._signature_calls = 0
        self._signature_seconds = 0.0
        self._empty_exe = set()
        self._reader = ProcessReader(self._note)
        self._hasher = ExecutableHasher(self._note, max_bytes=max_hash_bytes, max_binaries=max_binaries)
        self._powershell = shutil.which('powershell.exe') or shutil.which('pwsh.exe')
        self._schtasks = shutil.which('schtasks.exe')
        self.startup_dirs = list(startup_dirs) if startup_dirs is not None else [
            ntpath.join(os.environ.get('APPDATA', ntpath.join(str(Path.home()), 'AppData', 'Roaming')),
                        'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            ntpath.join(os.environ.get('PROGRAMDATA', r'C:\ProgramData'),
                        'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')]

    def _note(self, source, reason, count=1):
        if count:
            self._failures[(source, reason)] += count

    def _ps(self, script, *, source, payload=None):
        if not self._powershell:
            self._note(source, 'PowerShell unavailable')
            return None
        try:
            result = subprocess.run([self._powershell, '-NoProfile', '-NonInteractive',
                '-Command', script], input=payload, capture_output=True, text=True,
                encoding='utf-8', errors='replace', timeout=self.timeout, check=False)
            if result.returncode != 0:
                self._note(source, 'PowerShell execution blocked or query failed')
                return None
            parsed = json.loads(result.stdout.lstrip('\ufeff'))
            if isinstance(parsed, dict):
                return [parsed]
            if isinstance(parsed, list):
                return parsed
            self._note(source, 'JSON result is not a list or object')
        except subprocess.TimeoutExpired:
            self._note(source, 'PowerShell timed out')
        except OSError:
            self._note(source, 'PowerShell missing or execution blocked')
        except (ValueError, TypeError):
            self._note(source, 'malformed JSON output')
        return None

    def _inspect_signatures(self, paths):
        pending = []
        for path in dict.fromkeys(p for p in paths if p):
            key = ntpath.normcase(path)
            if key in self._signatures:
                continue
            self._signatures[key] = (None, 'unknown')
            if is_network_path(path):
                self._note('signature inspection', 'network or device path skipped')
            elif len(self._signatures) > self.max_binaries:
                self._note('signature inspection', 'snapshot binary budget exceeded')
            else:
                pending.append(path)
        for offset in range(0, len(pending), 32):
            group = pending[offset:offset + 32]
            if self._signature_seconds >= self.inspection_seconds:
                self._note('signature inspection', 'snapshot time budget exceeded', len(group))
                continue
            before = time.monotonic()
            rows = self._ps(_SIGNATURE_SCRIPT, source='signature inspection',
                            payload=json.dumps(group, ensure_ascii=True))
            self._signature_seconds += time.monotonic() - before
            self._signature_calls += 1
            if rows is None:
                continue
            expected = {ntpath.normcase(p) for p in group}
            seen = set()
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get('Path'), str):
                    self._note('signature inspection', 'malformed signature record')
                    continue
                key = ntpath.normcase(row['Path'])
                if key not in expected or key in seen:
                    self._note('signature inspection', 'unexpected or duplicate signature record')
                    continue
                seen.add(key)
                status = row.get('Status')
                status = status if isinstance(status, str) and status in _STATUS else 'UnrecognizedStatus'
                signal = {'Valid': 'verified', 'NotSigned': 'unsigned'}.get(status, 'unknown')
                publisher = _cn(row.get('Subject')) if status not in {'NotSigned', 'OfflineRequired', 'InspectionError'} else None
                self._signatures[key] = (redact(publisher), signal)
                if signal == 'unknown':
                    self._note('signature inspection', status)
            self._note('signature inspection', 'signature records missing', len(expected - seen))

    def get_publisher(self, exe_path):
        self._inspect_signatures([exe_path])
        return self._signatures.get(ntpath.normcase(exe_path), (None, 'unknown'))[0]

    def get_trust_signal(self, exe_path):
        self._inspect_signatures([exe_path])
        return self._signatures.get(ntpath.normcase(exe_path), (None, 'unknown'))[1]

    def list_processes(self):
        rows = []
        for process in self._reader.processes():
            name = self._reader.call(process, 'name', None, 'process names')
            if name is None:
                continue
            path = self._reader.call(process, 'exe', None, 'executable paths')
            if path == '':
                self._empty_exe.add(process.pid)
            memory = self._reader.call(process, 'memory_info', None, 'process memory')
            started = self._reader.call(process, 'create_time', None, 'process start times')
            parent = self._reader.call(process, 'parent', None, 'parent processes')
            parent_name = self._reader.call(parent, 'name', None, 'parent names') if parent else None
            rows.append(dict(name=name, exe_path=path or '',
                cpu_percent=self._reader.call(process, 'cpu_percent', 0.0, 'process CPU'),
                mem_mb=memory.rss / 1048576 if memory else 0.0,
                started_at=self._reader.timestamp(started), parent=parent_name))
        self._inspect_signatures([row['exe_path'] for row in rows])
        for row in rows:
            path = row['exe_path']
            row.update(publisher=self.get_publisher(path), trust_signal=self.get_trust_signal(path),
                       sha256=self._hasher.hash(path))
        return redact(rows)

    def list_connections(self):
        return self._reader.connections()

    def _registry(self):
        rows = []
        try:
            winreg = importlib.import_module('winreg')
        except ImportError:
            self._note('startup registry', 'winreg unavailable')
            return rows
        base = r'Software\Microsoft\Windows\CurrentVersion'
        # Explicit 32-bit view maps to WOW6432Node on 64-bit Windows. Do not
        # concatenate WOW6432Node with a view flag and enumerate it twice.
        for hive_name in ('HKEY_LOCAL_MACHINE', 'HKEY_CURRENT_USER'):
            for view in ('KEY_WOW64_64KEY', 'KEY_WOW64_32KEY'):
                for branch in ('Run', 'RunOnce'):
                    try:
                        with winreg.OpenKey(getattr(winreg, hive_name), base + '\\' + branch, 0,
                            winreg.KEY_READ | getattr(winreg, view)) as key:
                            count = winreg.QueryInfoKey(key)[1]
                            for index in range(count):
                                try:
                                    name, value, kind = winreg.EnumValue(key, index)
                                    if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                                        continue
                                    # Values are command lines: discard the entire value.
                                    rows.append(dict(name=str(name), kind='registry', path='', enabled=True,
                                        source=f'{hive_name} {branch} {view}'))
                                except OSError:
                                    self._note('startup registry values', 'entry unreadable or disappeared')
                    except FileNotFoundError:
                        pass
                    except OSError:
                        self._note('startup registry keys', 'key unreadable or view unsupported')
        return rows

    def _startup_folders(self):
        rows = []
        for directory in self.startup_dirs:
            if is_network_path(str(directory)):
                self._note('startup folders', 'network or device folder skipped')
                continue
            try:
                folder = Path(directory)
                flags = getattr(folder.lstat(), 'st_file_attributes', 0)
                if folder.is_symlink() or flags & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400):
                    self._note('startup folders', 'link folder skipped')
                    continue
                for path in sorted(folder.iterdir()):
                    if path.name.lower() == 'desktop.ini':
                        continue
                    try:
                        # Do not resolve shortcut targets or follow symlinks/junctions.
                        info = path.lstat()
                        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                            self._note('startup folders', 'link entry skipped')
                            continue
                        if stat.S_ISREG(info.st_mode):
                            rows.append(dict(name=path.name, kind='startup_folder', path=str(path),
                                             enabled=None, source=str(directory)))
                    except OSError:
                        self._note('startup folders', 'entry unreadable')
            except FileNotFoundError:
                pass
            except OSError:
                self._note('startup folders', 'directory unreadable')
        return rows

    def _tasks(self):
        rows = self._ps(_TASK_SCRIPT, source='scheduled tasks')
        items = []
        if rows is None:
            return self._tasks_csv()
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get('LimitedCount'), int):
                self._note('scheduled tasks', 'tasks unreadable or unavailable', max(0, row['LimitedCount']))
                continue
            if (not isinstance(row, dict) or not isinstance(row.get('Name'), str)
                    or not isinstance(row.get('Source'), str)):
                self._note('scheduled tasks', 'malformed task record')
                continue
            state = row.get('State') if isinstance(row.get('State'), str) else None
            enabled = False if state == 'Disabled' else True if state in {'Ready', 'Running', 'Queued'} else None
            items.append(dict(name=row['Name'], kind='scheduled_task', path='', enabled=enabled,
                              source='Task Scheduler ' + row['Source']))
        return items

    def _tasks_csv(self):
        if not self._schtasks:
            self._note('scheduled tasks', 'schtasks fallback unavailable')
            return []
        try:
            result = subprocess.run([self._schtasks, '/query', '/fo', 'csv', '/v'],
                capture_output=True, text=True,
                encoding='oem' if sys.platform == 'win32' else 'utf-8', errors='replace',
                timeout=self.timeout, check=False)
            if result.returncode != 0:
                self._note('scheduled tasks', 'schtasks query blocked or failed')
                return []
            reader = csv.DictReader(io.StringIO(result.stdout.lstrip('\ufeff')), strict=True)
            if not {'TaskName', 'Schedule Type'}.issubset(reader.fieldnames or []):
                self._note('scheduled tasks', 'localized or malformed CSV headers; fallback unavailable')
                return []
            rows = []
            for row in reader:
                schedule = (row.get('Schedule Type') or '').strip().lower()
                if schedule not in {'at logon time', 'at logon', 'at log on',
                                    'at system start up', 'at system startup', 'at startup'}:
                    continue
                name = row.get('TaskName')
                if not name:
                    self._note('scheduled tasks', 'malformed CSV task record')
                    continue
                state = row.get('Scheduled Task State', '')
                enabled = True if state == 'Enabled' else False if state == 'Disabled' else None
                rows.append(dict(name=ntpath.basename(name), kind='scheduled_task', path='',
                    enabled=enabled, source='Task Scheduler ' + ntpath.dirname(name)))
            return rows
        except (OSError, subprocess.TimeoutExpired, csv.Error):
            self._note('scheduled tasks', 'schtasks unavailable, timed out or malformed CSV')
            return []

    def _services(self):
        rows = []
        if not hasattr(psutil, 'win_service_iter'):
            self._note('automatic services', 'Windows service API unavailable')
            return rows
        try:
            for service in psutil.win_service_iter():
                try:
                    if service.start_type() in ('automatic', 'automatic-delayed'):
                        rows.append(dict(name=service.name(), kind='service', path='', enabled=True,
                                         source='Windows Service Control Manager'))
                except (psutil.Error, OSError):
                    self._note('automatic services', 'service unreadable or disappeared')
        except (psutil.Error, OSError):
            self._note('automatic services', 'enumeration unavailable')
        return rows

    def startup_items(self):
        return redact([*self._registry(), *self._startup_folders(), *self._tasks(), *self._services()])

    def privilege_status(self):
        try:
            import ctypes
            administrator = bool(ctypes.windll.shell32.IsUserAnAdmin())
            level = 'administrator' if administrator else 'standard'
        except (AttributeError, OSError):
            level = 'unknown'
            self._note('privilege inspection', 'Administrator status unavailable')
        notes = [f'{count} {source} operations limited: {reason}.'
                 for (source, reason), count in sorted(self._failures.items())]
        if level != 'administrator':
            notes.append('Without Administrator access, protected process metadata, connections, registry keys, scheduled tasks and services may be hidden. Invisible processes cannot be counted.')
        if self._empty_exe:
            notes.append(f'{len(self._empty_exe)} processes without executable paths retained (for example System, Registry or Idle); this is normal.')
        notes.append(f'Authenticode: {self._signature_calls} batch calls in {self._signature_seconds:.3f} seconds.')
        notes.append('Signature checks require all non-loopback adapters to be down; otherwise OfflineRequired leaves trust unknown to avoid certificate network lookups.')
        notes.append('CPU percentages are nonblocking first samples and may be zero.')
        notes.append('Startup inventory shows configuration, not execution. StartupApproved overrides, shortcut targets and other accounts are not inspected.')
        return redact(dict(level=level, visibility_notes=notes,
            guidance='For broader local visibility, manually launch a trusted Python environment with Run as administrator. '
                     'Protected processes can remain hidden even then. PowerShell may be unavailable or blocked by policy; '
                     'this collector never bypasses execution policy or changes settings. Exited processes cannot be recovered.'))
