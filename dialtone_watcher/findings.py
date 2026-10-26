"""Offline explanations of explicit matches and documented signal combinations."""
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from .privacy import redact
from .rules import CAPS, MAX_INPUT, SEVERITIES, RuleSet, load_rules, normalize_domain, normalize_path
from .schema import Finding, Snapshot


@dataclass
class FindingsReport:
    snapshot_id: str
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[dict] = field(default_factory=list)
    allowlisted: list[dict] = field(default_factory=list)
    not_assessed: list[dict] = field(default_factory=list)
    message: str = ('Only visible metadata was assessed. No findings means no matches here; '
                    'it does not establish that a computer is safe or that all activity was visible.')

    def to_dict(self):
        return redact(asdict(self))

    def counts(self):
        return {'by_type': {kind: sum(f.type == kind for f in self.findings)
                            for kind in ('junk', 'telemetry', 'unusual')},
                'by_severity': {level: sum(f.severity == level for f in self.findings)
                                for level in SEVERITIES}}


def _name(value, platform):
    return value if platform == 'linux' else value.casefold()


def _subject(name, path=''):
    text = redact(f'{name} ({path})' if path else name)
    return text if len(text) <= 512 else text[:509] + '...'


def _visibility(notes):
    gaps = []
    informational = ('CPU percentages', 'Package ownership:', 'Authenticode:',
                     'Signature checks require', 'For broader', 'For more')
    for note in notes:
        if not note or note.startswith(informational):
            continue
        lower = note.casefold()
        if 'processes without executable paths' in lower:
            if 'retained' in lower:
                continue  # Normal Windows kernel records are still present.
            sources = {'processes'}
        elif 'not running as root' in lower or 'without administrator' in lower:
            sources = {'processes', 'connections', 'startup_items'}
        elif any(word in lower for word in ('startup', 'registry', 'scheduled task', 'login item', 'crontab', 'cron ', 'automatic services', 'systemd ')):
            sources = {'startup_items'}
        elif 'connection' in lower:
            sources = {'connections'}
        elif any(word in lower for word in ('signature', 'trust', 'powershell', 'offlinerequired')):
            sources = {'trust_signals'}
        elif 'hash' in lower:
            sources = {'executable_hashes'}
        elif any(word in lower for word in ('process', 'proc ', 'hidepid', 'privilege')):
            sources = {'processes'}
        else:
            sources = {'snapshot'}  # Unstructured legacy notes: conservative caveat.
        for source in sorted(sources):
            gaps.append({'source': source, 'status': 'not_assessed', 'reason': redact(note)})
    return gaps


def _action(platform, kind, *, identity=False):
    tool = {'macos': 'Activity Monitor', 'windows': 'Task Manager', 'linux': 'systemctl and your process viewer'}[platform]
    if identity:
        return (f'Review the recorded location and publisher using {tool}. Confirm the identity before '
                'changing a core component or its startup configuration.')
    if kind == 'telemetry':
        return (f'Review the associated app in {tool} and its optional analytics or diagnostics settings. '
                'If you change a setting, record the previous value so you can restore it.')
    startup = {'macos': 'System Settings > General > Login Items',
               'windows': 'Task Manager > Startup apps',
               'linux': 'your desktop startup settings or the corresponding systemctl user unit'}[platform]
    return (f'Review this item using {tool}. If it is optional and unwanted, consider disabling its '
            f'startup entry in {startup}; record the previous setting so it can be re-enabled.')


def _cap(severity, confidence):
    return SEVERITIES[min(SEVERITIES.index(severity), SEVERITIES.index(CAPS[confidence]))]


def _unusual_location(path, platform):
    parts = normalize_path(path, platform).split('/')
    folders = {'tmp', 'temp', 'Downloads'} if platform == 'linux' else {'tmp', 'temp', 'downloads'}
    return any(part in folders for part in parts[:-1])


def analyze(snapshot: Snapshot, rules: RuleSet | None = None, *, min_severity='info') -> FindingsReport:
    """Pure metadata analysis; never collect, resolve, persist, or modify anything."""
    if min_severity not in SEVERITIES:
        raise ValueError('min_severity must be info, low or medium')
    if snapshot.os not in {'macos', 'windows', 'linux'}:
        raise ValueError('unsupported snapshot OS')
    rules = rules if rules is not None else load_rules()
    platform = snapshot.os
    report = FindingsReport(snapshot.id)
    report.not_assessed.extend(_visibility(snapshot.visibility_notes))
    core_rules = [r for r in rules.section('core_os_allowlist') if r.applies(platform)]
    bloat_rules = rules.section('known_bloatware')
    candidates = []
    processes_by_name = defaultdict(list)
    allowed = set()
    identities = {}
    seen_findings = set()
    finding_sources = {}

    def gap(source, reason, subject=None):
        entry = {'source': source, 'status': 'not_assessed', 'reason': reason}
        if subject:
            entry['subject'] = subject
        if entry not in report.not_assessed:
            report.not_assessed.append(entry)

    def record_values(record, target):
        if target == 'process':
            return {'name': record.name, 'path': record.exe_path, 'publisher': record.publisher}
        if target == 'startup':
            return {'name': record.name, 'label': record.name, 'path': record.path}
        return {'domain': record.resolved_domain or record.remote_host}

    def check_lengths(values, target, subject):
        if any(isinstance(v, str) and len(v) > MAX_INPUT for v in values.values()):
            gap(target, 'A metadata field exceeds the matching length limit; this record was not assessed.', subject)
            return False
        return True

    def emit(kind, subject, reason, severity, confidence, rule_id, evidence, sources, *, identity=False):
        key = (kind, subject, rule_id)
        if key in seen_findings:
            return
        seen_findings.add(key)
        finding_sources[key] = sources
        caveats = [g['reason'] for g in report.not_assessed if g['source'] in sources | {'snapshot'}]
        if any('process_name' in e for e in evidence):
            caveats.append('Connections identify a process by name only; individual process instances cannot always be attributed.')
        candidates.append(Finding(kind, subject, _cap(severity, confidence), reason,
            _action(platform, kind, identity=identity), [platform], rule_id, confidence,
            evidence, list(dict.fromkeys(caveats))))

    for index, process in enumerate(snapshot.processes):
        processes_by_name[_name(process.name, platform)].append(index)
        values = record_values(process, 'process')
        subject = _subject(process.name, process.exe_path)
        if not check_lengths(values, 'processes', subject):
            identities[index] = 'not_assessed'
            continue
        core = next((r for r in core_rules if r.matches('process', values, platform)), None)
        if core:
            allowed.add(index)
            identities[index] = 'allowlisted'
            report.allowlisted.append({'subject': subject, 'rule_id': core.id,
                                       'reason': core.reason, 'evidence': core.evidence(values)})
            continue
        named_core = [r for r in core_rules if next(p for p in r.predicates if p.field == 'name').matches(process.name, platform)]
        location_core = [r for r in named_core if any(p.field == 'path' for p in r.predicates)]
        if named_core and not process.exe_path:
            identities[index] = 'not_assessed'
            gap('processes', 'A core component name was visible, but its location was not; no identity or junk assessment was made.', subject)
        elif location_core and not any(all(p.matches(values.get(p.field), platform) for p in r.predicates if p.field in {'name', 'path'}) for r in location_core):
            identities[index] = 'lookalike'
            rule = location_core[0]
            emit('unusual', subject,
                'This process uses a core OS component name, but its recorded location differs from the reviewed allowlist. '
                'A different installation layout is also possible; confirm its identity before changing anything.',
                'low', rule.confidence, 'builtin.core_location.' + rule.id,
                [f'name matches core rule {rule.id}', f'unexpected location: {redact(process.exe_path)}',
                 'expected locations: ' + ', '.join(p.value or '(no executable path)' for r in location_core
                     for p in r.predicates if p.field == 'path')],
                {'processes'}, identity=True)

    unknown_trust = sum(p.trust_signal == 'unknown' for p in snapshot.processes)
    if unknown_trust:
        gap('trust_signals', f'Trust is unknown for {unknown_trust} processes; no negative signal was inferred from unknown trust.')

    # Domain rules cannot classify addresses without locally known names.
    missing_domains = sum(normalize_domain(c.resolved_domain or c.remote_host) is None for c in snapshot.connections)
    if missing_domains:
        gap('destination_domains', f'{missing_domains} connections have no usable locally known domain; domain rules were not assessed for them. No DNS lookups were performed.')
    for index, process in enumerate(snapshot.processes):
        if index in allowed or index in identities:
            continue
        values = record_values(process, 'process')
        subject = _subject(process.name, process.exe_path)
        for rule in bloat_rules:
            if rule.matches('process', values, platform):
                emit('junk', subject, rule.reason, rule.severity or 'info', rule.confidence,
                     rule.id, rule.evidence(values), {'processes'})
        if process.trust_signal != 'unsigned':
            continue  # Unknown is neutral; verified/package-owned are not negative signals.
        evidence = ['trust_signal: unsigned']
        if _unusual_location(process.exe_path, platform):
            evidence.append('unusual location: temporary or downloads directory')
        if process.exe_path and any(item.enabled is True and item.path and
                normalize_path(item.path, platform) == normalize_path(process.exe_path, platform)
                for item in snapshot.startup_items):
            evidence.append('auto-start: enabled startup entry has the same executable path')
        named = processes_by_name[_name(process.name, platform)]
        if len(named) == 1 and any(_name(c.process_name, platform) == _name(process.name, platform)
                                   for c in snapshot.connections):
            evidence.append('network connection: unique observed process_name match')
        elif len(named) > 1 and any(_name(c.process_name, platform) == _name(process.name, platform)
                                    for c in snapshot.connections):
            gap('connection_identity', 'Several processes share a name; network connections were not attributed to a particular executable.', subject)
        signal_count = len(evidence)
        if signal_count >= 2:
            for rule in rules.section('trusted_publishers'):
                if rule.matches('process', values, platform):
                    evidence.append(f'context only: trusted publisher rule {rule.id}; this does not verify file identity')
            confidence, severity = ('high', 'medium') if signal_count == 4 else ('medium', 'low')
            emit('unusual', subject,
                'An unsigned executable has additional observed activity or location signals. This combination is unusual; '
                'it does not establish that the app is unwanted.', severity, confidence,
                'builtin.unsigned_combination', evidence, {'processes', 'startup_items', 'connections', 'connection_identity', 'trust_signals'})

    for item in snapshot.startup_items:
        values = record_values(item, 'startup')
        subject = _subject(item.name, item.path)
        if not check_lengths(values, 'startup_items', subject):
            continue
        if item.path:
            matches = [i for i, p in enumerate(snapshot.processes) if p.exe_path and
                       normalize_path(p.exe_path, platform) == normalize_path(item.path, platform)]
            if matches and all(i in allowed for i in matches):
                continue
            executable_name = item.path.replace('\\', '/').rsplit('/', 1)[-1]
            if any(r.matches('process', {'name': executable_name, 'path': item.path, 'publisher': None}, platform) for r in core_rules):
                continue
        for rule in bloat_rules:
            if rule.matches('startup', values, platform):
                emit('junk', subject, rule.reason, rule.severity or 'info', rule.confidence,
                     rule.id, rule.evidence(values), {'startup_items'})

    for connection in snapshot.connections:
        values = record_values(connection, 'destination')
        domain = normalize_domain(values['domain'])
        if not check_lengths(values, 'connections', _subject(connection.process_name)):
            continue
        named = processes_by_name.get(_name(connection.process_name, platform), [])
        if named and all(i in allowed for i in named):
            continue  # Never let one genuine core instance hide a same-name look-alike.
        for rule in rules.section('known_telemetry_domains'):
            if rule.matches('destination', values, platform):
                emit('telemetry', _subject(connection.process_name + ' → ' + domain),
                    'Possible telemetry: ' + rule.reason, rule.severity or 'low', rule.confidence,
                    rule.id, rule.evidence(values) + [f'process_name: {redact(connection.process_name)}'],
                    {'connections', 'processes', 'destination_domains'})

    # New attribution gaps may have been discovered after an earlier finding.
    for finding in candidates:
        for gap_record in report.not_assessed:
            sources = finding_sources[(finding.type, finding.subject, finding.rule_id)] | {'snapshot'}
            if (gap_record['source'] in sources and gap_record.get('subject', finding.subject) == finding.subject
                    and gap_record['reason'] not in finding.caveats):
                finding.caveats.append(gap_record['reason'])
        suppression = next((r for r in rules.section('ignore_list') if r.matches('finding',
            {'rule_id': finding.rule_id, 'subject': finding.subject}, platform)), None)
        if suppression:
            report.suppressed.append({'rule_id': finding.rule_id, 'subject': finding.subject,
                'suppressed_by': suppression.id, 'reason': suppression.reason,
                'evidence': suppression.evidence({'rule_id': finding.rule_id, 'subject': finding.subject})})
        elif SEVERITIES.index(finding.severity) >= SEVERITIES.index(min_severity):
            # Redact the dataclass itself as well as the report serialization boundary.
            report.findings.append(Finding(**finding.to_dict()))
    report.findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.type, f.subject, f.rule_id))
    report.not_assessed = redact(report.not_assessed)
    report.suppressed = redact(report.suppressed)
    report.allowlisted = redact(report.allowlisted)
    return report
