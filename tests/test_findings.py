from dataclasses import asdict
import json
from pathlib import Path
import socket
import subprocess

import pytest

from dialtone_watcher.findings import analyze
from dialtone_watcher.normalizer import normalize_snapshot
from dialtone_watcher.rules import SECTIONS, load_rules, validate_rules
from dialtone_watcher.schema import Connection, Process, Snapshot, StartupItem


def snapshot(platform='linux', *, processes=None, connections=(), startup=(), notes=()):
    return Snapshot('fixture', '2026-10-26T00:00:00+00:00', platform, '0' * 64, 'standard',
        list(notes), processes if processes is not None else [Process('Example','/opt/example')],
        list(connections), list(startup))


def rules(section='known_bloatware', *, match=None, confidence='high', severity='medium', extras=()):
    data = {s:[] for s in SECTIONS}
    data[section].append(dict(id='fixture.rule', match=match or {'target':'process','name':{'exact':'Example'}},
        reason='This fixture explicitly requests review of the matching item.', confidence=confidence,
        platforms='all', severity=severity, source_note='Synthetic fixture, not a starter entry.'))
    for destination, entry in extras:
        data[destination].append(entry)
    return validate_rules(data)


def empty():
    return validate_rules({s:[] for s in SECTIONS})


@pytest.mark.parametrize('confidence,expected', [('low','info'),('medium','low'),('high','medium')])
@pytest.mark.parametrize('section,match', [
    ('known_bloatware', {'target':'process','name':{'exact':'Example'}}),
    ('known_telemetry_domains', {'target':'destination','domain':{'exact':'example.com'}})])
def test_confidence_caps(confidence, expected, section, match):
    report = analyze(snapshot(connections=[Connection('Example','192.0.2.1',443,'tcp','example.com')]),
                     rules(section, match=match, confidence=confidence))
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity == expected
    assert finding.rule_id == 'fixture.rule'
    assert finding.evidence and finding.reason and finding.suggested_action
    assert finding.confidence == confidence


@pytest.mark.parametrize('trust', ['unknown', 'verified', 'package_owned'])
def test_unknown_and_positive_trust_never_negative(trust):
    report = analyze(snapshot(processes=[Process('Example','/tmp/Example', trust_signal=trust)],
        startup=[StartupItem('Example','cron','/tmp/Example',True)],
        connections=[Connection('Example','192.0.2.1',443,'tcp')]), empty())
    assert report.findings == []


def test_unknown_does_not_raise_explicit_severity():
    for trust in ('unknown','unsigned','verified','package_owned'):
        report = analyze(snapshot(processes=[Process('Example','/opt/example',trust_signal=trust)]),
                         rules(confidence='low'))
        assert report.findings[0].severity == 'info'


def test_unsigned_alone_creates_no_finding():
    assert analyze(snapshot(processes=[Process('Example','/opt/example', trust_signal='unsigned')]), empty()).findings == []


@pytest.mark.parametrize('extra', ['location','startup','connection'])
def test_unsigned_second_signal_low(extra):
    path = '/tmp/example' if extra == 'location' else '/opt/example'
    report = analyze(snapshot(processes=[Process('Example',path,trust_signal='unsigned')],
        startup=[StartupItem('Example','cron',path,True)] if extra=='startup' else [],
        connections=[Connection('Example','192.0.2.1',443,'tcp')] if extra=='connection' else []), empty())
    assert len(report.findings) == 1
    assert report.findings[0].type == 'unusual' and report.findings[0].severity == 'low'
    assert report.findings[0].confidence == 'medium'


def test_unsigned_full_combination_medium():
    report = analyze(snapshot(processes=[Process('Example','/tmp/example',trust_signal='unsigned')],
        startup=[StartupItem('Example','cron','/tmp/example',True)],
        connections=[Connection('Example','192.0.2.1',443,'tcp')]), empty())
    assert report.findings[0].severity == 'medium'
    assert report.findings[0].confidence == 'high'
    assert len(report.findings[0].evidence) == 4


def test_disabled_startup_and_ambiguous_connections_do_not_raise():
    report = analyze(snapshot(processes=[Process('Example','/opt/a',trust_signal='unsigned'),
        Process('Example','/opt/b',trust_signal='unsigned')],
        startup=[StartupItem('Example','cron','/opt/a',False)],
        connections=[Connection('Example','192.0.2.1',443,'tcp')]), empty())
    assert report.findings == []
    assert any(g['source']=='connection_identity' for g in report.not_assessed)


@pytest.mark.parametrize('platform,name,path', [
    ('macos','launchd','/sbin/launchd'), ('macos','kernel_task',''),
    ('linux','systemd','/usr/lib/systemd/systemd'), ('linux','systemd','/lib/systemd/systemd'),
    ('linux','init','/sbin/init'), ('windows','System',''),
    ('windows','svchost.exe',r'C:\Windows\System32\svchost.exe'),
    ('windows','svchost.exe',r'C:\Windows\SysWOW64\svchost.exe'),
    ('windows','csrss.exe',r'C:\Windows\System32\csrss.exe'),
    ('windows','explorer.exe',r'C:\Windows\explorer.exe'),
])
def test_core_allowlist_always_wins(platform, name, path):
    seed = load_rules()
    hostile = rules(match={'target':'process','name':{'exact':name}})
    all_rules = type(seed)(seed.rules + hostile.rules)
    report = analyze(snapshot(platform, processes=[Process(name,path,trust_signal='unsigned')],
        startup=[StartupItem(name,'service',path,True)],
        connections=[Connection(name,'192.0.2.1',443,'tcp','incoming.telemetry.mozilla.org')]), all_rules)
    assert report.findings == []
    assert report.allowlisted


def test_lookalike_in_user_folder_is_unusual_even_with_unknown_trust():
    report = analyze(snapshot('windows',processes=[Process('svchost.exe',r'C:\Users\fixtureperson\Downloads\svchost.exe')]),load_rules())
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.type == 'unusual' and 'location' in finding.reason
    assert finding.rule_id.startswith('builtin.core_location.')
    assert 'fixtureperson' not in json.dumps(report.to_dict())


def test_one_core_instance_does_not_hide_same_name_other_process():
    report = analyze(snapshot('windows',processes=[Process('svchost.exe',r'C:\Windows\System32\svchost.exe'),
        Process('svchost.exe',r'C:\Users\fixtureperson\svchost.exe')],
        connections=[Connection('svchost.exe','192.0.2.1',443,'tcp','telemetry.microsoft.com')]), load_rules())
    assert {f.type for f in report.findings} == {'unusual','telemetry'}


def test_unreadable_core_location_not_assessed_instead_of_lookalike():
    report = analyze(snapshot('windows', processes=[Process('svchost.exe','')]), load_rules())
    assert report.findings == []
    assert any('location was not' in gap['reason'] for gap in report.not_assessed)


@pytest.mark.parametrize('field,pattern', [('rule_id','fixture.rule'), ('subject','Example (/opt/example)')])
def test_ignore_suppression_visible(field, pattern):
    ignore = dict(id='ignore.fixture',match={'target':'finding',field:{'exact':pattern}},
        reason='The user chose to ignore this fixture.',confidence='high',platforms='all')
    report = analyze(snapshot(),rules(extras=[('ignore_list',ignore)]))
    assert report.findings == []
    assert report.suppressed[0]['suppressed_by'] == 'ignore.fixture'
    assert report.suppressed[0]['rule_id'] == 'fixture.rule'
    assert report.suppressed[0]['reason']


def test_visibility_scoped_caveats_and_missing_domains():
    notes = ['3 per-process connections operations limited: AccessDenied.']
    data = rules()
    telemetry = rules('known_telemetry_domains',match={'target':'destination','domain':{'exact':'example.com'}})
    report = analyze(snapshot(notes=notes,connections=[Connection('Example','192.0.2.1',443,'tcp','example.com'),
        Connection('Example','192.0.2.2',80,'tcp')]),type(data)(data.rules + tuple(
            type(r)(**{**r.__dict__,'id':'fixture.telemetry'}) for r in telemetry.rules)))
    junk = next(f for f in report.findings if f.type=='junk')
    telemetry_finding = next(f for f in report.findings if f.type=='telemetry')
    assert junk.caveats == []
    assert any('AccessDenied' in c for c in telemetry_finding.caveats)
    assert any(g['source']=='destination_domains' and g['status']=='not_assessed' for g in report.not_assessed)
    assert 'does not establish' in report.message


def test_unknown_visibility_note_conservative_caveat():
    report = analyze(snapshot(notes=['Visibility restricted by local policy.']),rules())
    assert report.not_assessed
    assert report.findings[0].caveats == ['Visibility restricted by local policy.']


@pytest.mark.parametrize('platform', ['macos','windows','linux'])
def test_clean_fixture_regression(platform):
    raw = json.loads((Path(__file__).parent / 'fixtures/findings' / f'clean_{platform}.json').read_text(encoding='utf-8'))
    snap = normalize_snapshot(**raw)
    report = analyze(snap,load_rules())
    assert all(f.severity=='info' for f in report.findings)
    assert not any(f.type=='junk' for f in report.findings)


@pytest.mark.parametrize('home', ['/Users/fixtureperson','/home/fixtureperson','/root',r'C:\Users\fixtureperson',r'\\server\share\fixtureperson'])
def test_finding_privacy(home):
    report = analyze(snapshot(processes=[Process('Example',home+'/Downloads/example')],
        notes=[f'Process path unavailable: {home}/private']),rules())
    encoded = json.dumps(report.to_dict())
    for secret in ('fixtureperson',home,'server'):
        assert secret not in encoded
    finding = report.findings[0]
    assert finding.reason and finding.evidence and finding.caveats and finding.platforms
    assert set(finding.to_dict()) == {'type','subject','severity','reason','suggested_action','platforms',
                                      'rule_id','confidence','evidence','caveats'}


def test_analysis_is_offline_and_advice_only(monkeypatch):
    configured = rules()
    monkeypatch.setattr(socket,'socket',lambda *a,**k: pytest.fail('network access'))
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k: pytest.fail('DNS access'))
    monkeypatch.setattr(subprocess,'run',lambda *a,**k: pytest.fail('OS command executed'))
    monkeypatch.setattr(Path,'read_text',lambda *a,**k: pytest.fail('file read during analysis'))
    assert analyze(snapshot(),configured).findings


def test_trusted_publisher_is_context_not_a_blanket_allowlist():
    trusted = dict(id='trusted.example', match={'target':'process','publisher':{'exact':'Example Publisher'}},
        reason='User-provided provenance context.',confidence='high',platforms='all')
    report = analyze(snapshot(processes=[Process('Example','/opt/example',publisher='Example Publisher')]),
                     rules(extras=[('trusted_publishers',trusted)]))
    assert report.findings


def test_oversized_metadata_is_not_silently_assessed():
    report = analyze(snapshot(processes=[Process('a'*100000,'/opt/example')]),rules())
    assert report.findings == []
    assert any('length limit' in g['reason'] for g in report.not_assessed)


def test_filtering_counts_and_order():
    report = analyze(snapshot(processes=[Process('Example','/opt/example'), Process('Other','/tmp/other',trust_signal='unsigned')]), rules())
    assert [f.severity for f in report.findings] == ['medium','low']
    assert report.counts()['by_severity'] == {'info':0,'low':1,'medium':1}
    assert len(analyze(snapshot(),rules(),min_severity='medium').findings) == 1
    with pytest.raises(ValueError,match='min_severity'):
        analyze(snapshot(),rules(),min_severity='critical')



def test_snapshot_not_mutated():
    snap = snapshot()
    before = asdict(snap)
    analyze(snap,rules())
    assert asdict(snap) == before


def test_startup_explicit_rule():
    report = analyze(snapshot(startup=[StartupItem('Example Agent','launchd','/opt/example',True)]),
        rules(match={'target':'startup','label':{'glob':'Example*'},'path':{'exact':'/opt/example'}}))
    assert len(report.findings) == 1
    assert report.findings[0].type == 'junk'
    assert any('label matched' in e for e in report.findings[0].evidence)


def test_location_without_unsigned_or_other_signal_is_neutral():
    for signal in ('unknown','verified','package_owned'):
        report = analyze(snapshot(processes=[Process('Example','~/Downloads/example',trust_signal=signal)]),empty())
        assert report.findings == []
