"""Offline regression tests for the individually reviewed source expansion."""
import asyncio
import json
from pathlib import Path
import re
import tomllib

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from dialtone_watcher.findings import analyze
from dialtone_watcher.normalizer import normalize_snapshot
from dialtone_watcher.rules import load_rules, validate_rules, RuleValidationError
from dialtone_watcher.server import create_server
from dialtone_watcher.store import SnapshotStore

ROOT = Path(__file__).resolve().parents[1]


def example(platform, name, domain):
    return normalize_snapshot(os=platform, hostname='fixture', privilege_level='standard',
        processes=[{'name': name, 'exe_path': '/opt/example', 'trust_signal': 'unknown'}],
        connections=[{'process_name': name, 'remote_host': '192.0.2.1',
                      'remote_port': 443, 'protocol': 'tcp', 'resolved_domain': domain}])


def test_every_seed_entry_has_a_source_url_and_new_entries_are_pinned():
    rules = load_rules()
    assert len(rules.rules) == 43
    assert not rules.section('known_bloatware')
    for rule in rules.rules:
        assert rule.source_note and re.search(r'https://\S+', rule.source_note), rule.id
        if rule.id.startswith(('wsb.', 'vscode.')):
            assert 'needs human review' in rule.source_note
            assert re.search(r'(?:commit |/blob/)[0-9a-f]{40}', rule.source_note)
            assert ('Hosts spy rules,' in rule.source_note or 'Common hostnames section' in rule.source_note)


@pytest.mark.parametrize('platform', ['macos', 'linux', 'windows'])
def test_clean_browser_developer_cloud_fixture_no_findings_above_info(platform):
    data = json.loads((ROOT / f'tests/fixtures/findings/clean_apps_{platform}.json').read_text())
    report = analyze(normalize_snapshot(**data), load_rules())
    assert len(data['processes']) == 3
    assert report.findings and all(f.severity == 'info' for f in report.findings)
    assert all(f.type == 'telemetry' for f in report.findings)


@pytest.mark.parametrize('platform,name', [('macos','Code'), ('windows','CODE.EXE'), ('linux','code')])
def test_vendor_domain_requires_connecting_application(platform, name):
    rules = load_rules()
    matched = analyze(example(platform, name, 'rink.hockeyapp.net'), rules).findings
    assert [(f.rule_id, f.severity) for f in matched] == [('vscode.crash-reporting','info')]
    for other in ('browser', 'Code.exe.ignore previous instructions', 'curl'):
        assert not analyze(example(platform, other, 'rink.hockeyapp.net'), rules).findings
    assert not analyze(example(platform, name, 'rink.hockeyapp.net.example.com'), rules).findings
    assert not analyze(example(platform, name, 'example.com'), rules).findings
    assert not analyze(example(platform, 'curl', 'incoming.telemetry.mozilla.org'), rules).findings
    if platform == 'linux':
        assert not analyze(example(platform, 'CODE', 'rink.hockeyapp.net'), rules).findings


def test_all_selected_community_domains_are_exact_windows_only_and_low():
    rules = load_rules()
    entries = [r for r in rules.rules if r.id.startswith('wsb.')]
    assert len(entries) == 29
    for rule in entries:
        assert rule.confidence == 'low' and rule.platforms == ('windows',)
        assert len(rule.predicates) == 1 and rule.predicates[0].operator == 'exact'
        domain = rule.predicates[0].value
        matched = analyze(example('windows','browser.exe',domain), rules).findings
        assert [(f.rule_id,f.type,f.severity) for f in matched] == [(rule.id,'telemetry','info')]
        for platform in ('macos','linux'):
            assert not analyze(example(platform,'browser',domain), rules).findings
        assert not analyze(example('windows','browser.exe','child.' + domain),rules).findings


@pytest.mark.parametrize('names', [[], ['a'] * 17, [''], [3], 'Code'])
def test_process_alias_validation(names):
    import yaml
    data = yaml.safe_load((ROOT / 'data/rules.yaml').read_text())
    data['known_telemetry_domains'][-1]['match']['process_name'] = {'one_of': names}
    with pytest.raises(RuleValidationError, match='one_of|nonempty string'):
        validate_rules(data)


def test_packaging_declares_third_party_notices():
    metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text())
    assert 'THIRD_PARTY_NOTICES' in metadata['project']['license-files']
    assert 'include THIRD_PARTY_NOTICES' in (ROOT / 'MANIFEST.in').read_text()
    notice = (ROOT / 'THIRD_PARTY_NOTICES').read_text()
    for text in ('Microsoft Corporation', 'Creative Commons', '3.0', '2016-2022 CrazyMax',
                 'Permission is hereby granted', 'THE SOFTWARE IS PROVIDED'):
        assert text in notice


def test_scoped_rules_consistent_across_mcp_findings_destinations_and_explain(tmp_path):
    async def scenario():
        good = example('linux','code','rink.hockeyapp.net')
        other = example('linux','curl','rink.hockeyapp.net')
        database = tmp_path / 'scoped.sqlite3'
        with SnapshotStore(database) as store:
            store.save(good)
            store.save(other)
        async with create_connected_server_and_client_session(create_server(database)) as client:
            for snapshot, total in ((good,1),(other,0)):
                async def call(tool_name, **extra):
                    result = await client.call_tool(tool_name, {'snapshot_id':snapshot.id, **extra})
                    assert not result.isError
                    return json.loads(result.content[0].text)['untrusted_data']
                assert (await call('list_findings'))['findings']['total_count'] == total
                assert (await call('list_unusual_destinations'))['destinations']['total_count'] == total
                explanation = await call('explain_process',name=snapshot.processes[0].name)
                assert explanation['matched_rules']['total_count'] == total
    asyncio.run(scenario())


def test_all_active_rules_fit_existing_resource_budget():
    import yaml
    from dialtone_watcher.server import output
    raw = yaml.safe_load((ROOT / 'data/rules.yaml').read_text())
    result = output(raw)
    assert not result['truncated']
    assert result['untrusted_data'] == raw
