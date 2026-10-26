from copy import deepcopy
import time

import pytest

from dialtone_watcher.rules import RuleValidationError, SECTIONS, load_rules, validate_rules


def raw_rules(section='known_bloatware', match=None, **changes):
    data = {section: [] for section in SECTIONS}
    entry = dict(id='fixture.example', match=match or {'target':'process', 'name':{'exact':'Example'}},
        reason='A synthetic fixture rule for review.', confidence='high', platforms='all',
        source_note='Synthetic test only; not a starter software claim.')
    entry.update(changes)
    data[section] = [entry]
    return data


@pytest.mark.parametrize('mutate,message', [
    (lambda d: d.update(extra=[]), 'unknown sections'),
    (lambda d: d.pop('ignore_list'), 'missing sections'),
    (lambda d: d.update(ignore_list={}), 'expected a list'),
    (lambda d: d['known_bloatware'][0].pop('reason'), 'missing fields'),
    (lambda d: d['known_bloatware'][0].update(reason=' '), 'nonempty'),
    (lambda d: d['known_bloatware'][0].update(reason=42), 'nonempty'),
    (lambda d: d['known_bloatware'][0].update(unrecognized=True), 'unknown fields'),
    (lambda d: d['known_bloatware'][0].update(confidence='certain'), 'confidence'),
    (lambda d: d['known_bloatware'][0].update(severity='critical'), 'severity'),
    (lambda d: d['known_bloatware'][0].update(severity=None), 'severity'),
    (lambda d: d['known_bloatware'][0].update(source_note=None), 'source_note'),
    (lambda d: d['known_bloatware'][0].update(platforms=['android']), 'platforms'),
    (lambda d: d['known_bloatware'][0].update(platforms=['linux','linux']), 'platforms'),
    (lambda d: d['known_bloatware'][0].update(platforms=[]), 'platforms'),
    (lambda d: d['known_bloatware'][0].update(id='builtin.override'), 'reserved id'),
    (lambda d: d['known_bloatware'][0].update(match={'name':{'exact':'Example'}}), 'target'),
    (lambda d: d['known_bloatware'][0].update(match={'target':'process','argv':{'exact':'secret'}}), 'unknown fields'),
    (lambda d: d['known_bloatware'][0].update(match={'target':'process'}), 'missing predicates'),
    (lambda d: d['known_bloatware'][0]['match'].update(name={'bad':'Example'}), 'operator'),
    (lambda d: d['known_bloatware'][0]['match'].update(name={'exact':'Example','glob':'*'}), 'exactly one'),
    (lambda d: d['known_bloatware'][0]['match'].update(name={'regex':'['}), 'invalid regex'),
    (lambda d: d['known_bloatware'][0]['match'].update(name={'regex':'(a+)+'}), 'unsafe regex'),
    (lambda d: d['known_bloatware'][0]['match'].update(name={'regex':'a*a*'}), 'unsafe regex'),
    (lambda d: d['known_bloatware'][0]['match'].update(name={'regex':r'(a)\1'}), 'unsafe regex'),
    (lambda d: d['known_bloatware'][0].update(reason='This is malicious', confidence='low'), 'restricted wording'),
])
def test_validation_errors(mutate, message):
    data = raw_rules()
    mutate(data)
    with pytest.raises(RuleValidationError, match=message):
        validate_rules(data)


def test_duplicate_ids_across_sections():
    data = raw_rules()
    data['ignore_list'] = [dict(data['known_bloatware'][0], match={'target':'finding', 'rule_id':{'exact':'fixture.example'}})]
    with pytest.raises(RuleValidationError, match='duplicate rule id'):
        validate_rules(data)


@pytest.mark.parametrize('section,match,message', [
    ('core_os_allowlist', {'target':'process','name':{'exact':'core'}}, 'name AND'),
    ('trusted_publishers', {'target':'process','name':{'exact':'core'}}, 'needs publisher'),
    ('known_telemetry_domains', {'target':'process','name':{'exact':'Example'}}, 'target is not supported'),
    ('known_telemetry_domains', {'target':'destination','domain':{'exact':'https://example.com/'}}, 'expected a domain'),
    ('known_telemetry_domains', {'target':'destination','domain':{'exact':'192.0.2.1'}}, 'expected a domain'),
])
def test_section_constraints(section, match, message):
    with pytest.raises(RuleValidationError, match=message):
        validate_rules(raw_rules(section, match))


def test_loader_errors(tmp_path):
    path = tmp_path / 'rules.yaml'
    with pytest.raises(RuleValidationError, match='missing or unreadable'):
        load_rules(path)
    path.write_text('known_bloatware: [')
    with pytest.raises(RuleValidationError, match='invalid YAML near line'):
        load_rules(path)
    path.write_text('known_bloatware: []\nknown_bloatware: []')
    with pytest.raises(RuleValidationError, match='duplicate YAML field'):
        load_rules(path)
    path.write_bytes(b'\xff')
    with pytest.raises(RuleValidationError, match='unreadable'):
        load_rules(path)
    path.write_bytes(b' ' * (256 * 1024 + 1))
    with pytest.raises(RuleValidationError, match='size limit'):
        load_rules(path)


@pytest.mark.parametrize('operator,pattern,value', [('exact','Example','Example'),
    ('glob','Example*','Example Helper'), ('regex','Example[0-9]+','Example12')])
def test_process_name_match_types(operator, pattern, value):
    rule = validate_rules(raw_rules(match={'target':'process','name':{operator:pattern}})).rules[0]
    assert rule.matches('process', {'name':value}, 'linux')
    assert not rule.matches('startup', {'name':value}, 'linux')


@pytest.mark.parametrize('platform,matched', [('macos',True), ('windows',True), ('linux',False)])
def test_path_case_and_normalization(platform, matched):
    rule = validate_rules(raw_rules(match={'target':'process','path':{'glob':'/Opt/Example/*'}})).rules[0]
    assert rule.matches('process', {'path':'/opt/example/bin/../app'}, platform) == matched


def test_windows_separators():
    rule = validate_rules(raw_rules(match={'target':'process','path':{'glob':'C:/Apps/Example/*'}})).rules[0]
    assert rule.matches('process', {'path':r'c:\apps\example\helper.exe'}, 'windows')
    assert not rule.matches('process', {'path':r'c:\apps\example\helper.exe'}, 'linux')


def test_publisher_and_conjunction():
    rule = validate_rules(raw_rules(match={'target':'process','name':{'exact':'Example'},
        'publisher':{'exact':'Example Publisher'}})).rules[0]
    assert rule.matches('process', {'name':'Example','publisher':'EXAMPLE PUBLISHER'}, 'linux')
    assert not rule.matches('process', {'name':'Other','publisher':'Example Publisher'}, 'linux')
    assert not rule.matches('process', {'name':'Example','publisher':None}, 'linux')


@pytest.mark.parametrize('field', ['name','label','path'])
def test_startup_fields(field):
    rule = validate_rules(raw_rules(match={'target':'startup',field:{'glob':'example*'}})).rules[0]
    assert rule.matches('startup', {field:'example.agent'}, 'linux')


@pytest.mark.parametrize('operator,domain,expected', [
    ('exact','EXAMPLE.COM.',True), ('exact','sub.example.com',False),
    ('suffix','example.com',True), ('suffix','sub.example.com',True),
    ('suffix','notexample.com',False), ('suffix','example.com.attacker.invalid',False),
    ('suffix','192.0.2.1',False),
])
def test_domains(operator, domain, expected):
    rule = validate_rules(raw_rules('known_telemetry_domains',
        {'target':'destination','domain':{operator:'.example.com' if operator=='suffix' else 'example.com'}})).rules[0]
    assert rule.matches('destination', {'domain':domain}, 'linux') == expected


def test_platform_scope_and_safe_regex():
    rule = validate_rules(raw_rules(match={'target':'process','name':{'regex':'Example[0-9]+'}}, platforms=['windows'])).rules[0]
    assert rule.matches('process', {'name':'EXAMPLE42'}, 'windows')
    assert not rule.matches('process', {'name':'Example42'}, 'linux')


def test_long_inputs_are_bounded_and_regexes_not_recompiled(monkeypatch):
    import dialtone_watcher.rules as module
    rule = validate_rules(raw_rules(match={'target':'process','name':{'regex':'a+b'}})).rules[0]
    monkeypatch.setattr(module.re, 'compile', lambda *a, **k: pytest.fail('pattern recompiled during matching'))
    before = time.monotonic()
    for _ in range(200):
        assert not rule.matches('process', {'name':'a' * 4095}, 'linux')
        assert not rule.matches('process', {'name':'a' * 100000}, 'linux')
    assert time.monotonic() - before < 2


def test_starter_rules_have_human_review_sources():
    rules = load_rules()
    assert rules.rules
    assert {p for r in rules.rules for p in r.platforms} == {'macos','windows','linux'}
    assert all('needs human review' in r.source_note for r in rules.rules)



def test_linux_backslash_is_a_literal_filename_character():
    rule = validate_rules(raw_rules(match={'target':'process','path':{'exact':r'/opt/name\part'}})).rules[0]
    assert rule.matches('process', {'path':r'/opt/name\part'}, 'linux')
    assert not rule.matches('process', {'path':'/opt/name/part'}, 'linux')


def test_unicode_path_case():
    rule = validate_rules(raw_rules(match={'target':'process','path':{'exact':'/Apps/Straße/Tool'}})).rules[0]
    assert rule.matches('process', {'path':'/APPS/STRAẞE/TOOL'}, 'macos')
    assert not rule.matches('process', {'path':'/APPS/STRAẞE/TOOL'}, 'linux')



def test_installed_rules_data_location(monkeypatch, tmp_path):
    import yaml
    import dialtone_watcher.rules as module
    share = tmp_path / 'share/dialtone-watcher'
    share.mkdir(parents=True)
    (share / 'rules.yaml').write_text(yaml.safe_dump(raw_rules()),encoding='utf-8')
    monkeypatch.setattr(module, '__file__', str(tmp_path / 'package/rules.py'))
    monkeypatch.setattr(module.sysconfig, 'get_path', lambda name: str(tmp_path))
    assert module.load_rules().rules[0].id == 'fixture.example'



@pytest.mark.parametrize('platform',['macos','windows','linux'])
def test_unicode_identical_path_not_changed_before_regex_case_matching(platform):
    rule = validate_rules(raw_rules(match={'target':'process','path':{'exact':'/Apps/İstanbul/Tool'}})).rules[0]
    assert rule.matches('process', {'path':'/Apps/İstanbul/Tool'}, platform)
