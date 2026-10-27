"""Strict local YAML rules and bounded, precompiled metadata matching."""
from dataclasses import dataclass
import fnmatch
import ipaddress
from pathlib import Path
import posixpath
import re
import sysconfig

import yaml

from .privacy import redact

SECTIONS = ('known_telemetry_domains', 'known_bloatware', 'trusted_publishers',
            'core_os_allowlist', 'ignore_list')
PLATFORMS = frozenset({'macos', 'windows', 'linux'})
SEVERITIES = ('info', 'low', 'medium')
CAPS = {'low': 'info', 'medium': 'low', 'high': 'medium'}
MAX_INPUT = 4096
MAX_PATTERN = 256
_RESTRICTED = re.compile(r'\b(malicious|virus|malware)\b', re.I)


class RuleValidationError(ValueError):
    """A rule file cannot be safely interpreted; never partially load it."""


class _Loader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise RuleValidationError('YAML mapping keys must be strings')
        if key in result:
            raise RuleValidationError(f'duplicate YAML field at line {key_node.start_mark.line + 1}')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def normalize_path(value, platform, *, fold_case=True):
    value = redact(value)
    if platform == 'windows':
        value = value.replace('\\', '/')
    value = posixpath.normpath(value) if value else ''
    return value.lower() if fold_case and platform in {'windows', 'macos'} else value


def normalize_domain(value):
    if not isinstance(value, str) or not value or len(value) > 254:
        return None
    value = value.rstrip('.').casefold()
    try:
        ipaddress.ip_address(value.strip('[]'))
        return None
    except ValueError:
        pass
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    if len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                   for label in value.split('.')):
        return None
    return value


def _text(value, label, *, empty=False, maximum=1000):
    if not isinstance(value, str) or (not empty and not value.strip()) or len(value) > maximum:
        raise RuleValidationError(f'{label}: expected {"a string" if empty else "a nonempty string"} (max {maximum} characters)')
    return value


def _safe_regex(value, label):
    """A deliberately small regular language: no groups, branches or backrefs.

    At most one quantified single atom, and fullmatch only. This eliminates
    nested/overlapping repetitions and unanchored-search quadratic behavior.
    More complex expressions should be separate rules or glob predicates.
    """
    try:
        compiled = re.compile(value)
    except re.error as exc:
        raise RuleValidationError(f'{label}: invalid regex ({exc.msg})') from None
    index, repeats, atom = 0, 0, False
    while index < len(value):
        char = value[index]
        if char == '\\':
            index += 1
            if index == len(value) or value[index].isalnum() and value[index] not in 'dDwWsS':
                raise RuleValidationError(f'{label}: unsafe regex escape; use literals or character classes')
            atom = True
        elif char == '[':
            index += 1
            if index < len(value) and value[index] == '^':
                index += 1
            if index < len(value) and value[index] == ']':
                index += 1
            while index < len(value) and value[index] != ']':
                if value[index] == '\\':
                    index += 1
                index += 1
            atom = True
        elif char in '*+?':
            repeats += 1
            if not atom or repeats > 1:
                raise RuleValidationError(f'{label}: unsafe regex repetition (at most one quantified atom)')
            atom = False
        elif char in '()|{}':
            raise RuleValidationError(f'{label}: unsafe regex construct; groups, alternation and braces are unsupported')
        elif char in '^$':
            atom = False
        else:
            atom = True
        index += 1
    return compiled


@dataclass(frozen=True)
class Predicate:
    field: str
    operator: str
    value: str | tuple[str, ...]
    sensitive: object = None
    insensitive: object = None
    windows: object = None

    def matches(self, actual, platform):
        if not isinstance(actual, str) or len(actual) > MAX_INPUT:
            return False
        if self.field == 'domain':
            actual = normalize_domain(actual)
            if actual is None:
                return False
            return actual == self.value or self.operator == 'suffix' and actual.endswith('.' + self.value)
        if self.field == 'path':
            actual = normalize_path(actual, platform, fold_case=False)
        else:
            actual = redact(actual)
        insensitive = self.field == 'publisher' or platform in {'windows', 'macos'}
        pattern = self.windows if self.field == 'path' and platform == 'windows' else (self.insensitive if insensitive else self.sensitive)
        return pattern.fullmatch(actual) is not None


def _predicate(field, raw, label):
    if not isinstance(raw, dict) or len(raw) != 1:
        raise RuleValidationError(f'{label}: expected exactly one match operator')
    operator, value = next(iter(raw.items()))
    allowed = {'exact', 'suffix'} if field == 'domain' else {'exact', 'glob', 'regex'}
    if field == 'process_name':
        allowed = {'exact', 'one_of'}
    if operator not in allowed:
        raise RuleValidationError(f'{label}: unsupported match operator')
    if field == 'process_name' and operator == 'one_of':
        if not isinstance(value, list) or not 1 <= len(value) <= 16:
            raise RuleValidationError(f'{label}: one_of requires 1–16 exact process names')
        for name in value:
            _text(name, label, maximum=MAX_PATTERN)
        expression = '(?:' + '|'.join(re.escape(name) for name in value) + ')'
        return Predicate(field, operator, tuple(value), re.compile(expression),
                         re.compile(expression, re.I), re.compile(expression, re.I))
    _text(value, label, empty=field == 'path' and operator == 'exact', maximum=MAX_PATTERN)
    if field == 'domain':
        value = normalize_domain(value.lstrip('.') if operator == 'suffix' else value)
        if value is None:
            raise RuleValidationError(f'{label}: expected a domain, not a URL, address or wildcard')
        return Predicate(field, operator, value)
    windows_value = value
    if field == 'path' and operator != 'regex':
        # Backslashes remain literal filename characters on POSIX platforms.
        windows_value = posixpath.normpath(value.replace('\\', '/')) if value else ''
        value = posixpath.normpath(value) if value else ''
    compiled = None
    if operator == 'exact':
        expression, windows_expression = re.escape(value), re.escape(windows_value)
    elif operator == 'glob':
        expression, windows_expression = fnmatch.translate(value), fnmatch.translate(windows_value)
    else:
        compiled = _safe_regex(value, label)
        expression = windows_expression = value
    sensitive = compiled if compiled is not None else re.compile(expression)
    insensitive = re.compile(expression, re.I)
    windows = insensitive if windows_expression == expression else re.compile(windows_expression, re.I)
    return Predicate(field, operator, value, sensitive, insensitive, windows)



@dataclass(frozen=True)
class Rule:
    id: str
    section: str
    target: str
    predicates: tuple[Predicate, ...]
    reason: str
    confidence: str
    platforms: tuple[str, ...]
    severity: str | None = None
    source_note: str | None = None

    def applies(self, platform):
        return platform in self.platforms

    def matches(self, target, values, platform):
        return self.target == target and self.applies(platform) and all(
            p.matches(values.get(p.field), platform) for p in self.predicates)

    def evidence(self, values):
        return [f'{p.field} matched {p.operator}: {redact(str(values.get(p.field, "")))}'
                for p in self.predicates]


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...]

    def section(self, name):
        return tuple(rule for rule in self.rules if rule.section == name)


def validate_rules(data):
    if not isinstance(data, dict) or any(not isinstance(k, str) for k in data):
        raise RuleValidationError('rules: expected a mapping of the five rule sections')
    if set(data) != set(SECTIONS):
        unknown, missing = set(data) - set(SECTIONS), set(SECTIONS) - set(data)
        raise RuleValidationError(f'rules: unknown sections {sorted(unknown)}; missing sections {sorted(missing)}')
    loaded, ids = [], set()
    for section in SECTIONS:
        entries = data[section]
        if not isinstance(entries, list):
            raise RuleValidationError(f'{section}: expected a list')
        if len(entries) > 1000:
            raise RuleValidationError(f'{section}: too many rules (maximum 1000)')
        for index, raw in enumerate(entries):
            label = f'{section}[{index}]'
            required = {'id', 'match', 'reason', 'confidence', 'platforms'}
            if not isinstance(raw, dict) or any(not isinstance(k, str) for k in raw):
                raise RuleValidationError(f'{label}: expected a rule mapping')
            if set(raw) - required - {'severity', 'source_note'} or required - set(raw):
                raise RuleValidationError(f'{label}: unknown fields {sorted(set(raw) - required - {"severity", "source_note"})}; missing fields {sorted(required - set(raw))}')
            identifier = _text(raw['id'], label + '.id', maximum=128)
            if not re.fullmatch(r'[a-z][a-z0-9_.-]*', identifier) or identifier.startswith('builtin.'):
                raise RuleValidationError(f'{label}: invalid or reserved id')
            if identifier in ids:
                raise RuleValidationError(f'{label}: duplicate rule id {identifier}')
            ids.add(identifier)
            confidence = raw['confidence']
            if not isinstance(confidence, str) or confidence not in CAPS:
                raise RuleValidationError(f'{label}: confidence must be high, medium or low')
            reason = _text(raw['reason'], label + '.reason')
            if _RESTRICTED.search(reason) and confidence != 'high':
                raise RuleValidationError(f'{label}: restricted wording requires explicit high confidence')
            platforms = raw['platforms']
            if platforms == 'all':
                platforms = sorted(PLATFORMS)
            if (not isinstance(platforms, list) or not platforms or
                    any(not isinstance(p, str) or p not in PLATFORMS for p in platforms)
                    or len(set(platforms)) != len(platforms)):
                raise RuleValidationError(f'{label}: platforms must be a nonempty OS list or "all"')
            severity = raw.get('severity')
            if 'severity' in raw and (not isinstance(severity, str) or severity not in SEVERITIES):
                raise RuleValidationError(f'{label}: severity must be info, low or medium')
            source = raw.get('source_note')
            if 'source_note' in raw:
                _text(source, label + '.source_note', maximum=2000)
            match = raw['match']
            if not isinstance(match, dict) or any(not isinstance(k, str) for k in match) or 'target' not in match:
                raise RuleValidationError(f'{label}.match: target is required')
            target = match['target']
            fields = {'process': {'name', 'publisher', 'path'}, 'startup': {'name', 'label', 'path'},
                      'destination': {'domain', 'process_name'}, 'finding': {'rule_id', 'subject'}}
            if not isinstance(target, str) or target not in fields:
                raise RuleValidationError(f'{label}.match: invalid target')
            if set(match) - {'target'} - fields[target] or len(match) == 1:
                raise RuleValidationError(f'{label}.match: unknown fields or missing predicates')
            allowed_targets = {'known_telemetry_domains': {'destination'}, 'known_bloatware': {'process', 'startup'},
                               'trusted_publishers': {'process'}, 'core_os_allowlist': {'process'},
                               'ignore_list': {'finding'}}
            if target not in allowed_targets[section]:
                raise RuleValidationError(f'{label}: target is not supported in this section')
            if section == 'trusted_publishers' and 'publisher' not in match:
                raise RuleValidationError(f'{label}: trusted publisher rule needs publisher')
            if section == 'core_os_allowlist' and ('name' not in match or not {'path', 'publisher'} & set(match)):
                raise RuleValidationError(f'{label}: core allowlist requires name AND path or publisher')
            predicates = tuple(_predicate(field, value, label + '.match.' + field)
                               for field, value in match.items() if field != 'target')
            loaded.append(Rule(identifier, section, target, predicates, reason, confidence,
                               tuple(platforms), severity, source))
    return RuleSet(tuple(loaded))


def load_rules(path=None):
    """Read only a local YAML file. No includes, URLs, plugins or network access."""
    if path is None:
        source = Path(__file__).resolve().parent.parent / 'data' / 'rules.yaml'
        path = source if source.is_file() else Path(sysconfig.get_path('data')) / 'share/dialtone-watcher/rules.yaml'
    path = Path(path)
    try:
        if path.stat().st_size > 256 * 1024:
            raise RuleValidationError('rules file exceeds 256 KB size limit')
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError):
        raise RuleValidationError('rules file is missing or unreadable') from None
    try:
        data = yaml.load(text, Loader=_Loader)
    except yaml.YAMLError as exc:
        mark = getattr(exc, 'problem_mark', None)
        raise RuleValidationError(f'invalid YAML near line {mark.line + 1 if mark else "unknown"}') from None
    return validate_rules(data)
