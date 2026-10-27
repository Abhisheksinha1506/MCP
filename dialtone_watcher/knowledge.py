"""Validated, locally sourced context; a name match never establishes identity."""
from dataclasses import asdict, dataclass
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path
import re
import sys

import yaml

from .privacy import redact
from .rules import normalize_path

PLATFORMS = {'macos', 'windows', 'linux'}
CATEGORIES = {'os_core', 'driver', 'updater', 'browser', 'cloud_sync', 'security',
              'developer_tool', 'other'}
REQUIRED = {'id', 'names', 'platforms', 'description', 'publisher', 'category',
            'usually_safe_to_ignore', 'confidence', 'source_note', 'last_reviewed'}
RESTRICTED = re.compile(r'\b(malware|virus|malicious|hack)\b', re.I)


class KnowledgeValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    id: str
    names: tuple[str, ...]
    platforms: tuple[str, ...]
    description: str
    publisher: str | None
    category: str
    usually_safe_to_ignore: bool | str
    confidence: str
    source_note: str
    last_reviewed: str
    expected_locations: tuple[str, ...] = ()

    def to_dict(self):
        return redact(asdict(self))

    def compare(self, process, platform):
        """Compare recorded metadata only; missing evidence never means agreement."""
        checks = []
        if self.expected_locations:
            if not process.exe_path:
                checks.append(('not_checkable', 'Executable location is unavailable.'))
            elif any(fnmatchcase(normalize_path(process.exe_path, platform),
                                 normalize_path(pattern, platform)) for pattern in self.expected_locations):
                checks.append(('matches', 'Recorded location matches a documented expected pattern.'))
            else:
                checks.append(('mismatch', 'Recorded location differs from the documented expected locations.'))
        if self.publisher is not None:
            if not process.publisher:
                checks.append(('not_checkable', 'Publisher metadata is unavailable.'))
            elif self.publisher.casefold() == process.publisher.casefold():
                checks.append(('matches', 'Recorded publisher matches the expected publisher text.'))
            else:
                checks.append(('mismatch', 'Recorded publisher differs from the documented expected publisher.'))
        if not checks:
            checks.append(('not_checkable', 'This entry has no documented location or signer expectation.'))
        state = ('mismatch' if any(s == 'mismatch' for s, _ in checks) else
                 'not_checkable' if any(s == 'not_checkable' for s, _ in checks) else 'matches')
        return {'consistency': state, 'explanations': [message for _, message in checks]}


@dataclass(frozen=True)
class KnowledgeTable:
    entries: tuple[Entry, ...]

    def lookup(self, name, platform):
        if platform not in PLATFORMS:
            return None
        key = name if platform == 'linux' else name.casefold()
        return next((entry for entry in self.entries if platform in entry.platforms and
                     any((n if platform == 'linux' else n.casefold()) == key for n in entry.names)), None)


def validate_knowledge(data):
    if not isinstance(data, dict) or set(data) != {'entries'} or not isinstance(data['entries'], list):
        raise KnowledgeValidationError('knowledge: expected an entries list')
    entries, ids, identities = [], set(), {}
    for index, raw in enumerate(data['entries']):
        label = f'knowledge entry {index + 1}'
        def fail(message):
            raise KnowledgeValidationError(f'{label}: {message}')
        if not isinstance(raw, dict) or any(not isinstance(k, str) for k in raw):
            fail('expected a mapping')
        missing, unknown = REQUIRED - set(raw), set(raw) - REQUIRED - {'expected_locations'}
        if missing:
            fail('missing fields: ' + ', '.join(sorted(missing)))
        if unknown:
            fail('unknown fields: ' + ', '.join(sorted(unknown)))
        identifier = raw['id']
        if not isinstance(identifier, str) or not re.fullmatch(r'[a-z][a-z0-9_.-]{0,127}', identifier):
            fail('invalid id')
        if identifier in ids:
            fail('duplicate id: ' + identifier)
        ids.add(identifier)
        for field in ('description', 'source_note'):
            if not isinstance(raw[field], str) or not raw[field].strip() or len(raw[field]) > 1024:
                fail(field + ' must be nonempty text of at most 1024 characters')
        if not isinstance(raw['category'], str) or raw['category'] not in CATEGORIES:
            fail('unknown category')
        if RESTRICTED.search(raw['description']) and raw['category'] != 'security':
            fail('restricted description words require category security')
        if re.search(r'\bsafe\b', raw['description'], re.I):
            fail('description must not give a safe verdict')
        if not isinstance(raw['confidence'], str) or raw['confidence'] not in {'high', 'medium', 'low'}:
            fail('invalid confidence')
        if type(raw['usually_safe_to_ignore']) is not bool and raw['usually_safe_to_ignore'] != 'depends':
            fail('usually_safe_to_ignore must be true, false or depends')
        publisher = raw['publisher']
        if publisher is not None and (not isinstance(publisher, str) or not publisher.strip() or len(publisher) > 512):
            fail('publisher must be nonempty text or null')
        platforms = sorted(PLATFORMS) if raw['platforms'] == 'all' else raw['platforms']
        if (not isinstance(platforms, list) or not platforms or
                any(not isinstance(p, str) or p not in PLATFORMS for p in platforms) or len(set(platforms)) != len(platforms)):
            fail('invalid platforms')
        names = raw['names']
        if (not isinstance(names, list) or not names or any(
                not isinstance(n, str) or not n.strip() or len(n) > 256 or
                any(ord(c) < 32 or ord(c) == 127 for c in n) for n in names)):
            fail('names must be a nonempty list of process names without controls')
        for platform in platforms:
            for name in names:
                identity = (platform, name if platform == 'linux' else name.casefold())
                if identity in identities and identities[identity] != identifier:
                    fail('ambiguous name on the same platform')
                identities[identity] = identifier
        locations = raw.get('expected_locations', [])
        if not isinstance(locations, list) or any(not isinstance(p, str) or not p or len(p) > 512 for p in locations):
            fail('expected_locations must be a list of nonempty path patterns')
        reviewed = raw['last_reviewed']
        try:
            reviewed = date.fromisoformat(reviewed) if isinstance(reviewed, str) else reviewed
            if type(reviewed) is not date:
                fail('last_reviewed must be an ISO date')
        except (ValueError, TypeError):
            fail('last_reviewed must be an ISO date')
        entries.append(Entry(identifier, tuple(names), tuple(platforms), raw['description'].strip(),
            publisher, raw['category'], raw['usually_safe_to_ignore'], raw['confidence'],
            raw['source_note'].strip(), reviewed.isoformat(), tuple(locations)))
    return KnowledgeTable(tuple(entries))


def load_knowledge(path=None):
    if path is None:
        candidate = Path(__file__).resolve().parent.parent / 'data' / 'knowledge.yaml'
        path = candidate if candidate.is_file() else Path(sys.prefix) / 'share/dialtone-watcher/knowledge.yaml'
    try:
        return validate_knowledge(yaml.safe_load(Path(path).read_text(encoding='utf-8')))
    except yaml.YAMLError as exc:
        raise KnowledgeValidationError('knowledge: invalid YAML') from exc
