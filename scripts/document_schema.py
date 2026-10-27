#!/usr/bin/env python3
"""Generate README metadata tables from the actual dataclass fields."""
import argparse
from dataclasses import fields
from pathlib import Path

from dialtone_watcher.schema import Connection, Finding, Process, Snapshot, StartupItem

MODELS = (Snapshot, Process, Connection, StartupItem, Finding)


def schema_tables():
    blocks = []
    for model in MODELS:
        rows = [f'<!-- schema:{model.__name__}:start -->', f'#### {model.__name__}', '',
                '| Field | Python type |', '| --- | --- |']
        for field in fields(model):
            kind = field.type.__name__ if isinstance(field.type, type) else str(field.type)
            kind = kind.replace('typing.', '').replace('|', r'\|')
            rows.append(f'| `{field.name}` | `{kind}` |')
        rows.append(f'<!-- schema:{model.__name__}:end -->')
        blocks.append('\n'.join(rows))
    return '\n\n'.join(blocks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='fail if the README tables differ')
    args = parser.parse_args()
    readme = Path(__file__).resolve().parent.parent / 'README.md'
    text = readme.read_text(encoding='utf-8')
    start, end = '<!-- generated-schema:start -->', '<!-- generated-schema:end -->'
    before, rest = text.split(start, 1)
    _, after = rest.split(end, 1)
    updated = before + start + '\n\n' + schema_tables() + '\n\n' + end + after
    if args.check:
        if text != updated:
            raise SystemExit('README schema tables are stale; run scripts/document_schema.py')
        print('Schema documentation matches the code.')
    else:
        readme.write_text(updated, encoding='utf-8')
        print('Schema documentation updated.')


if __name__ == '__main__':
    main()
