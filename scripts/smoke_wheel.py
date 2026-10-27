#!/usr/bin/env python3
"""Check installed imports, bundled data and both stdio entry points outside a checkout."""
import asyncio
from datetime import timedelta
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import sysconfig
import tempfile

import dialtone_watcher
from dialtone_watcher.knowledge import load_knowledge
from dialtone_watcher.normalizer import normalize_snapshot
from dialtone_watcher.rules import load_rules
from dialtone_watcher.store import SnapshotStore
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def check():
    package = Path(dialtone_watcher.__file__).resolve()
    assert package.is_relative_to(Path(sys.prefix).resolve()), 'Import escaped the clean environment'
    distribution = importlib.metadata.distribution('dialtone-watcher')
    assert distribution.version == '0.1.0'
    assert distribution.metadata['License-Expression'] == 'MIT'
    assert distribution.metadata['Requires-Python'] == '>=3.11'
    assert distribution.metadata['Description-Content-Type'] == 'text/markdown'
    bundled = []
    for filename in ('rules.yaml', 'knowledge.yaml'):
        matches = [p for p in distribution.files or [] if str(p).replace('\\', '/').endswith('/share/dialtone-watcher/' + filename)]
        assert len(matches) == 1, 'Bundled data missing from installation'
        assert Path(distribution.locate_file(matches[0])).is_file()
        bundled.append(filename)
    rules, knowledge = load_rules(), load_knowledge()
    assert rules.rules and knowledge.lookup('launchd', 'macos')
    root = Path(tempfile.mkdtemp(prefix='dialtone-wheel-smoke-'))
    executable = Path(sysconfig.get_path('scripts')) / ('dialtone-watcher.exe' if os.name == 'nt' else 'dialtone-watcher')
    assert executable.is_file()
    for index, (command, args) in enumerate(((str(executable), []), (sys.executable, ['-m', 'dialtone_watcher.server']))):
        database = root / f'snapshot-{index}.sqlite3'
        snapshot = normalize_snapshot(os='macos', hostname='synthetic-package-check', privilege_level='standard',
            processes=[{'name': 'launchd', 'exe_path': '/sbin/launchd', 'trust_signal': 'unknown'}])
        with SnapshotStore(database) as store:
            store.save(snapshot)
        parameters = StdioServerParameters(command=command, args=args,
            env={'DIALTONE_WATCHER_DB': str(database), 'PYTHONNOUSERSITE': '1'})
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=30)) as client:
                await client.initialize()
                tools = (await client.list_tools()).tools
                assert len(tools) == 8
                resources = (await client.list_resources()).resources
                assert {str(r.uri) for r in resources} == {'snapshot://latest', 'rules://active'}
                for uri in ('snapshot://latest', 'rules://active'):
                    resource = json.loads((await client.read_resource(uri)).contents[0].text)
                    assert 'untrusted_data' in resource and 'error' not in resource['untrusted_data']
                result = await client.call_tool('explain_process', {'name': 'launchd', 'snapshot_id': snapshot.id})
                assert not result.isError
                result = json.loads(result.content[0].text)['untrusted_data']
                assert result['known_info']['id'] == 'macos.launchd'
                assert result['consistency'] == 'matches'
                findings = await client.call_tool('list_findings', {'snapshot_id': snapshot.id})
                assert json.loads(findings.content[0].text)['untrusted_data']['findings']['total_count'] == 0
    print(json.dumps({'version': distribution.version, 'entry_points_checked': 2,
                      'tools': 8, 'resources': 2, 'bundled_data_files': len(bundled),
                      'rules': len(rules.rules), 'knowledge_entries': len(knowledge.entries),
                      'synthetic_only': True}))


if __name__ == '__main__':
    asyncio.run(check())
