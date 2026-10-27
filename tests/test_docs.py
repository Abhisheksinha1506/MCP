"""Documentation contracts are checked against the real schema and MCP listing."""
import asyncio
from dataclasses import fields
import json
from pathlib import Path
import re
import tomllib

from mcp.shared.memory import create_connected_server_and_client_session

from dialtone_watcher.schema import Snapshot, Process, Connection, StartupItem, Finding
from dialtone_watcher.server import create_server
from scripts.document_schema import schema_tables

ROOT = Path(__file__).resolve().parent.parent


def test_documented_schema_matches_every_actual_field():
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    for model in (Snapshot, Process, Connection, StartupItem, Finding):
        block = readme.split(f'<!-- schema:{model.__name__}:start -->', 1)[1].split(
            f'<!-- schema:{model.__name__}:end -->', 1)[0]
        names = re.findall(r'^\| `([a-z_0-9]+)` \|', block, re.M)
        assert names == [field.name for field in fields(model)], f'{model.__name__}: undocumented field change'
    generated = readme.split('<!-- generated-schema:start -->', 1)[1].split('<!-- generated-schema:end -->', 1)[0]
    assert generated.strip() == schema_tables()


def test_documented_tools_and_resources_match_sdk_listing(tmp_path):
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    tools = readme.split('<!-- tools:start -->', 1)[1].split('<!-- tools:end -->', 1)[0]
    documented = re.findall(r'^\| `([a-z_]+)` \|', tools, re.M)
    assert len(documented) == len(set(documented))
    resources = readme.split('<!-- resources:start -->', 1)[1].split('<!-- resources:end -->', 1)[0]
    resource_names = set(re.findall(r'^\| `([^`]+://[^`]+)` \|', resources, re.M))
    async def scenario():
        async with create_connected_server_and_client_session(create_server(tmp_path / 'docs.db')) as client:
            actual = (await client.list_tools()).tools
            assert set(documented) == {tool.name for tool in actual}
            for tool in actual:
                row = next(line for line in tools.splitlines() if line.startswith(f'| `{tool.name}` |'))
                for parameter in tool.inputSchema.get('properties', {}):
                    assert parameter in row, f'{tool.name}: undocumented parameter {parameter}'
            assert resource_names == {str(r.uri) for r in (await client.list_resources()).resources}
    asyncio.run(scenario())


def test_desktop_snippets_match_actual_module_entry_point():
    metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    assert metadata['project']['scripts']['dialtone-watcher'] == 'dialtone_watcher.server:main'
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    configs = re.findall(r'```json\n(.*?)\n```', readme, re.S)
    assert len(configs) == 3
    for block in configs:
        server = json.loads(block)['mcpServers']['dialtone-watcher']
        assert server['args'] == ['-m', 'dialtone_watcher.server']
        assert server['command'].endswith(('/bin/python', '\\Scripts\\python.exe'))


def test_release_metadata_and_data_declarations():
    metadata = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    assert metadata['project']['version'] == '0.1.0'
    assert metadata['project']['requires-python'] == '>=3.11'
    assert metadata['project']['license'] == 'MIT'
    assert metadata['project']['license-files'] == ['LICENSE', 'THIRD_PARTY_NOTICES']
    assert set(metadata['tool']['setuptools']['data-files']['share/dialtone-watcher']) == {
        'data/rules.yaml', 'data/knowledge.yaml'}
    for filename in ('LICENSE', 'SECURITY.md', 'CHANGELOG.md'):
        assert (ROOT / filename).is_file()
