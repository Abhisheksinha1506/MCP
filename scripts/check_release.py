#!/usr/bin/env python3
"""Build wheel + sdist, rebuild from sdist, then smoke-test a clean wheel install.

Uses only stdlib and the project's declared setuptools build backend. pip may
use the network to provision build/runtime dependencies. No publication or tag.
Temporary workspaces and synthetic databases are retained, never removed here.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import venv
import zipfile


def run(args, cwd):
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    env['PYTHONNOUSERSITE'] = '1'
    subprocess.run([str(a) for a in args], cwd=cwd, env=env, check=True)


def python_at(folder):
    return folder / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def unpack(archive, destination):
    # Explicit safe extraction also works with Python 3.11 before tar filters.
    with tarfile.open(archive) as source:
        for item in source.getmembers():
            path = Path(item.name)
            if path.is_absolute() or '..' in path.parts or item.issym() or item.islnk():
                raise ValueError('Unexpected unsafe sdist member')
            target = destination / path
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif item.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(item) as data, target.open('wb') as output:
                    shutil.copyfileobj(data, output)
            else:
                raise ValueError('Unexpected sdist member type')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=Path('dist'))
    args = parser.parse_args()
    project = Path(__file__).resolve().parent.parent
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if list(output.glob('*.whl')) or list(output.glob('*.tar.gz')):
        raise SystemExit('Artifact directory already contains distributions; select a new --output-dir.')
    root = Path(tempfile.mkdtemp(prefix='dialtone-release-check-'))
    source = root / 'source'
    source.mkdir()
    # Build only tracked/intentionally staged working files, never private untracked files.
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=project).decode().split('\0')
    for name in filter(None, tracked):
        path = project / name
        if path.is_symlink():
            raise ValueError('Tracked symlinks require explicit release review')
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    metadata = tomllib.loads((source / 'pyproject.toml').read_text(encoding='utf-8'))
    builder, installed = root / 'builder', root / 'installed'
    venv.EnvBuilder(with_pip=True).create(builder)
    build_python = python_at(builder)
    run([build_python, '-m', 'pip', 'install', *metadata['build-system']['requires']], root)
    artifacts = root / 'artifacts'
    artifacts.mkdir()
    build = ('import setuptools.build_meta as backend; import sys; '
             'destination = sys.argv[1]; backend.build_sdist(destination); backend.build_wheel(destination)')
    run([build_python, '-c', build, artifacts], source)
    wheel, = artifacts.glob('*.whl')
    sdist, = artifacts.glob('*.tar.gz')
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        for filename in ('rules.yaml', 'knowledge.yaml'):
            assert any(n.endswith('/share/dialtone-watcher/' + filename) for n in names)
        assert any(n.endswith('/licenses/LICENSE') for n in names)
        assert any(n.endswith('/licenses/THIRD_PARTY_NOTICES') for n in names)
        assert any(n.endswith('/entry_points.txt') for n in names)
    extracted = root / 'extracted'
    unpack(sdist, extracted)
    sdist_source, = extracted.iterdir()
    for filename in ('LICENSE', 'THIRD_PARTY_NOTICES', 'README.md', 'SECURITY.md', 'CHANGELOG.md', 'data/rules.yaml', 'data/knowledge.yaml'):
        assert (sdist_source / filename).is_file(), 'Missing sdist file: ' + filename
    rebuilt = root / 'rebuilt'
    rebuilt.mkdir()
    run([build_python, '-c', 'import setuptools.build_meta as b; import sys; b.build_wheel(sys.argv[1])', rebuilt], sdist_source)
    rebuilt_wheel, = rebuilt.glob('*.whl')
    venv.EnvBuilder(with_pip=True).create(installed)
    installed_python = python_at(installed)
    run([installed_python, '-m', 'pip', 'install', rebuilt_wheel], root)
    outside = root / 'outside-checkout'
    outside.mkdir()
    smoke = outside / 'smoke_wheel.py'
    shutil.copy2(source / 'scripts/smoke_wheel.py', smoke)
    run([installed_python, smoke], outside)
    # Retain both original distributions only after the rebuilt wheel passes.
    shutil.copy2(wheel, output / wheel.name)
    shutil.copy2(sdist, output / sdist.name)
    print(json.dumps({'wheel': wheel.name, 'sdist': sdist.name, 'sdist_rebuild': True,
                      'clean_install': True, 'publication': False}))


if __name__ == '__main__':
    main()
