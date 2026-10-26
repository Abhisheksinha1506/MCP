#!/usr/bin/env python3
"""Explicit local demo: collect one snapshot, print counts and up to five findings.

Run from the repository root after installation. No database writes or MCP server.
"""
import json

from dialtone_watcher.findings import analyze
from dialtone_watcher.snapshot import take_snapshot


def main():
    report = analyze(take_snapshot())
    print(json.dumps({**report.counts(), 'suppressed': len(report.suppressed),
                      'allowlisted': len(report.allowlisted), 'not_assessed': len(report.not_assessed)}))
    for finding in report.findings[:5]:
        print(json.dumps(finding.to_dict(), ensure_ascii=False))
    if not report.findings:
        print('No findings matched the visible metadata. Unseen sources are not assessed; this does not establish safety.')


if __name__ == '__main__':
    main()
