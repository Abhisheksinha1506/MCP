# Dialtone Watcher

An offline, advice-only local MCP server under development. Milestone 1 provides
the platform collector contract, metadata schema, normalization, redaction,
and append-only SQLite storage. OS collectors, MCP tools, rules and findings
are planned; this milestone does not yet inspect your machine.

Requires Python 3.11+. From this folder:

```sh
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m pytest
```

Only mcp (official Python SDK), psutil, PyYAML and pytest are dependencies.
If unrelated globally installed pytest plugins break collection, run with
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` (PowerShell: `$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"`).

## Metadata contract and privacy

Snapshots contain a random ID, UTC timestamp, OS, SHA-256 hostname hash,
privilege level and visibility notes. Process metadata contains executable
name/path, publisher, trust signal, executable SHA-256, CPU percentage,
memory in MB, start time and parent process name. Connections contain process
name, remote address/port, protocol and an optional locally known domain.
Startup metadata contains name, kind, executable/configuration path, enabled
status and source. No DNS lookups or external requests are permitted.

The schema excludes file contents, command-line arguments and account fields.
Normalization drops unrecognized fields. Redaction replaces Windows, macOS
and Linux home prefixes with `~`, removes sensitive field names recursively,
and masks the current account name in text. Collectors must never feed raw
commands, file contents or arbitrary OS diagnostic text into the schema.
Executable hashes will require reading executable bytes but never storing or
returning those bytes. Hostname hashing is pseudonymization, not anonymity.

Only explicitly supplied snapshots are stored. SQLite contains redacted JSON;
there is no deletion, replacement, process-control or system-modification API.
Use a local private directory for future persistent databases. Current tests
use temporary databases. Partial visibility must be reported by collectors;
unknown trust is never evidence of wrongdoing. Package-unowned Linux binaries
are at most unusual. Peer comparison will expose an unavailable result in a
later milestone; there is no peer dataset or remote service.
