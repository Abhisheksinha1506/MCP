# Dialtone Watcher

An offline, advice-only local MCP server under development. Milestones 1–2 provide
the metadata schema, redaction, SQLite storage, and a macOS collector. MCP tools,
rules and findings are planned. Windows and Linux collectors are not implemented.

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

## macOS snapshot (milestone 2)

After installation, run `python -m dialtone_watcher.snapshot` for a counts-only
summary. Python callers can use `from dialtone_watcher.snapshot import take_snapshot`
and `snapshot = take_snapshot()`; `snapshot.to_dict()` returns redacted metadata.
This function does not save a database or modify the system. Selection uses
`sys.platform == "darwin"`; other platforms currently raise `NotImplementedError`.

The collector uses per-process psutil APIs, falling back to the older
`connections()` API when necessary. It never collects command lines or resolves
DNS. Individual process failures preserve the rest of the snapshot. Visibility
notes count limited operations by data source and failure reason; one process
can contribute multiple failures. Without root, protected processes and most
connections may be inaccessible. Run manually with `sudo` from a trusted local
Python environment if broader visibility is needed. Full Disk Access under
System Settings > Privacy & Security may help with protected startup files.
Neither elevation nor Full Disk Access guarantees access to all data. Processes
that exited cannot be recovered. An execution sandbox may block enumeration
entirely; then the snapshot reports empty process lists and the limitation.

Publisher metadata comes from `codesign -dv --verbose=2`. Gatekeeper assessment
runs `spctl --assess --type execute --no-cache` inside macOS `sandbox-exec` with
network access and all service lookups denied. This conservative offline policy
can prevent Gatekeeper from working: trust remains `unknown` in that case.
A publisher string alone never establishes verified trust. Missing tools,
timeouts, rejected assessments and malformed output also remain `unknown`;
only explicit unsigned codesign output maps to `unsigned`. Diagnostics are
summarized rather than exposing raw tool output. No assessments run without
the offline sandbox wrapper. No security policy or cache is modified.

Only `~/Library/LaunchAgents`, `/Library/LaunchAgents` and
`/Library/LaunchDaemons` are scanned. Plists provide the label, program path
(or the first ProgramArguments entry only), Disabled status, RunAtLoad, and
KeepAlive boolean or boolean conditions. No other arguments or plist contents
are returned. System paths (including symlink targets) and login items are
excluded and this coverage gap appears in visibility notes. Unreadable or
malformed files are skipped and counted. Startup enabled status reflects the
plist's Disabled flag, not launchctl overrides or proof of current execution.

Executable SHA-256 is streamed in 1 MB chunks, with a 200 MB per-file limit.
Hashing and signature metadata are cached by executable path per snapshot,
with at most 100 unique executables inspected. Signature subprocesses have a
three-second timeout each and a cumulative ten-second inspection budget
(one in-flight executable may exceed the cumulative budget). Skips are counted.
CPU percentages are nonblocking initial samples and may be zero.

Tests mock macOS APIs and fixtures; the real snapshot integration test runs
only on macOS and requires ordinary process visibility outside restrictive
execution sandboxes. Run `python -m pytest` in the fresh virtual environment;
no special plugin flags are needed there.
