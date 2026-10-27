# Dialtone Watcher

Local, offline computer-activity inspection through a stdio MCP server.
Python 3.11+ · macOS / Windows / Linux · version 0.1.0 · [MIT](LICENSE)

## 1. What it is and is not

Dialtone Watcher helps answer “What is my computer doing that I did not ask
for?” It collects visible process, connection and automatic-launch metadata,
then lets an MCP client explain local rule matches and sourced process context.

It is **read-only toward processes and system settings**, and **advice-only**:
it never stops processes, disables services, changes startup settings or removes
software. It creates its own local storage at server startup, and an explicit
snapshot request appends metadata. It is not an antivirus, endpoint protection
product or forensic guarantee. **No findings is NOT a safety verdict.** Results
are heuristics, can be wrong, and cannot detect all malware. Read assessment
gaps and visibility notes alongside any finding.

## 2. Install

Use Python **3.11 or newer**. CI exercises 3.11 and 3.12 on macOS, Windows and
Ubuntu; the local verification record below separately identifies the Mac's
Python version. Runtime dependencies are the official `mcp>=1.30,<2` SDK
(FastMCP API), psutil and PyYAML. No administrator access is needed to function.

### From source

macOS or Linux, in a terminal with Git and Python 3.11+:

```sh
git clone https://github.com/Abhisheksinha1506/MCP.git dialtone-watcher
cd dialtone-watcher
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -c "import sys; print(sys.executable)"
```

Windows PowerShell, with Git and Python 3.11+ on PATH:

```powershell
git clone https://github.com/Abhisheksinha1506/MCP.git dialtone-watcher
Set-Location dialtone-watcher
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -c "import sys; print(sys.executable)"
```

The final command prints the absolute interpreter path to paste into the client
configuration. Keep the installation/venv at a stable location. No shell
activation is required. The Windows shell commands are not executed on this
Mac; CI verifies the underlying installation and executable on Windows.

### Via pip or pipx from a local wheel

**This milestone does not publish to PyPI or create a release tag.** Do not
assume an index package with this name is this project's release. Build a local
wheel using section 10, or obtain a wheel from a source you have reviewed.
The expected filename is `dialtone_watcher-0.1.0-py3-none-any.whl`.

With the venv created above, macOS/Linux:

```sh
.venv/bin/python -m pip install ./dist/dialtone_watcher-0.1.0-py3-none-any.whl
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install .\dist\dialtone_watcher-0.1.0-py3-none-any.whl
```

Or, if [pipx is installed](https://pipx.pypa.io/stable/installation/), on any OS:

```sh
pipx install ./dist/dialtone_watcher-0.1.0-py3-none-any.whl
pipx environment --value PIPX_BIN_DIR
```

Use the absolute `dialtone-watcher` executable in that printed directory
(`dialtone-watcher.exe` on Windows) with no arguments. pipx itself is a separate
installation tool, not a project dependency. macOS pip/pipx verification and
any unverified command paths are recorded in section 10. Package installation
and dependency downloads may use the internet; server operation stays offline.

## 3. Connect to a client

### Claude Desktop

Open **Settings → Developer → Edit Config** in the installed app, merge the
`mcpServers` entry below into its JSON, then fully quit and reopen the client.
Preserve other server entries. Use a real absolute path; `~`, `%VARIABLE%` and
relative paths in the `command` string are not shell-expanded by this server.

| OS | Config file location |
| --- | --- |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json`; use Edit Config to locate the file for the installed package, including Store/MSIX variants. |
| Linux | Use Edit Config to locate the actual file. `~/.config/Claude/claude_desktop_config.json` is the [community-build convention](https://github.com/aaddrick/claude-desktop-debian#configuration), **unverified here for the official Linux beta**. Do not assume this path without checking the app. |

macOS/Windows locations follow the [MCP Desktop quickstart](https://modelcontextprotocol.io/docs/develop/connect-local-servers).
Anthropic now lists a [Linux beta](https://support.claude.com/en/articles/10065433-install-claude-desktop);
its installed GUI/config location has not been tested here. Desktop host support
and its own OS requirements are separate from this server's collector tests.

Replace these **example installation paths** with the interpreter printed during
installation. The module and arguments are checked against the actual entry
point and exercised by the installed-wheel test on each CI OS.

macOS:

```json
{
  "mcpServers": {
    "dialtone-watcher": {
      "command": "/Applications/dialtone-watcher/.venv/bin/python",
      "args": ["-m", "dialtone_watcher.server"]
    }
  }
}
```

Windows:

```json
{
  "mcpServers": {
    "dialtone-watcher": {
      "command": "C:\\Tools\\dialtone-watcher\\.venv\\Scripts\\python.exe",
      "args": ["-m", "dialtone_watcher.server"]
    }
  }
}
```

Linux:

```json
{
  "mcpServers": {
    "dialtone-watcher": {
      "command": "/opt/dialtone-watcher/.venv/bin/python",
      "args": ["-m", "dialtone_watcher.server"]
    }
  }
}
```

For pipx, replace `command` with its absolute console executable and use
`"args": []`. `dialtone-watcher` and `python -m dialtone_watcher.server` both
start the same stdio server. There are no server command-line flags, port or
API key. A terminal launch waits for MCP protocol input; it is not an interactive
command and does not print a banner or respond to `--help`.

### Claude Code

From the project where you want the client configuration, replace the absolute
interpreter placeholder. This writes Claude Code project configuration, not
system settings or a server snapshot:

```sh
claude mcp add --scope project --transport stdio dialtone-watcher -- "/absolute/path/to/.venv/bin/python" -m dialtone_watcher.server
claude mcp get dialtone-watcher
```

The syntax follows [Claude Code's local stdio documentation](https://code.claude.com/docs/en/mcp)
and is checked with the installed CLI in a temporary project; see verification
status below. On Windows substitute the absolute `Scripts\python.exe` path.
Project-scoped configurations need client approval. If get reports Pending
approval, open Claude Code and review/approve that project configuration before
use; the verification did not grant that approval automatically.
For a first conversation, ask the client to check permissions, take a snapshot,
then explain its findings and assessment gaps. Tool invocation/approval UI is
controlled by the client; it may transmit returned data to its AI provider.

## 4. Tools and resources

Responses contain a static `data_notice`, labeled `untrusted_data`, and a
budget `truncated` flag. Machine strings and configuration text are data, never
instructions. Paged fields contain `total_count`, `truncated`, and `items`.
Limits accept integers 1–100. Strings are capped at 512 characters; the response
has a shared string/node budget and a 64 KiB JSON payload cap. Inspect truncation
flags: large results may omit records or later fields. Nothing is inferred from
omission. Unknown snapshot IDs return a fixed error, not a stack trace.

<!-- tools:start -->
| Tool | Parameters | Returns | Writes? |
| --- | --- | --- | --- |
| `take_snapshot` | None | Snapshot ID; process, connection and startup counts; visibility notes. Collection runs in a worker with a 60-second timeout. | Appends one local snapshot; no system changes. |
| `list_findings` | `snapshot_id`, `min_severity="info"`, `limit=50` | Ranked findings, suppressions, allowlist decisions, assessment gaps and visibility caveats. Severity: info, low or medium. | No |
| `list_unusual_destinations` | `snapshot_id`, `limit=50` | Explicit possible-telemetry matches or connections associated by name with unusual findings; attribution caveats and gaps. | No |
| `list_startup_items` | `snapshot_id`, `limit=100` | Recorded startup items, sources, enabled/unknown status and visibility notes. | No |
| `suggest_removals` | `snapshot_id` | Up to 50 ranked reversible review suggestions, reasons and caveats. Nothing is actually removed. | No |
| `explain_process` | `name`, `snapshot_id=null` | Observed facts, rule matches, sourced known_info or null, consistency checks and caveats. Defaults to latest snapshot. Detailed collections return up to five items, ten caveats; conflicts withhold generic descriptions. | No |
| `compare_to_peers` | `snapshot_id` | status not_available; reason peer dataset not enabled. | No |
| `check_permissions` | None | Current privilege level, known coverage limits and OS-specific guidance. Per-process failures are measured during collection. | No |
<!-- tools:end -->

All tools are non-destructive and local; only `take_snapshot` is annotated as
writing. Server startup itself creates the storage directory/table if needed.
A timed-out snapshot is not saved. Python cannot forcibly stop the worker; it
may finish existing read operations afterward, and another collection is refused
until it finishes. Other tools remain available; shutdown can wait for it.

<!-- resources:start -->
| Resource | Returns | Writes? |
| --- | --- | --- |
| `snapshot://latest` | Latest stored snapshot as bounded, redacted JSON, with total counts. | No |
| `rules://active` | The rules file loaded when the server started, represented as bounded, redacted JSON. | No |
<!-- resources:end -->

`explain_process` performs exact name matching, ignoring case on macOS/Windows
and preserving it on Linux. It compares documented location/signer expectations
against recorded facts. `matches` is metadata consistency, not proof of identity;
missing evidence is `not_checkable`, and any conflicting instance makes the
summary `mismatch`. With neither knowledge nor rule matches, it returns
“no information available” plus observed facts and a vendor/signature-check
suggestion. Knowledge never changes finding severity or core allowlist logic.

## 5. Permissions guide

**The server never needs elevated privileges to function.** It returns partial
results with limits and guidance. Understand the implications before elevating:
you give the interpreter, dependencies and client-started server greater access.
Use only a trusted installation, start without elevation, and inspect
`check_permissions` and snapshot visibility notes first. The server never grants
permissions, elevates itself or changes OS policy. Elevation cannot recover
exited processes or bypass every protection.

| OS | Ordinary-account visibility and limits | Optional broader access |
| --- | --- | --- |
| macOS | Visible process metadata and selected startup plists; protected processes and many per-process connections can deny access. Login items and /System startup definitions are not inspected. | Manually launch a trusted local environment with sudo only if you understand the wider access. Full Disk Access for the actual host/interpreter may help **protected startup-file reads**, not guarantee connection visibility. Review System Settings → Privacy & Security → Full Disk Access; this tool does not request it automatically. |
| Windows | Visible processes, Run/RunOnce keys, Startup folder entries, selected scheduled tasks and automatic services; protected processes/keys/tasks may be hidden. | Manually launch a trusted terminal/client with Run as administrator. Some protected processes remain inaccessible. PowerShell execution policy is never bypassed. |
| Linux | Visible /proc process/connection metadata, local package ownership, current-user/system startup configuration; other accounts can be hidden. | Manually launch a trusted environment with sudo for broader visibility. Root can still be limited by namespaces, security policy or /proc hidepid. Ask an administrator to review hidepid policy; the server never remounts /proc. Run inside the desktop login session for user systemd visibility. |

A client already running without elevation does not become elevated because an
unrelated terminal was elevated. These optional manual procedures are **not
executed by verification**, and elevated launches are not recommended as a
routine client configuration. Missing OS tools must be installed separately.

## 6. Privacy and storage

### What is collected

The tables below are generated from `dialtone_watcher/schema.py` and checked in
CI. Snapshot, Process, Connection and StartupItem are stored metadata; Finding is
derived analysis returned by tools, not a separately stored table. Process CPU
values are nonblocking first samples and may be zero. Memory is in MiB (bytes
per 1024²), executable hashes are SHA-256, and timestamps are UTC strings.
Connections are attributed by process name, not a durable process-instance ID.
Startup metadata describes configuration, not proof of current execution.

<!-- generated-schema:start -->

<!-- schema:Snapshot:start -->
#### Snapshot

| Field | Python type |
| --- | --- |
| `id` | `str` |
| `created_at` | `str` |
| `os` | `Literal['macos', 'windows', 'linux']` |
| `hostname_hash` | `str` |
| `privilege_level` | `str` |
| `visibility_notes` | `list[str]` |
| `processes` | `list[dialtone_watcher.schema.Process]` |
| `connections` | `list[dialtone_watcher.schema.Connection]` |
| `startup_items` | `list[dialtone_watcher.schema.StartupItem]` |
<!-- schema:Snapshot:end -->

<!-- schema:Process:start -->
#### Process

| Field | Python type |
| --- | --- |
| `name` | `str` |
| `exe_path` | `str` |
| `publisher` | `str \| None` |
| `trust_signal` | `Literal['verified', 'unsigned', 'package_owned', 'unknown']` |
| `sha256` | `str \| None` |
| `cpu_percent` | `float` |
| `mem_mb` | `float` |
| `started_at` | `str \| None` |
| `parent` | `str \| None` |
<!-- schema:Process:end -->

<!-- schema:Connection:start -->
#### Connection

| Field | Python type |
| --- | --- |
| `process_name` | `str` |
| `remote_host` | `str` |
| `remote_port` | `int` |
| `protocol` | `str` |
| `resolved_domain` | `str \| None` |
<!-- schema:Connection:end -->

<!-- schema:StartupItem:start -->
#### StartupItem

| Field | Python type |
| --- | --- |
| `name` | `str` |
| `kind` | `str` |
| `path` | `str` |
| `enabled` | `bool \| None` |
| `source` | `str` |
| `run_at_load` | `bool \| None` |
| `keep_alive` | `bool \| dict[str, bool] \| None` |
<!-- schema:StartupItem:end -->

<!-- schema:Finding:start -->
#### Finding

| Field | Python type |
| --- | --- |
| `type` | `Literal['junk', 'telemetry', 'unusual']` |
| `subject` | `str` |
| `severity` | `Literal['info', 'low', 'medium']` |
| `reason` | `str` |
| `suggested_action` | `str` |
| `platforms` | `list[str]` |
| `rule_id` | `str` |
| `confidence` | `Literal['high', 'medium', 'low']` |
| `evidence` | `list[str]` |
| `caveats` | `list[str]` |
<!-- schema:Finding:end -->

<!-- generated-schema:end -->

### Where it is stored

SQLite stores redacted snapshot JSON in `snapshots(id, created_at, payload)`.
The hostname is stored only as a stable SHA-256 hash (pseudonymization, not
anonymity). Startup initializes storage, and each successful explicit
`take_snapshot` appends one row. No update, replace, per-snapshot deletion or
automatic retention API exists. Findings are computed from stored snapshots;
the plain Python collector alone does not persist them.

| OS | Default database |
| --- | --- |
| macOS | `~/Library/Application Support/dialtone-watcher/snapshots.sqlite3` |
| Windows | `%LOCALAPPDATA%\dialtone-watcher\snapshots.sqlite3`; fallback `~/AppData/Local/dialtone-watcher/snapshots.sqlite3` if LOCALAPPDATA is unset. |
| Linux | `$XDG_DATA_HOME/dialtone-watcher/snapshots.sqlite3`; fallback `~/.local/share/dialtone-watcher/snapshots.sqlite3`. |

`DIALTONE_WATCHER_DB` overrides this with a local file path. Keep it in a private
directory. Stderr logs can contain private exception diagnostics and are kept
by the host/client according to its settings; redact them before sharing.

### Redaction, exclusions and network behavior

Home prefixes `/Users/<account>`, `/home/<account>`, `/root`, and case-insensitive
Windows drive/Users paths become `~`. UNC paths become `[network path]`. The
current account name is masked in text (the public root privilege value is
preserved). Sensitive account/argument/content field keys are dropped. Unknown
input fields are removed by normalization. Tool/resource outputs also strip
controls and apply size limits. Redaction cannot identify every arbitrary
account name in free text; collectors avoid collecting account fields. Paths
outside home directories, executable names, destination IPs/domains and the
pseudonymous hostname hash remain potentially identifying metadata.

Never collected or returned as snapshot fields: usernames/UIDs/GIDs, full home
prefixes, raw hostname, command-line arguments, file contents, packet payloads,
browsing history or environment-variable dumps. Hashing **reads executable bytes
in chunks** but stores only a digest, with a 200 MiB per-file bound and snapshot
inspection budgets. Startup configuration and signature/package metadata are read
only to extract permitted fields; their raw contents/diagnostics are not stored
in snapshots. Local rules and knowledge files are explicit configuration data.

**The v1 server makes no external network calls:** no DNS resolution, HTTP
requests, uploads, telemetry submission or peer lookup. It reads locally
available destination names only; many connections therefore have no domain.
OS trust checks are constrained for offline use as described below. Package
installation, build dependency downloads and CI can use networks. The MCP/AI
client has its own storage/network policy and may send the returned metadata to
its configured provider; review that policy before connecting.

### How to delete stored snapshots (manual; destructive)

There is no deletion tool. To intentionally clear **all** stored history, first
stop every server using that database by quitting/disconnecting its MCP clients.
Confirm the configured path, including any DIALTONE_WATCHER_DB override. Using
Finder/File Explorer or your local file manager, remove that `snapshots.sqlite3`
file and any same-database `-journal`, `-wal` or `-shm` sidecars **after all
connections are closed**. Do not remove unrelated files. The server creates an
empty database next time it starts. Moving the database aside is a reversible
alternative; removing it is destructive. Backups, client chat histories and
client logs are separate copies. Verification never deletes a user database.

## 7. Limitations

- Unknown trust is neutral. Publisher strings and expected locations do not
  establish executable identity. Unsigned alone produces no finding; explicit
  matches and defined combinations of signals can still be false positives.
- Permissions, exited processes, /proc hidepid, namespaces, tool failures,
  timeouts, file-size limits and inspection budgets leave gaps. Completely
  invisible processes cannot be counted. Multiple instances sharing a name make
  connection attribution uncertain. No output establishes complete coverage.
- Starter data is small: 13 rules (including core/context entries) and 41
  knowledge entries; the bloatware and ignore sections start empty. Entries
  need human review. Missing a process/domain is not an endorsement.
- macOS uses codesign plus Gatekeeper inside a network/service-denying
  sandbox-exec wrapper. Gatekeeper can fail under that offline restriction;
  missing tools or unavailable checks remain unknown. A publisher alone is not
  verified trust. Only explicit unsigned output becomes unsigned.
- Windows Authenticode uses batched PowerShell JSON with timeouts. Checks are
  skipped as OfflineRequired unless all non-loopback adapters are down, avoiding
  certificate network retrieval. The server never disables adapters for you;
  ordinary connected machines often retain unknown trust.
- Linux has no standard signing check here: local dpkg/rpm/pacman package
  ownership supplies package_owned provenance. Unowned executables remain
  unknown and get a visibility note, not a finding merely for being unowned.
- Startup coverage is selective: macOS excludes login items and /System
  startup definitions; Windows does not resolve shortcut targets or inspect
  StartupApproved overrides/other accounts; Linux covers enabled system/user
  units, XDG autostart and selected cron configuration, including recurring jobs.
- There is no peer dataset, remote reputation service, automatic remediation or
  ability to detect all malware. See [the threat model](SECURITY.md).

## 8. Rules and knowledge files

**Both starter datasets need human review before relying on them.** Sources
are recorded below and in source_note; they are not fetched at runtime.
Source check date for rules: 2026-10-26; knowledge: 2026-10-27.

The checkout keeps `data/rules.yaml` and `data/knowledge.yaml`. Wheels install
them under `<venv>/share/dialtone-watcher/`; distribution file metadata also
identifies the actual installed paths. There is no CLI flag, environment variable
or MCP tool to select alternate files. For an editable development install edit the checkout's files. A normal
`pip install .` from source is also a non-editable wheel installation: edit its
installed data files, as with wheel/pipx installs, after making a local copy. Upgrades may replace them. Restart the server
after editing rules; knowledge is loaded and validated on each explain call.

Rules have five sections: known_telemetry_domains, known_bloatware,
trusted_publishers, core_os_allowlist and ignore_list. Each rule requires id,
match, reason, confidence (high/medium/low), and platforms (OS list or all).
Optional fields: severity (info/low/medium) and source_note. Add a unique ID and
reviewed provenance, an exact/glob/restricted-regex process name, publisher or
path predicate; startup label/name/path; exact/suffix domain; or a finding
rule_id/subject suppression. Predicates within a rule combine with AND.

For example, this **documentation-only fragment** illustrates a user opt-out
under ignore_list; it is not added to the shipped rules:

```yaml
- id: local.ignore-reviewed-entry
  match:
    target: finding
    rule_id: {exact: mozilla.firefox.telemetry}
  reason: I reviewed this app setting and prefer to suppress this rule.
  confidence: high
  platforms: all
  source_note: Local user decision; review again if the app configuration changes.
```

Suppressions remain visible. The core allowlist requires a name AND expected
location or publisher and wins before findings. Known core names in unexpected
locations can produce unusual identity-review findings. Low confidence caps
severity at info; medium caps it at low; high can reach medium. Unknown trust is
neutral and never raises severity. Trusted publishers are context only.

Knowledge uses an entries list. Required fields: id, names, platforms,
description (plain-language purpose), publisher (nullable exact signer text),
category, usually_safe_to_ignore (boolean or depends), confidence, source_note
and last_reviewed (ISO date). Optional expected_locations contain whole-path
patterns. Categories are os_core, driver, updater, browser, cloud_sync, security,
developer_tool and other. A name can have different entries per platform; same-
platform ambiguity, missing/unknown fields, invalid dates/categories and empty
descriptions are rejected. Restricted security wording requires a security-tool
entry; descriptions cannot give a safe verdict. Conflicts with observed metadata
withhold descriptions; below-high confidence is explicitly stated in output.

Paths/names ignore case on macOS/Windows and preserve it on Linux. Windows path
separators normalize; domains normalize case/IDNA and suffixes respect label
boundaries. Rule regexes use a restricted, precompiled subset: no groups,
alternation, backreferences, lookarounds or brace repetition, and at most one
quantified atom. Matching length limits apply. Use redacted home paths in
patterns. **Adding configuration cannot establish file identity.** Validate
custom files locally before use:

```sh
.venv/bin/python -c "from dialtone_watcher.rules import load_rules; from dialtone_watcher.knowledge import load_knowledge; print(len(load_rules('data/rules.yaml').rules), len(load_knowledge('data/knowledge.yaml').entries))"
```

On Windows use `.\.venv\Scripts\python.exe` for that interpreter; the Python
expression is identical and platform-independent. Full matcher behavior and
validation examples are covered by the unit tests.

<details>
<summary>Starter rule provenance — every entry needs human review</summary>

| Rule ID | Source and justification | Review status |
| --- | --- | --- |
| mozilla.firefox.telemetry | Mozilla explicitly lists incoming.telemetry.mozilla.org under [Telemetry](https://support.mozilla.org/en-US/kb/domains-allow-firefox). Applies to all three Firefox desktop platforms; consent remains unknown. | needs human review |
| core.macos.launchd | Apple's [launchd manual source](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.8) identifies the daemon manager; local read-only codesign inspection verified the /sbin/launchd path. | needs human review |
| core.macos.kernel-task | Apple identifies [kernel_task as a system process](https://support.apple.com/en-us/102172). The blank executable is a limited kernel-context representation. | needs human review |
| core.linux.systemd-usr | The upstream [systemd manual](https://www.freedesktop.org/software/systemd/man/251/init.html) names /usr/lib/systemd/systemd. | needs human review |
| core.linux.systemd-lib | Debian bookworm's [systemd file list](https://packages.debian.org/bookworm/amd64/systemd/filelist) documents /lib/systemd/systemd. | needs human review |
| core.linux.init | The upstream [systemd manual](https://www.freedesktop.org/software/systemd/man/251/init.html) describes /sbin/init as the boot entry point. | needs human review |
| core.windows.system | Microsoft includes System among its [critical system services](https://learn.microsoft.com/en-us/windows/win32/rstmgr/critical-system-services). Blank executable metadata does not verify identity. | needs human review |
| core.windows.svchost-system32 | Microsoft's [service-host discussion](https://azure.microsoft.com/en-us/blog/ways-to-use-azure-security-center-log-analytics-for-threat-hunting/) identifies system32 and SysWOW64 locations. The rule covers standard Windows installation directories. | needs human review |
| core.windows.svchost-wow64 | The same [Microsoft source](https://azure.microsoft.com/en-us/blog/ways-to-use-azure-security-center-log-analytics-for-threat-hunting/) documents the SysWOW64 variant. | needs human review |
| core.windows.csrss | Microsoft's [protocol exclusion example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsrm/7f4ee0ea-be67-4cca-a44c-ad6bfc7da803) supplies the system32/csrss.exe path. | needs human review |
| core.windows.explorer | Microsoft's [Sysinternals reference sample](https://download.microsoft.com/download/a/f/a/afab0aee-5bcb-445d-9e1a-a45214fa4e5f/9780735656727_samplechapters.pdf) uses c:/windows/explorer.exe. This is a standard-layout policy. | needs human review |
| publisher.microsoft-windows | The same [Sysinternals sample](https://download.microsoft.com/download/a/f/a/afab0aee-5bcb-445d-9e1a-a45214fa4e5f/9780735656727_samplechapters.pdf) documents the Microsoft Windows signer CN; used only as context. | needs human review |
| publisher.systemd-package | Debian's [systemd package description](https://packages.debian.org/stable/systemd) identifies the system/service manager package; used only as provenance context. | needs human review |

</details>

<details>
<summary>Knowledge provenance — every entry needs human review</summary>

| Entry ID | Source type and provenance |
| --- | --- |
| macos.launchd | OS documentation: https://support.apple.com/guide/terminal/apdc6c1077b-5d5d-4d35-9c19-60f2397b2369/mac; executable /sbin/launchd verified locally. |
| macos.kernel-task | OS documentation: https://support.apple.com/en-us/102172 |
| macos.finder | OS documentation: https://support.apple.com/guide/mac-help/mchlp2605/mac; standard executable location verified locally. |
| macos.dock | OS documentation: https://support.apple.com/guide/mac-help/mh35859/mac; standard executable location verified locally. |
| macos.mds | OS installed manual: Apple-supplied mds(8), /usr/share/man/man8/mds.8; metadata-server DESCRIPTION; executable location verified locally. |
| macos.mdworker | OS installed manual: Apple-supplied mdworker(8), /usr/share/man/man8/mdworker.8, DESCRIPTION. |
| windows.csrss | OS documentation: https://www-stg.microsoftpressstore.com/articles/article.aspx?p=2201310; Windows Internals, Boot Process table and initialization discussion. |
| windows.services | OS documentation: https://www-stg.microsoftpressstore.com/articles/article.aspx?p=2201310; Windows Internals, Boot Process table and initialization discussion. |
| windows.wininit | OS documentation: https://www-stg.microsoftpressstore.com/articles/article.aspx?p=2201310; Windows Internals, Boot Process table and initialization discussion. |
| windows.winlogon | OS documentation: https://www-stg.microsoftpressstore.com/articles/article.aspx?p=2201310; Windows Internals, Boot Process table and initialization discussion. |
| windows.lsass | OS documentation: https://www-stg.microsoftpressstore.com/articles/article.aspx?p=2201310; Windows Internals, Boot Process table and initialization discussion. |
| windows.smss | OS documentation: https://www-stg.microsoftpressstore.com/articles/article.aspx?p=2201310; Windows Internals, Boot Process table and initialization discussion. |
| windows.svchost | OS documentation: https://learn.microsoft.com/en-us/windows/win32/services/service-programs; locations: https://azure.microsoft.com/en-us/blog/ways-to-use-azure-security-center-log-analytics-for-threat-hunting/ |
| windows.system | OS documentation: https://learn.microsoft.com/en-us/windows/win32/rstmgr/critical-system-services; System is listed as a critical system process. |
| windows.explorer | OS documentation: Microsoft Sysinternals reference sample, explorer.exe path and Microsoft Windows signer: https://download.microsoft.com/download/a/f/a/afab0aee-5bcb-445d-9e1a-a45214fa4e5f/9780735656727_samplechapters.pdf |
| windows.defender | OS documentation: https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows; processes and services table. |
| windows.onedrive | OS documentation: https://learn.microsoft.com/en-us/sharepoint/sync-client-update-process; https://learn.microsoft.com/en-us/sharepoint/sync-process |
| linux.systemd | OS documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd.html |
| linux.init | OS documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd.html; documents the init entry point for systemd; this name is also used by other init implementations. |
| linux.systemd-journald | OS documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html |
| linux.systemd-logind | OS documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd-logind.service.html |
| linux.systemd-udevd | OS documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd-udevd.service.html |
| linux.systemd-resolved | OS documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html |
| linux.systemd-timesyncd | OS documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd-timesyncd.service.html |
| linux.dbus | OS documentation: https://dbus.freedesktop.org/doc/dbus-daemon.1.html |
| linux.sshd | Upstream manual: https://man.openbsd.org/sshd |
| linux.networkmanager | OS documentation: https://networkmanager.dev/docs/api/latest/NetworkManager.html |
| linux.dockerd | Vendor documentation: https://docs.docker.com/reference/cli/dockerd/ |
| linux.containerd | Upstream documentation: https://containerd.io/ |
| common.python | Upstream documentation: https://docs.python.org/3/using/cmdline.html |
| common.node | Upstream documentation: https://nodejs.org/en/about |
| common.git | Upstream documentation: https://git-scm.com/docs/git |
| common.vscode | Upstream documentation: https://code.visualstudio.com/docs/configure/command-line |
| common.firefox | Upstream documentation: https://firefox-source-docs.mozilla.org/browser/index.html |
| common.chrome | Upstream documentation: https://www.chromium.org/developers/design-documents/multi-process-architecture/ |
| common.java | Upstream documentation: https://docs.oracle.com/en/java/javase/21/docs/specs/man/java.html |
| common.go | Upstream documentation: https://go.dev/cmd/go/ |
| common.rustc | Upstream documentation: https://doc.rust-lang.org/rustc/what-is-rustc.html |
| common.cargo | Upstream documentation: https://doc.rust-lang.org/cargo/ |
| common.cmake | Upstream documentation: https://cmake.org/cmake/help/latest/manual/cmake.1.html |
| windows.onedrive-setup | Vendor documentation: https://learn.microsoft.com/en-us/sharepoint/sync-client-update-process; documents OneDriveSetup.exe for deploying updates. |

</details>

## 9. Troubleshooting

| Symptom | Check |
| --- | --- |
| Server not appearing | Use an absolute executable path from the correct venv/pipx installation, valid JSON and the correct Edit Config file. Fully restart the client. Read its local stderr logs; do not share them unredacted. |
| Stdio/protocol errors | stdout is protocol-only. Do not wrap the server with shell banners, print debugging or a command that expects interactive input. Application logs go to stderr. Both console and module launches are exercised through a real SDK client. |
| Empty network results | Inspect visibility notes and assessment gaps. Per-process access often requires broader privileges; no rows does not imply no activity. Missing locally known domains also limit domain rules; no DNS is attempted. |
| Slow first snapshot | Hashing, signature/package queries and startup enumeration can take seconds. Executable caching/budgets reduce repeated work. Collection has a 60-second deadline; no late result is saved, but a timed-out worker may still be finishing. Retry after it finishes. |
| Unknown trust / no description | Offline signature constraints, missing tools and small datasets are normal limits. No information available is deliberate; consult the vendor or file signature/package provenance. |

## 10. Development and verification

From a Git checkout, macOS/Linux:

```sh
.venv/bin/python -m pip install -e ".[test]"
.venv/bin/python -m pytest -q
.venv/bin/python scripts/document_schema.py --check
.venv/bin/python scripts/check_release.py --output-dir dist
```

Windows PowerShell uses `.\.venv\Scripts\python.exe` in place of
`.venv/bin/python`; the test/generator/build-check arguments are identical.
Regenerate the field tables after a schema change, then review the diff:

```sh
.venv/bin/python scripts/document_schema.py
```

The release check needs Git and intentionally tracked/staged source files. It
uses the existing setuptools build backend, creates an sdist and wheel, rebuilds
the wheel from that sdist, installs into a **clean venv**, and runs both stdio
entry points outside the checkout. It verifies imports come from that venv,
both bundled YAML files, the license, eight tools, two resources and synthetic
explain/findings calls. It does not collect a real snapshot, publish packages,
tag a release or delete databases. It retains temporary workspaces/synthetic
databases and writes only the two verified artifacts to dist. Select a new
--output-dir if distributions already exist there. New release files must be
tracked/staged first; private/untracked files are excluded from the build copy.
Dependency provisioning may use the network. CI calls this same check on all
three OSes and both Python versions; see the verification record for status.

CI has a full pytest matrix on ubuntu-latest, macos-latest and windows-latest,
Python 3.11/3.12, plus the wheel-install matrix above. A separate Ubuntu job
runs Linux integration in Debian/dpkg, Fedora/rpm and Arch/pacman containers
with runtime networking disabled. **All three distro families passed the
milestone 7 CI run**, including Fedora and Arch; they were not run locally on
this Mac. Container checks have few processes and no full desktop/systemd
session and do not demonstrate full-desktop coverage. Earlier milestone failures
are not current support evidence. The new release-check status appears below.

Contribute small, reviewable changes and fixture-based tests; preserve offline
operation, untrusted-data labels, redaction and protocol-only stdout. Update
schema documentation and tool tables with API changes. Add no unsupported rule
or knowledge claims. See [SECURITY.md](SECURITY.md) for sensitive reports,
[CHANGELOG.md](CHANGELOG.md) for 0.1.0 scope and [LICENSE](LICENSE) for MIT terms.
Runtime logic, tools, rules and knowledge entries are unchanged in this milestone.

### Command and platform verification record

<!-- verification:start -->

Checked on **2026-10-27**, using Python 3.13 on this Mac, in temporary candidate
checkouts/venvs. Source and original-wheel installs used separate fresh venvs;
pipx used a separate temporary pipx installation/home. The source clone was
updated with the candidate working files before testing. Personal client
configuration and user databases were not changed.

| Command or example | Observed result |
| --- | --- |
| Git clone and source-directory selection | Passed; public repository cloned in a temporary directory. |
| python3 venv creation; pip install .; print interpreter path | Passed on Mac; non-editable source installation. |
| pip install local 0.1.0 wheel | Passed in a separate clean venv; installed imports/resources checked outside the checkout. |
| pipx install local wheel; pipx environment --value PIPX_BIN_DIR | Passed on Mac; installed console/module, bundled data and MCP calls passed. |
| pip install -e .[test]; pytest -q | **335 passed, 2 platform skips**, fresh candidate checkout; no plugin flags. |
| document_schema.py and --check; explicit rules/knowledge validation expression | Passed; schema and both datasets validate. |
| check_release.py --output-dir dist | Passed: wheel + sdist, sdist rebuild, clean install, two entry points, two YAML files, eight tools and two resources. An initial helper argument-state error was fixed before the successful rerun. |
| Claude Desktop JSON templates | Parsed and checked against the real module entry point; substituted actual installed paths launched through the SDK. Native Desktop GUI loading was **not verified** on any OS. |
| claude mcp add / claude mcp get | Both exit 0 in an isolated project/config directory. Get reports **Pending approval**; Claude Code tool execution remains **unverified** until the user approves. |
| Windows PowerShell / Linux shell snippets | Not executed natively on this Mac. CI verifies Python packaging/entry points on these OSes; it does not prove their native Desktop GUI setup or PowerShell copy/paste flow. |
| Linux Desktop config file location | **Unverified for the official beta**; use the app's Edit Config. Community convention is labeled in section 3. |
| sudo, Administrator, Full Disk Access, database deletion | Manual guidance only; deliberately **not performed**. No destructive cleanup command is offered or tested. |

The [milestone 7 CI run](https://github.com/Abhisheksinha1506/MCP/actions/runs/40457357159)
proved the prior pytest matrix and Debian/Fedora/Arch checks. The milestone 8
release/wheel CI result will be linked after validation; until then it is not
claimed as demonstrated. No PyPI publication or release tag was created.

<!-- verification:end -->
