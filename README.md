# Dialtone Watcher

An offline, advice-only local MCP server under development. Milestones 1–7 provide
the metadata schema, redaction, SQLite storage, collectors for macOS, Linux
and Windows, a local rules/findings engine, a stdio MCP server, and sourced process context.

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
and masks the current account name in text. `/root` is redacted on every OS;
`root` as a public privilege-level or role remains readable. Collectors must never feed raw
commands, file contents or arbitrary OS diagnostic text into the schema.
Executable hashes will require reading executable bytes but never storing or
returning those bytes. Hostname hashing is pseudonymization, not anonymity.

Snapshots are stored when explicitly supplied to the store or requested through
the MCP `take_snapshot` tool. SQLite contains redacted JSON;
there is no deletion, replacement, process-control or system-modification API.
Use a local private directory for persistent databases. Tests
use temporary databases. Partial visibility must be reported by collectors;
unknown trust is never evidence of wrongdoing. Package-unowned Linux binaries
are at most unusual. Peer comparison will expose an unavailable result in a
later milestone; there is no peer dataset or remote service.

## macOS snapshot (milestone 2)

After installation, run `python -m dialtone_watcher.snapshot` for a counts-only
summary. Python callers can use `from dialtone_watcher.snapshot import take_snapshot`
and `snapshot = take_snapshot()`; `snapshot.to_dict()` returns redacted metadata.
This function does not save a database or modify the system. Selection uses
`sys.platform == "darwin"` for macOS and `sys.platform.startswith("linux")`
for Linux, and `sys.platform == "win32"` for Windows; other platforms raise
`NotImplementedError`.

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

## Linux snapshot (milestone 3)

Use the same `take_snapshot()` function or `python -m dialtone_watcher.snapshot`
counts-only command. Processes and per-process connections come from psutil;
older psutil falls back to `Process.connections()`. No command lines, account
names or DNS queries are collected. AccessDenied, NoSuchProcess and ZombieProcess
failures are counted by source and reason, while other processes remain visible.
Processes with an empty executable path are skipped and counted separately
(normally kernel threads; exited processes can also have no executable).

The collector inspects local `/proc/self/mounts` metadata for `hidepid` on `/proc`.
With hidepid or namespace restrictions, completely invisible processes cannot be
counted; visibility notes say this explicitly. An unreadable mount table is
reported rather than assuming visibility. Root status is reported, but does not
guarantee access across namespaces or security policies. To inspect more, run
manually with `sudo` in a trusted environment. An administrator can review proc
mount policy; the collector never remounts anything or grants permissions.
Use the desktop login session for current-account systemd units. Unavailable
tools must be installed separately; this program never installs them.

At collector creation it detects `dpkg`, then `rpm`, then `pacman` on PATH.
Ownership checks query the local package database with `dpkg -S`, `rpm -qf`, or
`pacman -Qo`. Queries batch up to 64 executable paths, cache per path, and report
query count and elapsed seconds in visibility notes. No repositories are queried.
The publisher field is the owning package name; trust is `package_owned` or
`unknown`. Package ownership indicates provenance, not code-signing verification.
A package-unowned binary, alias not present in a package manifest, unavailable
database, timeout or malformed output produces unknown trust and a note, never
a finding. Lookup time is limited to ten seconds plus one in-flight query with
a three-second timeout. At most 100 unique process executables are inspected.
The shared hasher reads chunks of 1 MB and skips executables over 200 MB.

Startup inventory includes enabled systemd unit files for system and current
account scopes, XDG `.desktop` entries, the current account's `crontab -l`,
`/etc/crontab`, and readable `/etc/cron.d` files. User XDG configuration defaults
to `~/.config/autostart` (or `$XDG_CONFIG_HOME/autostart`) and overrides matching
`/etc/xdg/autostart` filenames. Hidden entries are disabled; desktop-specific
conditions are left unevaluated and noted. This is configuration inventory,
not proof that systemd or cron is running. Missing systemctl/crontab, unavailable
user sessions and unreadable startup files produce partial results with notes.
Other accounts' user units/crontabs, cron spool directories, periodic cron
folders and init scripts are outside this milestone's coverage.

For privacy, XDG entries return desktop filenames and source configuration paths,
not localized display names or Exec strings. Cron entries use numbered labels
and source files, never account fields, commands, arguments, comments, environment
values or full crontab text. Unit names and system/user source scopes identify
systemd items. Executable command paths are not inferred from startup commands.
Home paths, including `/root`, are redacted before normalization and storage.

### Tests and Docker verification

`python -m pytest` runs the platform-independent mock tests on macOS or Linux.
The real Linux integration test is marked `linux_integration` and skipped on
macOS. The real macOS test remains skipped on Linux. The Linux test verifies
that the current Python process is present, snapshot metadata is redacted, and
counts can be printed without exposing names or paths.

`scripts/test_linux_docker.sh` tests Debian (the Debian/Ubuntu family), Fedora,
and Arch using **already prepared local images**. It refuses to pull images,
runs containers with `--network=none`, mounts this project read-only, and uses a
temporary in-container filesystem for test data. It neither builds images nor
installs packages. Containers are retained and their IDs printed; it never
deletes containers, images or volumes. Repeated runs leave additional containers
for your own lifecycle management.

Image preparation is a separate, optional dependency-installation step, requiring
network access unless base images and package repositories are already cached.
It is never performed by the collector or the verification script. Sample
Dockerfiles install Python, psutil and pytest (no new application dependencies):

```sh
docker build -t dialtone-watcher-test:debian -f scripts/docker/debian.Dockerfile .
docker build -t dialtone-watcher-test:fedora -f scripts/docker/fedora.Dockerfile .
docker build -t dialtone-watcher-test:arch -f scripts/docker/arch.Dockerfile .
scripts/test_linux_docker.sh
```

For prebuilt images, override `DIALTONE_DEBIAN_IMAGE`, `DIALTONE_FEDORA_IMAGE`,
and `DIALTONE_ARCH_IMAGE`. Each must contain Python 3.11+, pytest, psutil and the
family's package-manager binary/database (`dpkg`, `rpm`, `pacman`). Tests assert
both detection and an actual ownership lookup for the package manager's own
binary. Images do not need MCP installed because this milestone has no MCP
wiring. In containers, few processes, few/no connections and unavailable
systemd user sessions are expected. Counts reflect the container namespace,
not the host or a full Linux desktop. This does not validate a desktop's
permission policy, XDG session, or hidepid setup.

Verification on 2026-10-26: **Debian, Fedora and Arch were all NOT RUN**.
The Docker CLI was installed, but the Docker daemon socket was absent and
`docker info` could not connect. The script exited 2 with “Docker daemon
unavailable”; no containers were created and no images were downloaded.
Linux behavior on this Mac was verified with mocked OS APIs and fixture files,
not a real Linux snapshot. Batching tests verify that 100 unique paths use two
queries (64 + 36); real distro lookup timings remain unmeasured until Docker
verification runs. The collector reports measured query timings when run.

Shared fixes in this milestone: the snapshot uses the adapter's OS identity
instead of hard-coding macOS; `/root` redaction is independent of the current
account and preserves the public root privilege value; explicit home replacement
respects path boundaries. Executable hashing is shared by macOS and Linux and
uses nonblocking open plus fstat to prevent a file replaced by a FIFO from
hanging a snapshot. No Windows collector changes were made.

## GitHub Actions CI

`.github/workflows/ci.yml` runs on pushes, pull requests and manual dispatch.
The pytest matrix covers `ubuntu-latest`, `macos-latest` and `windows-latest`,
each with Python 3.11 and 3.12. Every combination creates a fresh virtual
environment, installs `.[test]`, and runs the full pytest suite without special
plugin flags. Platform-specific integration tests run only on their own OS.

**Windows jobs are required as of milestone 4.** The earlier temporary
`continue-on-error` exception has been removed. Failures on any OS or in the
Docker integration job fail the workflow.

A separate job uses the GitHub-hosted Ubuntu runner's Docker to build the three
existing distro test images and run `scripts/test_linux_docker.sh`. The test
containers exercise Debian/dpkg, Fedora/rpm and Arch/pacman, including real
package ownership lookups. Dependency installation and image preparation use
network access in CI; snapshot collection and the integration test containers
run with networking disabled. Containers are retained for the duration of the
hosted runner, with no explicit container or image deletion commands.

The earlier local Docker limitation still applies to this Mac; adding the
workflow does not establish that the remote jobs have passed. Check their
GitHub Actions results after pushing this commit.

## Windows snapshot (milestone 4)

Use `python -m dialtone_watcher.snapshot` or the same plain Python
`take_snapshot()` function. The collector imports safely on other platforms;
winreg and ctypes' Windows DLL access are loaded only inside Windows methods.
Processes and connections use per-process psutil reads, with the older
`connections()` fallback. AccessDenied, NoSuchProcess and ZombieProcess are
counted by source while other records survive. System, Registry and Idle can
have no executable path; these processes remain present with unknown trust
and a separate informational count. CPU first samples may be zero.

Publisher and trust come from PowerShell `Get-AuthenticodeSignature` and
`ConvertTo-Json`. A constant PowerShell program receives at most 32 paths as
JSON over stdin; paths are never interpolated into executable program text.
The collector uses `-NoProfile -NonInteractive`, UTF-8 JSON output, a ten-second
subprocess timeout, per-snapshot caches, at most 100 unique executables and a
15-second cumulative signature budget plus one in-flight batch. Batch calls
and measured elapsed seconds appear in visibility notes. Valid maps to verified,
NotSigned to unsigned; HashMismatch, NotTrusted, UnknownError and other statuses
remain unknown and are counted. Publisher is only the signer subject's CN,
not its complete certificate subject. Missing PowerShell, policy blocks,
malformed output and timeouts produce partial results, not execution-policy
bypasses. There are no certificate or reputation services owned by this project.

**Offline restriction:** the Windows trust provider can retrieve certificates
or revocation information. Before invoking the signature cmdlet, the constant
PowerShell script checks local adapter state and defers all assessments if a
non-loopback adapter is up, or if that check fails. Those results are unknown
with an `OfflineRequired` note; no interface or firewall setting is changed.
On a disconnected machine the cmdlet uses locally available trust material.
The check is conservative and is not an OS-level network sandbox: network state
must remain disconnected during assessment. The collector never makes HTTP or
DNS queries, probes destinations, or accesses UNC executables or Startup folders.
UNC and device namespaces are skipped for hashing and signatures, and redacted
in all returned metadata, including extended UNC syntax. Executable hashes use
the shared bounded, nonblocking, chunked hasher.

Startup inventory includes Run/RunOnce under HKLM and HKCU in both registry
views (the 32-bit view covers WOW6432Node), the current account and common
Startup folders, logon/boot-triggered scheduled tasks and automatic services.
The primary task query uses Get-ScheduledTask and emits no task actions,
arguments or principal/account fields. If unavailable, a read-only
`schtasks /query /fo csv /v` fallback supports English column names and reports
localized/unsupported CSV output as unavailable rather than misinterpreting it.
Other accounts' startup settings, StartupApproved overrides, shortcut targets
and arbitrary task schedules are outside this inventory. Folder symlinks,
junctions and link entries are skipped; ordinary `.lnk` filenames are listed
without opening or resolving the shortcut. Registry command values and service
command lines are discarded completely. Configuration does not prove execution;
folder enabled status is left unknown because StartupApproved is not inspected.

Administrator status comes from IsUserAnAdmin for the current token. For broader
visibility, manually launch the trusted Python environment with “Run as
administrator.” UAC elevation does not expose every protected process; vanished
processes cannot be recovered. The server never elevates itself, changes
registry values, starts/stops services or tasks, kills processes, or changes
PowerShell execution policy. Every permission limitation is summarized without
returning raw tool diagnostics or usernames.

### Windows verification status

Windows collector tests run in the existing `windows-latest` Python 3.11/3.12
CI matrix, including a `windows_integration` test that is skipped on other
platforms. Local validation on this Mac exercises mocked APIs and fixtures;
it is not a Windows integration result.

Verified on 2026-10-26 against candidate `a80cce7` on the retained
`validation/windows-milestone-4` branch:

| Environment | Actual result |
| --- | --- |
| Local fresh Python 3.13 venv on this Mac | 171 passed, 2 skipped; dependencies provisioned offline from the approved local venv |
| [windows-latest, Python 3.11](https://github.com/Abhisheksinha1506/MCP/actions/runs/40337240158/job/121621989459) | 170 passed, 3 skipped in 7.94 seconds |
| [windows-latest, Python 3.12](https://github.com/Abhisheksinha1506/MCP/actions/runs/40337240158/job/121621989279) | 170 passed, 3 skipped in 8.11 seconds |

Both Windows jobs ran the full suite, including the real Windows integration
test, with no continue-on-error exception. The initial candidate exposed an
AF_UNIX assumption in a Linux test fixture; that fixture is now portable.
The verified candidate and final milestone have identical collector and test
code; this verification record was added afterward.

[Candidate CI run](https://github.com/Abhisheksinha1506/MCP/actions/runs/40337240158):
Ubuntu Python 3.11/3.12 and macOS Python 3.12 also passed. macOS Python 3.11 was
still queued at the time of this record; no passing result is claimed for it.
The Docker integration job is **not green**: Debian passed, while Fedora and
Arch failed the Linux package-ownership assertion for their package-manager
executable. These failures are unresolved; no Linux collector code was changed
in this Windows milestone. The earlier all-NOT-RUN entry describes this Mac's
local Docker daemon limitation, not these subsequently executed remote tests.
Live results, including later runs on main, are available in
[GitHub Actions](https://github.com/Abhisheksinha1506/MCP/actions/workflows/ci.yml).

Counts-only Windows **fixture** summary: 1 process, 1 connection, 21 startup
items and 6 visibility notes. Those counts are mocked data, not the hosted
runner's machine inventory.

Shared fixes in milestone 4: home redaction handles case-insensitive Windows
paths, names with spaces and UNC locations; the shared hasher rejects network
and device paths before opening them. Existing non-native macOS unit tests
now mock their POSIX privilege API on Windows; a Linux connection fixture uses
a portable sentinel when AF_UNIX is absent; Unicode fixtures explicitly use
UTF-8; and old selection tests use a platform that remains unsupported. macOS and Linux collector source is unchanged.

## Rules and findings (milestone 5)

`analyze(snapshot, rules)` operates on the existing Snapshot metadata only.
It never collects additional data, opens executables, runs OS tools, resolves
DNS, connects to destinations, persists data or changes the computer. There are
no MCP tools or server code in this milestone. The plain demo explicitly takes
a snapshot first, then analyzes it:

```sh
python scripts/inspect_findings.py
```

Python callers can use:

```python
from dialtone_watcher.findings import analyze
from dialtone_watcher.rules import load_rules

report = analyze(snapshot, load_rules(), min_severity="info")
result = report.to_dict()
```

`result` contains findings, visible ignore suppressions, allowlist decisions,
`not_assessed` entries and an explicit warning that no matches do not establish
safety. Each finding includes type, redacted subject, severity, reason,
suggested_action, platforms, rule_id, confidence, evidence and caveats. Results
are ranked by severity, then stable type/subject/rule ordering. Suggestions are
reversible review steps using Activity Monitor, Task Manager or systemctl and
desktop startup settings; no deletion commands or automatic changes are made.

### File format and validation

The authoritative starter file is `data/rules.yaml`. Installed distributions
also include it under `share/dialtone-watcher/rules.yaml` in the Python prefix.
All five sections are required, even when empty: known_telemetry_domains,
known_bloatware, trusted_publishers, core_os_allowlist and ignore_list.
Every entry requires id, match, reason, confidence and platforms. Optional
fields are severity and source_note. Confidence is high/medium/low; severity
is info/low/medium; platforms is a nonempty list of macos/windows/linux or
`"all"`. IDs must be unique across sections; `builtin.` is reserved.

Within a match, predicates are ANDed. Separate entries express alternatives.
Supported targets and fields:

| Target | Fields | Operators |
| --- | --- | --- |
| process | name, publisher, path | exact, glob, regex |
| startup | name or label (both use the schema's name), path | exact, glob, regex |
| destination | domain | exact, suffix |
| finding (ignore_list only) | rule_id, subject | exact, glob, regex |

For example, a local user rule can suppress the documented combination check:

```yaml
- id: ignore.my-reviewed-combination
  match:
    target: finding
    rule_id: {exact: builtin.unsigned_combination}
  reason: I have reviewed this combination and prefer to hide these findings.
  confidence: high
  platforms: all
  source_note: User choice; review before applying because this suppression is broad.
```

Place this entry under ignore_list in a complete rules file. Suppressions remain
visible with the original rule ID, subject, ignore ID and plain-language reason.
Subject patterns match the displayed redacted subject; prefer an exact rule ID
or a narrowly scoped subject over a broad wildcard.

Unknown sections/fields, duplicate YAML keys, missing/empty reasons, duplicate
IDs, invalid platforms, invalid severity/confidence and invalid regexes reject
the whole file with a clear validation error. No partial loading or fetching of
includes is supported. Files are limited to 256 KB, sections to 1,000 entries,
patterns to 256 characters, and match inputs to 4,096 characters. Oversized
metadata is marked not assessed rather than silently treated as clean.

Patterns match whole normalized values. Globs use Python fnmatch semantics
(`*` can cross directory separators). Regexes are compiled once per case mode;
the supported safe subset has literals, anchors, character classes, escaped
punctuation and at most one quantified single atom (`*`, `+` or `?`). Groups,
alternation, backreferences, lookarounds and brace repetition are rejected.
Use globs or separate rules when the restricted regex language is insufficient.
Long-input tests guard matching cost. Linux paths retain case and literal
backslashes. Windows paths normalize separators, and Windows/macOS path and
name matching ignore case. Publisher matching ignores case on every OS.
Path rules operate on redacted paths: use `~/Downloads/*`, not a full account
home directory. Regex path rules use forward slashes for Windows.

Domains normalize case, trailing dots and IDNA. A suffix includes the apex and
proper subdomains, with a label boundary: `.example.com` cannot match
`notexample.com`. Domains come only from the snapshot's locally supplied
resolved_domain or a literal domain already in remote_host. IP addresses without
locally known names are not classified by domain rules; no DNS or IP reputation
lookup is performed.

### Classification policy and limits

Explicit known_bloatware matches produce junk findings; explicit telemetry
endpoint matches are described as **possible telemetry**. Default severities
are info for bloatware and low for telemetry, subject to confidence caps and
optional overrides. The starter telemetry entry explicitly uses info because
an endpoint alone cannot show whether data collection was requested.

Confidence always caps severity: low → info, medium → low, high → medium.
There is no severity above medium. Restricted claim words require an explicit
high-confidence rule reason; built-in explanations use unusual or possible
telemetry. `unknown` trust is neutral and never creates or raises a finding.
Unsigned alone creates no finding. The only generic combination inference is:

- Unsigned plus a temporary/downloads location, an enabled startup entry with
  the same executable path, or an observed network connection: unusual, low,
  medium confidence.
- Unsigned plus all three of those other signals: unusual, medium, high
  confidence in the observed combination (not a claim of unwanted intent).

Connections carry only process_name in the existing schema. Network activity
is used as a process signal only when that name identifies a single visible
process. Ambiguous instances are marked not assessed. Startup association uses
an exact normalized executable path, never a fuzzy label or a command line.
Trusted publisher rules are explanatory context only: they do not verify
identity, hide explicit matches or increase severity.

The core allowlist wins before classification. It requires a name AND an
expected path or publisher. A same-name file at a different **known** location
produces an unusual identity-review finding, rather than receiving core status.
Missing location metadata produces a not-assessed identity entry, not an
inference based on unknown trust. One genuine core process cannot hide a
same-name process elsewhere or its possible telemetry. Empty-path System and
kernel_task entries reflect limited kernel-context metadata; they are not proof
of file identity. Nonstandard Windows installation directories may need a
reviewed local allowlist adjustment.

Visibility notes are legacy strings, so source attribution is conservative.
Permission/coverage limitations, missing domains, unknown trust and oversized
fields become explicit assessment gaps. Affected findings receive caveats;
limitations in unrelated sources do not raise finding severity. No findings
must never be interpreted as a guarantee of safety or complete visibility.

### Starter provenance — every entry needs human review

This small starter set is reference data, not an endorsement or a guarantee.
Every row below is **needs human review**, and every YAML entry has that label
in source_note. No third-party app is pre-labelled as unwanted: known_bloatware
and ignore_list start empty. No Apple publisher CN is guessed when signature
metadata is unavailable. Sources were checked on 2026-10-26; source pages are
never fetched by the rules engine.

| Rule ID | What justifies it | Review status |
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

Clean-machine fixtures cover macOS, Linux and Windows, including legitimate
telemetry and unsigned development tools, and assert no findings above info.
Additional tests cover every matcher, validation errors, confidence caps,
look-alike names, allowlist precedence, visible suppressions, privacy, offline
analysis and partial visibility. Real-snapshot results and CI status are
recorded below after validation; earlier milestone results remain historical.

### Milestone 5 verification

On 2026-10-26 the final code candidate `29142a1` passed
[all seven CI jobs](https://github.com/Abhisheksinha1506/MCP/actions/runs/40357595177):
Ubuntu, macOS and Windows on Python 3.11/3.12, plus the separate Debian, Fedora
and Arch container integration job. No OS is allowed to fail. The final
milestone commit has the same implementation and tests; only this verification
record and the README introduction were updated after the candidate ran.

Fresh isolated Python 3.13 venv on this Mac: **282 passed, 2 skipped** in
5.42 seconds, without plugin flags. The local venv was provisioned offline
from the already approved installed dependencies. All 107 rules/findings tests
passed, including clean-machine and bounded-matching regressions.

The real macOS sample produced these counts:

| Type | Count | Severity | Count |
| --- | --- | --- | --- |
| junk | 0 | info | 0 |
| telemetry | 0 | low | 0 |
| unusual | 0 | medium | 0 |

There were 13 explicit assessment gaps, two allowlist decisions and no ignore
suppressions. No findings matched, so there are no top-five findings to list.
This is not a safety verdict: permissions, trust inspection and missing locally
known domains limited what could be assessed. Unknown trust was not converted
into a negative finding, and no live rule was invented to make the sample
produce a result. The local demo prints redacted subjects when findings exist.

One pre-existing CI blocker was fixed as part of satisfying the green-CI
requirement: Fedora and Arch located their package managers through /usr/sbin
aliases, while ownership tools reported canonical /usr/bin paths. Linux
ownership lookups now canonicalize local aliases, preserve the original
snapshot paths, and cache both identities. Regression tests cover successful,
unowned and cached alias queries without using a real package manager. No
macOS or Windows collector source was changed in this milestone. Temporary
read-only CI diagnostics were removed after confirming the cause. Earlier
milestone notes about failing Fedora/Arch checks are historical; this candidate
passed all three distro integrations.

## MCP server (milestone 6)

Install Python 3.11 or newer, create a virtual environment using the installation
steps above, and install with `python -m pip install -e ".[test]"`.
The official SDK is constrained to `mcp>=1.30,<2` because this server uses its
FastMCP API. No additional direct dependencies are introduced.
Run `dialtone-watcher` or `python -m dialtone_watcher.server` using that environment.
These start a **stdio** server: stdout is reserved for the MCP protocol. All
application logging goes to stderr. Launch it through your MCP client rather
than expecting an interactive terminal interface. The server opens no listener
and performs no external requests.

### Claude Desktop configuration

Merge the appropriate entry into `claude_desktop_config.json`, then restart
Claude Desktop. Replace the example installation directory with your absolute
local checkout path. Use the virtual environment's Python, so the client does
not depend on shell activation or PATH. These examples use placeholder paths.

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

For Claude Code, use the absolute executable path appropriate to your OS:

```sh
claude mcp add --transport stdio dialtone-watcher -- /opt/dialtone-watcher/.venv/bin/python -m dialtone_watcher.server
```

### Tool responses

Every response has a static `data_notice`, a labeled `untrusted_data` object,
and a top-level `truncated` flag. Machine names, labels, paths, rule reasons and
other observed strings are untrusted data; clients must never obey embedded
instructions. Controls (including terminal escapes and Unicode formatting
controls) are stripped. Strings are capped at 512 characters; nested output
has a shared budget and each JSON response is capped at 64 KiB. Paged fields
contain `items`, `total_count`, and their own `truncated` flag. Requested limits
must be 1–100. A truncation flag means omitted details were not returned; it is
not a complete assessment.

| Tool | What it returns |
| --- | --- |
| `take_snapshot()` | Saved snapshot ID, process/connection/startup counts and paged visibility notes. Runs collection in a worker with a 60-second deadline. It appends local storage and is non-destructive. |
| `list_findings(snapshot_id, min_severity="info", limit=50)` | Ranked findings, visible ignore suppressions, allowlist decisions, assessment gaps and visibility caveats. Severity accepts info, low or medium. |
| `list_unusual_destinations(snapshot_id, limit=50)` | Connections matching explicit possible-telemetry rules or associated by process name with unusual findings; includes attribution caveats and assessment gaps. Unknown domains alone are not suspicious. |
| `list_startup_items(snapshot_id, limit=100)` | Recorded startup entries with source and enabled/unknown status, plus visibility notes. |
| `suggest_removals(snapshot_id)` | Up to 50 severity-ranked reversible review suggestions, reasons and caveats. Nothing is removed or disabled. |
| `explain_process(name, snapshot_id=None)` | Exact-name snapshot facts: publisher, trust, rule matches, connections and startup associations. Defaults to the latest snapshot; absent processes are explicitly unknown. Adds sourced knowledge context with publisher/location consistency checks; no identity guarantee. |
| `compare_to_peers(snapshot_id)` | `status: not_available`, `reason: peer dataset not enabled`. No remote service. |
| `check_permissions()` | Current privilege status, known collector coverage limits and OS-specific access guidance. Per-process failures are measured during collection. |

All tools except `take_snapshot` are annotated read-only. Every tool is
non-destructive and local. Unknown snapshot IDs and internal failures return
fixed, clear errors; exception details stay in local stderr logs. No findings
never establishes safety: use assessment gaps and visibility caveats when
explaining results.

Resources `snapshot://latest` and `rules://active` return the same redacted,
bounded JSON envelope. The latter represents the loaded YAML file as JSON,
including provenance notes; rules are validated once at server creation.
Restart the server after editing rules. The snapshot resource includes total
counts so clients can detect omitted records.

### Local storage and timeouts

Only `take_snapshot` appends a redacted snapshot. Default database locations:

- macOS: `~/Library/Application Support/dialtone-watcher/snapshots.sqlite3`
- Windows: `%LOCALAPPDATA%\dialtone-watcher\snapshots.sqlite3`
- Linux: `$XDG_DATA_HOME/dialtone-watcher/snapshots.sqlite3`, falling back to
  `~/.local/share/dialtone-watcher/snapshots.sqlite3`.

Set `DIALTONE_WATCHER_DB` in the MCP client's server environment to override the
path. Keep this database in a private local directory. The server creates the
directory/table as needed; there is no update, replace or delete operation.
A timed-out collection is never saved. Python cannot forcibly stop a worker
thread: it may finish its existing read operations after the deadline, and a
second collection is refused until it finishes. Other tools remain available.
Stopping the server can wait for that worker to finish.

### Troubleshooting

- **Server not appearing:** confirm the configured absolute Python executable
  exists and that this environment can import `dialtone_watcher.server`.
  Check client stderr logs, JSON quoting (especially Windows backslashes), and
  restart the client after configuration changes. No banner appears on stdout.
- **Permission prompts or incomplete visibility:** consult the per-OS guides
  above and `check_permissions`. The server does not elevate itself or grant
  permissions. Only grant access to a trusted installation; elevation cannot
  bypass every OS protection. Keep stderr logs local, as diagnostics can contain
  private paths.
- **Empty network results:** ordinary accounts can be denied per-process
  connection access. Inspect snapshot visibility notes and assessment gaps;
  empty results are not proof of no activity. Manually launch in an appropriately
  privileged trusted environment only if broader visibility is needed.
- **Timeout:** retry after the existing worker finishes. No partial or late
  snapshot is saved on timeout. Existing saved snapshots remain available.

### Milestone 6 local verification

A fresh Python 3.13 virtual environment on this Mac passed **289 tests, with
2 platform skips**, without plugin flags. This includes the previously added
synthetic demo test still present locally; the six MCP test cases are part of
this milestone. Tests use the official SDK's in-process client and a real stdio
subprocess. They exercise every tool/resource, annotations, privacy for all
three OS path formats, untrusted instruction-like names, output budgets,
limits, unknown IDs, internal error handling, timeout recovery and stdout
cleanliness. Network connection attempts are forbidden during the mocked
all-tools test.

A real client launched the installed `dialtone-watcher` console entry point
and called `take_snapshot` followed by `list_findings` on this Mac. Counts:
555 processes, 47 connections, 11 startup items, 11 visibility notes,
0 findings, and 13 assessment gaps. Both resources were read successfully.
No findings is not a safety verdict. Collection required host process visibility;
the desktop execution sandbox hides all processes and cannot satisfy the
existing real-macOS integration test.

## Sourced process context (milestone 7)

The knowledge table is **needs human review before relying on it**. Its 41
entries describe documented purposes across macOS, Windows and Linux, using
vendor/upstream documentation, OS manuals and Microsoft Press OS internals
documentation. All starter entries have high confidence in the documented
purpose, not in the identity or behavior of any observed executable. Sources
were checked during development on 2026-10-27. No pages or descriptions are
fetched at runtime. macOS mds/mdworker entries cite Apple-supplied installed
manuals, which can be reviewed with `man mds` and `man mdworker`.

`data/knowledge.yaml` is installed with the package. Each entry requires id,
names, platforms, description, publisher (nullable), category,
usually_safe_to_ignore, confidence, source_note and an ISO last_reviewed date.
Optional expected_locations are whole-path glob patterns using the shared
path normalization. A null publisher means no exact signer-CN expectation is
asserted; the vendor brand alone is insufficient to guess a signing identity.
Unknown fields, missing fields, duplicate IDs, ambiguous same-platform names,
invalid dates/categories and restricted description wording are rejected.
Security-tool descriptions may use the restricted security vocabulary; no
description may give a safe verdict.

`explain_process` preserves its previous snapshot and rule facts and adds:

- `observed`: process publisher, trust signal, path and other recorded process
  metadata, connections, startup items and startup status. `not_observed` startup
  status does not mean disabled; visibility may be limited.
- `rule_matches`: local rules matched by the process and its associated metadata.
- `known_info`: sourced context and review date, or null when no entry matches.
- `consistency`: `matches`, `mismatch`, or `not_checkable`, with per-instance
  `consistency_details`. A conflict wins across instances. Missing expected
  evidence makes the comparison incomplete; unknown trust remains neutral.
- `caveats`: human-review guidance, attribution limits, visibility notes and
  assessment gaps. Lower-confidence entries explicitly say they are below high.

A location or publisher mismatch withholds the generic description and resets
usual-ignore guidance to `depends`; it never turns a name match into an identity
claim. Consistency compares recorded strings, not certificate authenticity.
Matching locations can still contain substituted executables. Entries without
a documented location or signer expectation are explicitly not checkable.
Knowledge matches can describe a name absent from a snapshot, but no observed
identity is inferred. A process with neither knowledge nor rule matches returns
`no information available`, its observed facts, and a suggestion to consult the
vendor or check its signature/package ownership.

Names match exactly, with case ignored on macOS/Windows and preserved on Linux.
Appending an instruction to a familiar name never creates a fuzzy match. Machine
text and table text remain inside the existing untrusted-data envelope and pass
through the existing redaction, control stripping and output budget. Detailed
collections in this enriched response return up to five items (ten caveats),
with total counts/truncation flags; mismatches are prioritized in consistency
details. Legacy fact fields remain for existing clients. No findings, severity,
collector, peer-comparison or other tool behavior changes. Knowledge loads
locally when explain_process is called, so a table edit is validated on the next
call without changing the active rules resource.

### Entry source manifest

Every row is **needs human review before relying on it**. The source_note in
each YAML entry records the same provenance and any local location verification.

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

### Milestone 7 local verification

On 2026-10-27 a fresh Python 3.13 environment on this Mac passed **332 tests,
with 2 platform skips**, without plugin flags. This local count includes the
previously added synthetic demo test, which remains outside this milestone.
The knowledge/server tests also preserve the milestone 6 stdout, redaction,
injection and response-budget checks. No findings or severity logic changed.

A real SDK stdio client collected a macOS snapshot and printed five redacted
explain_process responses: launchd and Finder matched their expected locations;
a synthetic launchd at ~/Downloads/launchd produced a mismatch with its generic
description withheld; observed logd and smd returned no information available
with their recorded facts. The synthetic example added only a record in a
temporary append-only database; no executable or startup item was created.
Signature and process visibility limitations remained visible in the responses.
The full five-response JSON report was kept locally and was not committed.
