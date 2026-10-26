# Dialtone Watcher

An offline, advice-only local MCP server under development. Milestones 1–3 provide
the metadata schema, redaction, SQLite storage, and macOS and Linux collectors.
MCP tools, rules and findings are planned. Windows collection is not implemented.

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
`sys.platform == "darwin"` for macOS and `sys.platform.startswith("linux")`
for Linux; other platforms currently raise `NotImplementedError`.

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
