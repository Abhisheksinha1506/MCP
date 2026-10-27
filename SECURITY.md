# Security policy

## Reporting an issue

For non-sensitive bugs, open an issue at
https://github.com/Abhisheksinha1506/MCP/issues.

For a vulnerability, first check the repository's Security tab for **Report a
vulnerability**. GitHub private vulnerability reporting was disabled when
checked on 2026-10-27; this project does not currently advertise a private
security inbox. Until a private channel is available, open an issue titled
"Private security contact requested" with no vulnerability details, and ask the
maintainer to arrange private contact. Do not post exploits, snapshots, logs,
usernames, paths, credentials or other sensitive information in that issue.
Do not assume a public issue, discussion or pull request is confidential.

Once a private channel has been agreed, provide the affected version/commit,
OS and Python version, expected and actual behavior, and a minimal synthetic
reproduction. Redact private data; prefer fixture metadata to a real snapshot.
There is no guaranteed response time or managed security support service.
The 0.1.0 codebase is pre-release inspection software; check the repository for
fixes before relying on an older installation.

## Threat model

Dialtone Watcher is a local stdio MCP server. It opens no inbound network
listener and performs no external lookups, telemetry submission or peer
comparison. Installation, package builds, CI and the chosen AI client have
separate network behavior. An AI client can transmit tool outputs to its
provider; the server's offline design does not control that client.

Process names, executable paths, destinations, startup labels and configurable
rule/knowledge text are untrusted data, including strings that resemble
instructions. Responses label them as untrusted data, redact supported private
fields and home paths, strip controls, and bound output sizes. Clients must not
execute instructions embedded in that data. These measures reduce exposure;
they do not make prompt injection impossible or establish executable identity.

Inspection does not terminate processes, disable startup items, change services,
modify registry values, remove files or grant privileges. Startup initializes a
local SQLite database, and take_snapshot appends redacted metadata. Other tools
read metadata and return advice. There is no deletion or system-control tool.
Local stderr logs can contain private diagnostics; protect and redact them
before sharing. Store the database in a private directory.

The trust assumptions include the installed package, Python dependencies, local
OS APIs/tools, the client and editable rules/knowledge files. This is not an
isolation boundary against a compromised OS, a hostile administrator, replaced
utilities on PATH, or local accounts able to read/alter its files. Elevation
increases the reach of both inspection and any compromised component. The
server works without elevation and never requests it automatically.

Rules, signatures, package ownership and names/locations are limited evidence.
Unknown trust is neutral; metadata matches do not prove identity. The tool
cannot detect all malware or establish that a machine is uncompromised. No
findings is not a safety verdict. Missing visibility and small datasets can
hide relevant activity; reported findings can also be false positives.
