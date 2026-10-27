# Changelog

## 0.1.0 — Unreleased

Initial offline, advice-only inspection implementation, prepared for release;
no PyPI publication or release tag is implied by this entry.

- macOS, Windows and Linux collectors for process, connection and startup
  metadata, with partial-visibility notes and bounded executable inspection.
- Shared schema, home/account redaction, hostname hashing and append-only local
  SQLite snapshots.
- Rule-based junk, possible telemetry and unusual findings, confidence caps,
  core identity allowlists, visible suppressions and assessment gaps.
- Eight local stdio MCP tools and latest-snapshot/active-rules resources, with
  bounded responses, control stripping, untrusted-data labels and collection
  timeouts.
- Sourced process context with expected-location/publisher comparisons,
  description withholding for conflicts and explicit unknown responses.
- Installation/client/privacy/permissions documentation, MIT license, threat
  model, schema/tool documentation checks and wheel/sdist installation checks.

Peer comparison remains unavailable. Inspection does not change system settings
or remove software. Findings and knowledge entries are heuristics requiring
human review; they are not detection or identity guarantees.
