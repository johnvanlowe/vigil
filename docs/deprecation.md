# Vigil API & Interface Deprecation Policy

**Version:** 1.0.0  
**Effective Date:** September 5, 2026

## 1. Principles & Commitment

Vigil follows Semantic Versioning (SemVer 2.0.0). As a mission-critical platform operating in enterprise security environments, contract stability is paramount.

- **Warning Period**: Any interface marked for deprecation must emit explicit deprecation warnings across at least **one full minor release cycle** prior to removal.
- **Breaking Removals**: Deprecated capabilities, schemas, endpoints, and metrics are removed **only in major version boundaries** (e.g., from 1.x to 2.0).

---

## 2. Scope of Protected Contracts

This deprecation policy applies strictly to the following seven public surfaces:

1. **Ledger Event Schemas (`data/schemas/ledger/v*`)**  
   - Every event kind carries `schema_version`.
   - Backward-incompatible payload modifications require a version bump (e.g. `v1` to `v2`).
   - Old schemas remain supported for reading historical chains indefinitely.

2. **Playbook Frontmatter (`WORKFLOW.md`)**  
   - Frontmatter keys defined in `data/schemas/workflow_v1.json` are guaranteed.
   - Unknown or retired fields emit `UserWarning` in 1.x and are rejected in 2.0.

3. **Skill Manifests (`SKILL.md`)**  
   - Frontmatter schemas defined in `data/schemas/skill_v1.json` follow the same deprecation lifecycle.

4. **Integration Descriptors (`core/integrations/*/descriptor.py`)**  
   - Descriptor registration fields, required secrets, and configuration interfaces.

5. **REST API (`/api/v1` and `/api/*`)**  
   - Endpoint removals or breaking schema shifts require snapshot update, CHANGELOG entry, and `Deprecated: true` OpenAPI annotation for one minor release before removal.

6. **MCP Tool Names and Parameter Schemas**  
   - Server tool names and parameter models exposed over MCP protocol.

7. **Prometheus Metric Names (`docs/metrics.md`)**  
   - Metric series names, unit conventions, and mandatory label sets.

---

## 3. Deprecation Process

1. **Announcement**: The capability is marked deprecated in code, documentation, and the [CHANGELOG.md](../CHANGELOG.md).
2. **Telemetry & Logs**: The server or CLI emits a clear log message or HTTP `Deprecation` header citing the target removal version and replacement alternative.
3. **Grace Period**: The deprecated feature remains functional for at least one minor release.
4. **Sunset**: In the next major release (e.g. Vigil 2.0.0), the deprecated interface is cleanly removed.
