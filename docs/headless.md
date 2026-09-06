# Headless & MCP Server Operations

Vigil can operate entirely headless in automation-heavy or air-gapped environments without the frontend GUI. Headless mode utilizes the background daemon service, the REST/FastAPI server, and the Model Context Protocol (MCP) server.

## 1. Background Daemon Service

The Vigil Daemon (`services/daemon`) executes periodic background evaluations, SLA breach monitoring, spend budget tracking, and suppression expiration sweeps.

### Running the Daemon
In containerized environments:
```bash
docker run -d --name vigil-daemon \
  -e DATABASE_URL="postgresql://deeptempo:deeptempo_secure_password_change_me@postgres:5432/deeptempo_soc" \
  -e REDIS_URL="redis://redis:6379/0" \
  ghcr.io/vigil-soc/vigil-daemon:1.0.0
```

Locally via CLI:
```bash
python -m services.daemon.main
```

### Daemon Tasks
- **Spend Budget Enforcement**: Enforces `Policy(kind=budget)` max daily/monthly USD and token limits.
- **Suppression Expiry**: Automatically deactivates expired suppression rules defined under `Policy(kind=suppression)`.
- **SLA Breach Monitoring**: Checks findings against `Policy(kind=sla)` MTTA/MTTR targets and emits `vigil_sla_breach_total` metric events.

---

## 2. Model Context Protocol (MCP) Server

Vigil exposes its security tooling and investigation capabilities via the Model Context Protocol (MCP). External AI agents (e.g., Claude Desktop, Cursor, Goose, custom external orchestrators) can connect to Vigil as an MCP client.

### Configuration
Expose the MCP endpoint:
```json
{
  "mcpServers": {
    "vigil": {
      "command": "python",
      "args": ["-m", "services.mcp.server"],
      "env": {
        "VIGIL_API_KEY": "vkey_analyst_example_token",
        "VIGIL_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

### Supported MCP Tools
- `vigil_get_finding`: Retrieve complete finding details, citations, and evidence traces.
- `vigil_evaluate_hypothesis`: Run cross-source correlation against SIEM/EDR logs.
- `vigil_validate_detection`: Lint and replay detection candidate logic.
- `vigil_execute_action`: Trigger response actions (bound by caller role and autonomy tier).

---

## 3. Role-Scoped API Keys

Every headless consumer—whether a script, CI pipeline, or MCP client—must authenticate using an API key bound to a specific role:

| Role | Permissions | MCP Tool Execution |
| :--- | :--- | :--- |
| `viewer` | Read-only inspection of findings, scorecards, and reports. | Cannot call any action tools (`vigil_execute_action` rejected). |
| `analyst` | Triage, investigation, verdict submission, draft actions. | Can execute reversible and simulation actions; cannot alter or loosen security policies. |
| `admin` | Full platform control, user provisioning, policy overrides. | Unrestricted tool execution subject to ledger audit logging. |

### Provisioning an API Key
Generate an API key bound to a specific role using the CLI:
```bash
vigil auth create-key --name "ci-pipeline-key" --role analyst
```

The resulting key is cryptographically hashed with SHA-256 before insertion into the database. MCP tool calls authenticate using the bearer token header, enforcing role separation at the routing layer.
