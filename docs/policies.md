# Policy Engine & Autonomy Controls

Vigil enforces strict operational governance through declarative, versioned policies. All policy definitions are validated against strongly-typed schemas (`core/policies/schema.py`) and stored in the database. Any modification to a policy emits an auditable `policy_change` event to the append-only Ledger.

## 1. Policy Kinds

Vigil supports five fundamental policy kinds:

| Kind | Description | Enforcement Mechanism |
| :--- | :--- | :--- |
| `autonomy` | Governs automated execution permissions across investigation and response. | `core/response/action.py` |
| `budget` | Enforces spending caps (USD) and token ceilings over daily/monthly intervals. | `services/daemon/budget.py` |
| `suppression` | Filters false positives or expected benign noise with mandatory rationale. | `core/policies/suppression.py` |
| `offensive` | Authorizes attack simulation and red team planner executions in defined target environments. | `core/integrations/offensive/contract.py` |
| `sla` | Defines MTTA, MTTR, and disposition duration objectives per severity level. | `core/policies/sla.py` |

---

## 2. Autonomy Postures

Autonomy tiers dictate whether actions are executed automatically or held for human authorization:

- **Tier 0 (Observer)**: Read-only triage and hypothesis generation. All actions require operator confirmation.
- **Tier 1 (Assisted)**: Reversible actions (e.g., ticket creation, notification, temporary quarantine) may execute automatically in staging/dev. Production environments gate on analyst confirmation.
- **Tier 2 (Autonomous Defender)**: Reversible actions execute automatically across all authorized scopes. Irreversible actions (e.g., host isolation, firewall blocklist, credential revocation) require explicit sign-off.
- **Tier 3 (Full Autonomy)**: Pre-approved response playbooks execute immediately within strict rate and budget envelopes.

---

## 3. Budget Envelopes (`Policy(kind=budget)`)

Prevent runaway AI token consumption and cloud spend:
```json
{
  "kind": "budget",
  "name": "production-frontier-cap",
  "params": {
    "max_daily_usd": 150.0,
    "max_monthly_usd": 3000.0,
    "max_tokens_per_call": 128000,
    "halt_on_exhaustion": true
  }
}
```

When spending exceeds the configured threshold, the background daemon flips the circuit breaker, emits `vigil_budget_exhausted_total`, and halts autonomous runs until authorized by an administrator.

---

## 4. Suppression Rules (`Policy(kind=suppression)`)

Noise reduction rules require a justification, expiration date, and match conditions:
```json
{
  "kind": "suppression",
  "name": "scheduled-backup-noise",
  "params": {
    "target_field": "command_line",
    "match_pattern": ".*rsync.*backup_service.*",
    "expires_at": "2026-12-31T23:59:59Z",
    "rationale": "Weekly scheduled database snapshot script"
  }
}
```
Suppression rules are visible in the `suppression_view` database view and are automatically audited.

---

## 5. Offensive Engine Policies (`Policy(kind=offensive)`)

Controls red team planning, ARTEMIS simulation integration, and authorized target environments:
- Enforces environment boundaries (e.g., only `temporange` or `staging`).
- Restricts toolsets to non-destructive adversary emulation.
- Requires operator gate approval for production attack generation.

---

## 6. Service Level Agreements (`Policy(kind=sla)`)

Configures response time thresholds and baseline human analyst minutes per stage:
```json
{
  "kind": "sla",
  "name": "soc-gold-sla",
  "params": {
    "targets": {
      "critical": {"mtta": 300, "mttr": 1800, "disposition": 900},
      "high": {"mtta": 900, "mttr": 7200, "disposition": 3600}
    },
    "baseline_minutes": {
      "triage": 15.0,
      "investigation": 45.0,
      "reconstruction": 60.0
    }
  }
}
```
If a finding exceeds the target MTTA or MTTR, the daemon increments `vigil_sla_breach_total`.
Modifying an SLA target emits an auditable event with `direction="loosen"` or `direction="tighten"`.

---

## 7. Ledger Audit Invariants

Every change to any policy requires an authenticated actor (`admin` or `policy`). 
The policy service records a `policy_change` event into the append-only Ledger containing:
- `policy_id` and `kind`
- `actor` (username or service identity)
- `direction` (`tighten` or `loosen`)
- Cryptographic hash chain link to previous ledger state
