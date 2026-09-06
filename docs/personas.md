# Persona-to-Workflow Map

Vigil serves diverse stakeholders across security engineering, operations, threat management, and executive leadership. This document maps operational personas to their primary workflows, CLI commands, and UI views.

| Persona | Core Objectives | Primary Workflows & Commands | Key UI & Grafana Views |
| :--- | :--- | :--- | :--- |
| **Evaluator** | Rapid proof of value, benchmark comparison against SOCBench, local verification. | `vigil dryrun --scenario redrun_v1`<br>`./start.sh --dryrun` | Scorecard View (`/scorecard`), Artifact Inspector |
| **SOC Tier 1 (Triage)** | High-throughput alert triage, noise suppression, false positive elimination. | `vigil_evaluate_hypothesis` via MCP<br>`workflows/triage/WORKFLOW.md` | Active Triage Queue, Alert Details & Citations (`/findings/:id`) |
| **SOC Tier 2 (Investigator)** | Root cause analysis, multi-stage attack reconstruction, timeline synthesis. | `skills/reconstruction/SKILL.md`<br>`workflows/incident-response/WORKFLOW.md` | Investigation Canvas, Evidence Graph, Citation Inspector |
| **SOC Tier 3 (Escalation / Hunting)** | Deep hunting, hypothesis formulation, custom detection authoring and testing. | `skills/author_detection/SKILL.md`<br>`skills/validate_detection/SKILL.md`<br>`vigil loop run` | Detection Lab, Coverage Heatmap, Rule Replay Runner |
| **Threat Intelligence / Red Team** | Adversary emulation, attack planning against test targets, gap analysis. | `core/agents/red_planner/planner.py`<br>`core/integrations/artemis/adapter.py`<br>`workflows/closed-loop/WORKFLOW.md` | Attack Simulation Workspace, MITRE ATT&CK Matrix View |
| **SRE / Platform Engineer** | System health, worker scaling, API latency, Prometheus alerts, migration sanity. | `alembic upgrade head`<br>`core/cli/auth.py` | AI SOC Health Dashboard (`infra/grafana/ai-soc-health.json`), `/metrics` |
| **CISO** | Security posture, autonomous work share, MTTA/MTTD/MTTR, audit defensibility. | `vigil attest --quarter 2026Q4`<br>`vigil ledger verify` | CISO Executive Dashboard (`infra/grafana/ciso-view.json`), Attestation Reports |
| **SOC Leader / Director** | Team capacity, analyst burnout reduction, hours returned, rule effectiveness. | `vigil verdicts export`<br>`vigil policies list` | Operational Performance Dashboard, Suppression Review Panel |
| **CFO / FinOps** | LLM spend management, budget ceiling enforcement, cost-per-outcome attribution. | `vigil policies apply --file budget.json`<br>`services/daemon/budget.py` | Spend & Budget Monitor, Cost-per-Investigation Ledger Fold |

---

## Persona Workflow Details

### 1. Evaluator
Evaluators can validate Vigil in under 15 minutes without connecting external SIEM pipelines by executing `vigil dryrun`. The command replays the recorded fixture, verifies automated triage and containment, and renders an auditable scorecard artifact comparing Vigil to SOCBench.

### 2. SOC Analysts (Tiers 1-3)
Analysts interact with findings where every assertion is backed by verifiable citations. If an agent proposes a detection or response, analysts review the candidate via `skills/validate_detection`, preview simulated results, and confirm or overturn verdicts.

### 3. Red Team & Threat Hunters
Threat teams use the Red Planner and closed-loop engine (`workflows/closed-loop/WORKFLOW.md`) to run controlled adversary emulation against staging environments (such as TempoRange), generating synthetic telemetry to uncover blind spots and automatically draft new detection candidates.

### 4. CISO & SOC Leadership
Executives utilize the tamper-evident Ledger and CISO dashboard to verify that security improvements are mathematically proven. The `vigil attest` tool generates quarterly attestations with SHA-256 hash chains, providing immutable proof of defense operations for regulators and boards.
