# Contributing to Vigil

Thank you for contributing to Vigil! This project provides an autonomous, verifiable AI SOC platform built around append-only ledger guarantees, multi-agent collaboration, and closed-loop validation.

## 1. Core Development Principles

1. **File Size Limit**: All files must remain strictly under 500 lines of code. Split complex modules into focused submodules.
2. **Immutable Audit Trail**: Never delete, update, or truncate records in `agent_events`. The Ledger is append-only and cryptographically hashed with SHA-256.
3. **Agent & Integration Terminology**: Vigil utilizes specialized and custom agents, and modular integrations. Do not hardcode static agent counts (e.g. avoid "12 agents" or "13 agents") or integration totals in documentation or code.
4. **Strict Schema Contracts**: All workflows, skills, policies, and ledger events must adhere to JSON schemas located in `data/schemas/`.
5. **Deterministic Testing**: Write unit and integration tests with deterministic fixtures. All new features must include regression tests.

---

## 2. Environment Setup

### Prerequisites
- Python 3.12+
- Docker & Docker Compose
- Node.js 20+ (for `clients/web`)

### Setup Local Environment
```bash
git clone https://github.com/johnvanlowe/vigil.git
cd vigil
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

### Running Tests
Execute test suites with pytest:
```bash
venv/bin/pytest -o addopts="" tests/
```

Targeted test execution:
```bash
venv/bin/pytest -o addopts="" tests/evals/test_dryrun.py
venv/bin/pytest -o addopts="" tests/ledger/
venv/bin/pytest -o addopts="" tests/findings/
```

---

## 3. Database Migrations

Vigil manages database schema evolution via Alembic:
```bash
# Check current migration revision
venv/bin/alembic current

# Apply pending migrations
venv/bin/alembic upgrade head

# Generate a new migration
venv/bin/alembic revision -m "description_of_change"
```

Migration scripts live in `infra/migrations/versions/`.

---

## 4. Workflows and Skills

New playbooks and skills must include valid frontmatter:
- Workflows: Defined in `WORKFLOW.md` files conforming to `data/schemas/workflow_v1.json`.
- Skills: Defined in `SKILL.md` files conforming to `data/schemas/skill_v1.json`.

Validate frontmatter locally:
```bash
python -m core.workflows.validate
python -m core.skills.validate
```

---

## 5. Submitting Pull Requests

1. Create a feature branch off `main`: `git checkout -b feat/your-feature-name`.
2. Ensure all tests pass: `pytest -o addopts="" tests/`.
3. Check for OpenAPI snapshot regressions: `pytest -o addopts="" tests/api/test_openapi_snapshot.py`.
4. Submit PR with clear motivation, design rationale, and test verification evidence.
