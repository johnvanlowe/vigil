"""Tests for suppression candidate view and suppression policy promotion."""

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.findings.verdicts import VerdictAction, record_verdict
from core.policies.models import PolicyModel
from core.policies.schema import Policy, PolicyKind
from core.policies.service import PolicyService
from core.policies.suppression import is_suppressed, promote_to_suppression_policy


def test_suppression_evaluation_and_metric():
    """Verify is_suppressed matches active suppression policies."""
    engine = create_engine("sqlite:///:memory:")
    PolicyModel.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    svc = PolicyService(session_factory=SessionLocal)

    policy = Policy(
        kind=PolicyKind.SUPPRESSION,
        scope="*vulnerability-scanner*",
        params={"reason": "Internal authorized vulnerability scan"},
        ttl=3600,
        promoted_by="sec_admin",
    )
    svc.set_policy(policy, actor="sec_admin", reason="Authorized scanner")

    # Finding matching the pattern
    matching_finding = {
        "finding_id": "f-1",
        "description": "Port scan from internal vulnerability-scanner host",
        "source": "suricata",
    }
    suppressed, matched_id = is_suppressed(matching_finding, service=svc)
    assert suppressed is True
    assert matched_id == policy.id

    # Non-matching finding
    benign_finding = {
        "finding_id": "f-2",
        "description": "Unusual SSH login from unknown host",
        "source": "auth",
    }
    suppressed2, _ = is_suppressed(benign_finding, service=svc)
    assert suppressed2 is False


def test_suppression_candidates_view_three_dismissals():
    """Simulate SQLite view of 3 consistent dismissals yielding one suppression candidate."""
    engine = create_engine("sqlite:///:memory:")
    with engine.connect() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE agent_events (
                    run_id TEXT,
                    seq INTEGER,
                    kind TEXT,
                    payload TEXT,
                    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE VIEW suppression_candidates AS
                SELECT
                    json_extract(payload, '$.reason') AS match_reason,
                    count(*) AS dismissal_count,
                    max(ts) AS last_dismissed_at,
                    json_extract(payload, '$.finding_id') AS sample_finding_id
                FROM agent_events
                WHERE kind = 'verdict'
                  AND json_extract(payload, '$.action') = 'dismiss'
                  AND json_extract(payload, '$.reason') IS NOT NULL
                GROUP BY json_extract(payload, '$.reason')
                HAVING count(*) >= 3;
                """
            )
        )
        # Insert 3 dismissals with reason "Scanner False Positive"
        for i in range(3):
            conn.execute(
                text(
                    "INSERT INTO agent_events (run_id, seq, kind, payload) VALUES (:r, :s, 'verdict', :p)"
                ),
                {
                    "r": f"run-{i}",
                    "s": 0,
                    "p": '{"action": "dismiss", "reason": "Scanner False Positive", "finding_id": "find-' + str(i) + '"}',
                },
            )
        # Insert 1 dismissal with different reason
        conn.execute(
            text(
                "INSERT INTO agent_events (run_id, seq, kind, payload) VALUES ('run-x', 0, 'verdict', :p)"
            ),
            {"p": '{"action": "dismiss", "reason": "One-off admin test", "finding_id": "find-x"}'},
        )
        conn.commit()

        rows = conn.execute(text("SELECT match_reason, dismissal_count FROM suppression_candidates;")).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "Scanner False Positive"
        assert rows[0][1] == 3
