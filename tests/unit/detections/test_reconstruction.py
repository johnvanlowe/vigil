"""Unit tests for the detection reconstruction phase and LogLM first-class signal."""

import pytest

from core.detections.reconstruction import (
    DetectionVerdictEnum,
    ReconstructionService,
)
from core.integrations.offensive_engine import ActionStatus, AttackTraceStep
from core.time import utcnow


@pytest.mark.unit
def test_reconstruction_classification_rule_and_loglm():
    """Verify correct classification of detected_by_rule, detected_by_loglm, both, and missed."""
    service = ReconstructionService(run_id="run-recon-test")

    now = utcnow()
    action_trace = [
        AttackTraceStep(
            step_id="s1",
            technique_id="T1059.001",
            name="PowerShell probe",
            status=ActionStatus.SUCCESS,
            executed_action="powershell.exe -enc ...",
            timestamp=now,
        ),
        AttackTraceStep(
            step_id="s2",
            technique_id="T1003",
            name="Credential Dump",
            status=ActionStatus.SUCCESS,
            executed_action="procdump.exe lsass.dmp",
            timestamp=now,
        ),
        AttackTraceStep(
            step_id="s3",
            technique_id="T1021.001",
            name="RDP Lateral Movement",
            status=ActionStatus.SUCCESS,
            executed_action="mstsc.exe",
            timestamp=now,
        ),
        AttackTraceStep(
            step_id="s4",
            technique_id="T1071.001",
            name="C2 Web Beaconing",
            status=ActionStatus.SUCCESS,
            executed_action="curl https://unknown-c2.net",
            timestamp=now,
        ),
    ]

    telemetry = [
        # s1 detected by rule ONLY
        {
            "event_id": "e1",
            "step_id": "s1",
            "technique_id": "T1059.001",
            "source": "sysmon",
            "rule_id": "sigma_powershell_obfuscation",
            "details": {"process_name": "powershell.exe"},
        },
        # s2 detected by LogLM ONLY (novel/unseen behavior)
        {
            "event_id": "e2",
            "step_id": "s2",
            "technique_id": "T1003",
            "source": "loglm",
            "schema_kind": "loglm",
            "details": {"process_name": "procdump.exe", "command_line": "procdump.exe lsass.dmp"},
        },
        # s3 detected by BOTH rule and LogLM
        {
            "event_id": "e3-rule",
            "step_id": "s3",
            "technique_id": "T1021.001",
            "source": "suricata",
            "rule_id": "suricata_rdp_connection",
            "details": {"dest_port": 3389},
        },
        {
            "event_id": "e3-loglm",
            "step_id": "s3",
            "technique_id": "T1021.001",
            "source": "loglm",
            "details": {"action": "rdp_tunnel"},
        },
        # s4 has NO telemetry / matches -> MISSED
    ]

    report = service.reconstruct(
        action_trace=action_trace,
        telemetry_findings=telemetry,
        environment_id="staging-range",
        plan_id="plan-1",
    )

    assert report.total_steps == 4
    assert report.detected_by_rule_count == 1
    assert report.detected_by_loglm_count == 1
    assert report.both_count == 1
    assert report.missed_count == 1

    verdicts = {s.step_id: s.verdict for s in report.step_verdicts}
    assert verdicts["s1"] == DetectionVerdictEnum.DETECTED_BY_RULE
    assert verdicts["s2"] == DetectionVerdictEnum.DETECTED_BY_LOGLM
    assert verdicts["s3"] == DetectionVerdictEnum.BOTH
    assert verdicts["s4"] == DetectionVerdictEnum.MISSED

    # Gaps reported: s2 is model_only gap (authoring opportunity), s4 is complete_miss
    gap_types = {g["step_id"]: g["gap_type"] for g in report.gaps}
    assert gap_types["s2"] == "model_only"
    assert gap_types["s4"] == "complete_miss"


@pytest.mark.unit
def test_schema_and_field_grounding():
    """Verify that claims resting on unemitted or unsupported fields are flagged."""
    service = ReconstructionService()

    known_schema = {"process_name", "command_line", "dest_ip", "dest_port"}

    # Grounded event
    grounded, unsupported = service.verify_field_grounding(
        claimed_fields=["process_name", "command_line"],
        available_fields=known_schema,
    )
    assert grounded is True
    assert unsupported == []

    # Ungrounded event citing fields not in sensor schema
    grounded, unsupported = service.verify_field_grounding(
        claimed_fields=["process_name", "fake_unemitted_sensor_header"],
        available_fields=known_schema,
    )
    assert grounded is False
    assert unsupported == ["fake_unemitted_sensor_header"]
