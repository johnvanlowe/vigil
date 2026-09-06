"""Tests for reconstruction skill and detection verdicts mapping."""

import json
from pathlib import Path
import pytest

from core.detections.candidates import DetectionVerdict
from core.detections.reconstruction import (
    ReconstructionService,
    skill_reconstruct,
)
from core.integrations.offensive.contract import ActionStatus, ActionTraceStep
from core.integrations.offensive.stub import StubOffensiveEngine


def test_skill_reconstruct_import_and_manifest():
    """Verify SKILL.md manifest exists and skill_reconstruct is callable."""
    skill_md = Path(__file__).resolve().parents[2] / "skills" / "reconstruction" / "SKILL.md"
    assert skill_md.exists()
    content = skill_md.read_text(encoding="utf-8")
    assert "schema_version: 1" in content
    assert callable(skill_reconstruct)


def test_reconstruction_schema_v1_and_replayable_queries():
    """Verify reconstruction emits DetectionVerdict with schema v1 and replayable queries."""
    service = ReconstructionService()
    trace = [
        ActionTraceStep(
            step_id="step-wmi",
            technique_id="T1047",
            status=ActionStatus.SUCCESS,
            executed_action="wmic process call create cmd",
            target_asset="srv-app-01",
        )
    ]
    telemetry = [
        {
            "step_id": "step-wmi",
            "technique_id": "T1047",
            "event_id": "evt-wmi-101",
            "rule_id": "SIGMA-RULE-WMIC",
            "source": "sysmon",
            "details": {"command_line": "wmic process call create cmd"},
        }
    ]

    report = service.reconstruct(
        action_trace=trace,
        telemetry_findings=telemetry,
        environment_id="staging-range",
        plan_id="plan-test",
    )

    assert len(report.step_verdicts) == 1
    verdict = report.step_verdicts[0]
    assert isinstance(verdict, DetectionVerdict)
    assert verdict.verdict == "rule"
    assert verdict.technique_id == "T1047"
    assert len(verdict.evidence_citations) == 1

    citation = verdict.evidence_citations[0]
    assert "replayable_query" in citation
    assert "SELECT * FROM telemetry" in citation["replayable_query"]
    assert "evt-wmi-101" in citation["replayable_query"]


def test_loglm_distinct_from_rule_separates_layers():
    """Verify loglm verdict is distinct from rule verdict and separated in report counts."""
    service = ReconstructionService()
    trace = [
        ActionTraceStep(
            step_id="step-rule",
            technique_id="T1059",
            status=ActionStatus.SUCCESS,
            executed_action="powershell.exe",
            target_asset="srv-01",
        ),
        ActionTraceStep(
            step_id="step-loglm",
            technique_id="T1021",
            status=ActionStatus.SUCCESS,
            executed_action="net use \\\\dc\\C$",
            target_asset="srv-02",
        ),
        ActionTraceStep(
            step_id="step-both",
            technique_id="T1078",
            status=ActionStatus.SUCCESS,
            executed_action="whoami /all",
            target_asset="srv-03",
        ),
    ]

    telemetry = [
        {
            "step_id": "step-rule",
            "technique_id": "T1059",
            "rule_id": "RULE-PS-01",
            "source": "sysmon",
        },
        {
            "step_id": "step-loglm",
            "technique_id": "T1021",
            "source": "loglm",
            "event_id": "loglm-evt-202",
        },
        {
            "step_id": "step-both",
            "technique_id": "T1078",
            "rule_id": "RULE-WHOAMI",
            "source": "sysmon",
        },
        {
            "step_id": "step-both",
            "technique_id": "T1078",
            "source": "loglm",
            "event_id": "loglm-evt-203",
        },
    ]

    report = service.reconstruct(
        action_trace=trace,
        telemetry_findings=telemetry,
        environment_id="staging-range",
        plan_id="plan-layers",
    )

    assert report.detected_by_rule_count == 1
    assert report.detected_by_loglm_count == 1
    assert report.both_count == 1
    assert report.missed_count == 0


def test_regression_missed_classification_against_fixture():
    """Verify against recorded red run fixture that missed classification matches expected."""
    stub = StubOffensiveEngine()
    fixture_trace = stub.load_fixture_trace()
    fixture_telemetry = stub.load_fixture_telemetry()
    expected_verdicts = stub.load_expected_verdicts()

    # Reconstruct the run
    report = skill_reconstruct(
        action_trace=fixture_trace,
        telemetry_findings=fixture_telemetry,
        environment_id="staging-range",
        plan_id="fixture-run",
    )

    verdict_by_step = {v.step_id: v.verdict for v in report.step_verdicts}
    expected_by_step = {e["step_id"]: e["verdict"] for e in expected_verdicts}

    # Step 4 (exfil) is missed in fixture
    assert verdict_by_step["step-04-exfil"] == "missed"
    assert report.missed_count >= 1
    assert any(g["step_id"] == "step-04-exfil" for g in report.gaps)
