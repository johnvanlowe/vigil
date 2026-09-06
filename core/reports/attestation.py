"""CISO Attestation Report generation and deterministic folding over Ledger events."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.artifacts.service import ArtifactService
from core.ledger.hash import verify_chain


def parse_period(
    quarter: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> Tuple[datetime, datetime, str]:
    """Resolve reporting timeframe into (from_dt, to_dt, identifier)."""
    if quarter:
        m = re.match(r"^(\d{4})Q([1-4])$", quarter.strip().upper())
        if not m:
            raise ValueError(f"Invalid quarter format '{quarter}'. Expected format YYYYQ[1-4], e.g. 2026Q4")
        year = int(m.group(1))
        q = int(m.group(2))
        quarters = {
            1: ((1, 1), (3, 31, 23, 59, 59)),
            2: ((4, 1), (6, 30, 23, 59, 59)),
            3: ((7, 1), (9, 30, 23, 59, 59)),
            4: ((10, 1), (12, 31, 23, 59, 59)),
        }
        (sm, sd), (em, ed, eh, emi, es) = quarters[q]
        from_dt = datetime(year, sm, sd, 0, 0, 0, tzinfo=timezone.utc)
        to_dt = datetime(year, em, ed, eh, emi, es, tzinfo=timezone.utc)
        return from_dt, to_dt, quarter.upper()

    if from_date and to_date:
        from_dt = datetime.fromisoformat(from_date.replace("Z", "+00:00"))
        to_dt = datetime.fromisoformat(to_date.replace("Z", "+00:00"))
        identifier = f"{from_date}_to_{to_date}"
        return from_dt, to_dt, identifier

    # Default fallback: past 90 days
    to_dt = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    from_dt = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)
    return from_dt, to_dt, "2026Q4"


def fold_ledger_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministically fold over agent_events sequence."""
    total_events = len(events)
    work_by_actor: Dict[str, int] = {"agent": 0, "human": 0, "policy": 0}
    work_by_stage: Dict[str, Dict[str, int]] = {}
    policy_changes: List[Dict[str, Any]] = []
    
    findings_created = 0
    findings_dispositioned = 0
    actions_executed = 0
    total_spend_usd = 0.0
    confirmed_dispositions = 0
    overturned_dispositions = 0
    red_runs = 0
    promoted_detections = 0
    sla_breaches = 0

    for ev in events:
        kind = ev.get("kind", "")
        payload = ev.get("payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        # Work share and stages
        if kind == "stage_completed":
            actor = payload.get("actor", "agent")
            stage = payload.get("stage", "unknown")
            work_by_actor[actor] = work_by_actor.get(actor, 0) + 1
            if stage not in work_by_stage:
                work_by_stage[stage] = {"agent": 0, "human": 0, "policy": 0}
            work_by_stage[stage][actor] = work_by_stage[stage].get(actor, 0) + 1

        elif kind == "finding_created":
            findings_created += 1

        elif kind == "verdict_recorded":
            findings_dispositioned += 1
            if payload.get("overturned"):
                overturned_dispositions += 1
            elif payload.get("confirmed"):
                confirmed_dispositions += 1

        elif kind == "action_executed":
            actions_executed += 1

        elif kind == "policy_change":
            policy_changes.append(
                {
                    "timestamp": ev.get("ts", ev.get("timestamp", "")),
                    "policy_id": payload.get("policy_id", ""),
                    "kind": payload.get("kind", ""),
                    "actor": payload.get("actor", "admin"),
                    "direction": payload.get("direction", "tighten"),
                }
            )

        elif kind == "sla_breach":
            sla_breaches += 1

        elif kind == "red_run_executed":
            red_runs += 1

        elif kind == "detection_promoted":
            promoted_detections += 1

        # Cost accumulation
        if "spend_usd" in payload:
            total_spend_usd += float(payload["spend_usd"])
        elif "cost_usd" in payload:
            total_spend_usd += float(payload["cost_usd"])

    total_work = sum(work_by_actor.values())
    agent_pct = round((work_by_actor["agent"] / total_work * 100.0), 2) if total_work > 0 else 0.0

    return {
        "throughput": {
            "total_events": total_events,
            "findings_created": findings_created,
            "findings_dispositioned": findings_dispositioned,
            "actions_executed": actions_executed,
            "red_runs": red_runs,
        },
        "work_share": {
            "total_completed_stages": total_work,
            "by_actor": work_by_actor,
            "by_stage": work_by_stage,
            "agent_percentage": agent_pct,
        },
        "spend": {
            "total_spend_usd": round(total_spend_usd, 4),
            "cost_per_outcome_usd": round(total_spend_usd / max(1, findings_dispositioned), 4),
        },
        "sla_attainment": {
            "breaches_observed": sla_breaches,
            "status": "met" if sla_breaches == 0 else "breached",
        },
        "governance": {
            "confirmed_agent_dispositions": confirmed_dispositions,
            "overturned_agent_dispositions": overturned_dispositions,
            "policy_changes": policy_changes,
        },
        "offensive_eval": {
            "red_runs_evaluated": red_runs,
            "detections_promoted": promoted_detections,
            "detection_promotion_rate": round(promoted_detections / max(1, red_runs), 2),
        },
    }


def generate_deterministic_pdf(report: Dict[str, Any]) -> bytes:
    """Build a minimal, RFC-compliant deterministic PDF 1.4 byte payload."""
    title = f"VIGIL CISO ATTESTATION - {report['period']['identifier']}"
    lines = [
        f"Period: {report['period']['from']} to {report['period']['to']}",
        f"Total Ledger Events: {report['throughput']['total_events']}",
        f"Findings Processed: {report['throughput']['findings_dispositioned']}",
        f"Agent Work Share: {report['work_share']['agent_percentage']}%",
        f"Total Spend: ${report['spend']['total_spend_usd']:.2f}",
        f"Cost per Finding: ${report['spend']['cost_per_outcome_usd']:.2f}",
        f"SLA Breaches: {report['sla_attainment']['breaches_observed']}",
        f"Ledger Hash Verification: {report['ledger_verification']['status']}",
        f"Policy Changes Recorded: {len(report['governance']['policy_changes'])}",
    ]

    text_ops = [f"BT /F1 14 Tf 50 740 Td ({title}) Tj ET"]
    y = 700
    for l in lines:
        text_ops.append(f"BT /F1 10 Tf 50 {y} Td ({l}) Tj ET")
        y -= 20

    stream = "\n".join(text_ops).encode("latin-1")
    objs = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj",
        b"4 0 obj << /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream\nendobj",
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    ]

    out = [b"%PDF-1.4"]
    xref = [0]
    pos = len(out[0]) + 1
    for obj in objs:
        xref.append(pos)
        out.append(obj)
        pos += len(obj) + 1

    xref_pos = pos
    xref_str = f"xref\n0 {len(xref)}\n0000000000 65535 f \n" + "".join(f"{x:010d} 00000 n \n" for x in xref[1:])
    out.append(xref_str.encode("latin-1"))
    out.append(f"trailer << /Size {len(xref)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode("latin-1"))
    return b"\n".join(out)


def build_attestation_report(
    events: List[Dict[str, Any]],
    quarter: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    artifact_service: Optional[ArtifactService] = None,
) -> Dict[str, Any]:
    """Compile attestation report, verify ledger chain, and write hash-addressed artifacts."""
    from_dt, to_dt, identifier = parse_period(quarter, from_date, to_date)
    is_valid, err = verify_chain(events)

    folded = fold_ledger_events(events)

    report_payload = {
        "report": "Vigil CISO Attestation Report",
        "period": {
            "identifier": identifier,
            "from": from_dt.isoformat(),
            "to": to_dt.isoformat(),
        },
        "ledger_verification": {
            "status": "VALID" if is_valid else "TAMPERED",
            "valid": is_valid,
            "error": err,
            "events_verified": len(events),
        },
        **folded,
    }

    # Deterministic JSON bytes
    json_bytes = json.dumps(
        report_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    # Deterministic PDF bytes
    pdf_bytes = generate_deterministic_pdf(report_payload)

    json_hash = None
    pdf_hash = None
    if artifact_service:
        json_hash = artifact_service.put(json_bytes, kind="attestation_json", emit_ledger_event=False)
        pdf_hash = artifact_service.put(pdf_bytes, kind="attestation_pdf", emit_ledger_event=False)

    return {
        "report": report_payload,
        "json_hash": json_hash,
        "pdf_hash": pdf_hash,
        "json_bytes": json_bytes,
        "pdf_bytes": pdf_bytes,
    }
