"""Anonymization and export pipeline for labeled verdicts."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import text

from core.storage.connection import get_db_manager
from core.time import utcnow

# Regex patterns for redacting sensitive entities
_IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SUBNET_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
_HOST_REGEX = re.compile(r"\b[a-zA-Z0-9_\-\.]+\.(?:local|corp|internal|lan|net)\b|\bhost-[a-zA-Z0-9_\-]+\b", re.IGNORECASE)
_USER_REGEX = re.compile(r"\b(?:user|admin|john|alice|bob|charlie|analyst)_[a-zA-Z0-9]+\b|\bDOMAIN\\[a-zA-Z0-9_]+\b", re.IGNORECASE)


def redact_text(val: str) -> str:
    """Strip IP addresses, subnets, hostnames, and usernames from a string."""
    if not isinstance(val, str):
        return val
    s = _SUBNET_REGEX.sub("[REDACTED_SUBNET]", val)
    s = _IP_REGEX.sub("[REDACTED_IP]", s)
    s = _HOST_REGEX.sub("[REDACTED_HOST]", s)
    s = _USER_REGEX.sub("[REDACTED_USER]", s)
    return s


def sanitize_dict(d: Any) -> Any:
    """Recursively sanitize keys and string values in dictionaries and lists."""
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            # Exclude raw case text or credentials
            if k.lower() in ("raw_log", "command_line", "description", "password", "token", "case_notes"):
                out[k] = "[WITHHELD_SENSITIVE_TEXT]"
            else:
                out[k] = sanitize_dict(v)
        return out
    elif isinstance(d, list):
        return [sanitize_dict(x) for x in d]
    elif isinstance(d, str):
        return redact_text(d)
    return d


def anonymize_verdict_row(raw_event: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    """Convert raw verdict event into an anonymized row conforming to verdict_export_v1.json.

    Returns (anonymized_row, structural_shape_key).
    """
    payload = raw_event.get("payload", {})
    action = payload.get("action", "confirm")
    source = payload.get("source", "ui")
    raw_reason = payload.get("reason") or "general"
    reason_cat = redact_text(raw_reason)[:64]
    severity = payload.get("new_severity")

    attack_mapping = payload.get("attack_mapping") or []
    tactics = [m.get("tactic") for m in attack_mapping if isinstance(m, dict) and m.get("tactic")]
    techniques = [m.get("technique_id") for m in attack_mapping if isinstance(m, dict) and m.get("technique_id")]

    # Extract sanitized features
    sanitized_features = sanitize_dict(payload.get("loglm_provenance") or {})

    shape_key = f"{action}:{source}:{reason_cat}"

    row = {
        "schema_version": 1,
        "verdict_id": str(raw_event.get("run_id")),
        "action": action,
        "reason_category": reason_cat,
        "source": source,
        "severity": severity,
        "attack_tactics": tactics,
        "attack_techniques": techniques,
        "anonymized_features": sanitized_features,
        "exported_at": utcnow().isoformat(),
    }

    return row, shape_key


def export_verdicts(
    since: Optional[datetime] = None,
    out_path: str = "verdicts_export.jsonl",
    min_shape_frequency: int = 1,
) -> Dict[str, Any]:
    """Export anonymized verdicts into JSONL format, withholding rare shapes."""
    db = get_db_manager()
    events = []
    with db.session_scope() as session:
        dialect = session.bind.dialect.name if session.bind else "postgresql"
        query_text = "SELECT run_id, seq, ts, payload FROM agent_events WHERE kind = 'verdict'"
        params = {}
        if since:
            query_text += " AND ts >= :since"
            params["since"] = since
        query_text += " ORDER BY ts ASC"

        rows = session.execute(text(query_text), params).fetchall()
        for r in rows:
            p = json.loads(r[3]) if isinstance(r[3], str) else r[3]
            events.append({"run_id": r[0], "seq": r[1], "ts": r[2], "payload": p})

    # First pass: identify shapes and count frequencies
    processed = []
    shape_counts = Counter()
    for ev in events:
        row, shape = anonymize_verdict_row(ev)
        processed.append((row, shape))
        shape_counts[shape] += 1

    # Second pass: write rows with frequency >= min_shape_frequency
    exported_count = 0
    withheld_count = 0

    with open(out_path, "w", encoding="utf-8") as f:
        for row, shape in processed:
            if shape_counts[shape] < min_shape_frequency:
                withheld_count += 1
                continue
            f.write(json.dumps(row) + "\n")
            exported_count += 1

    report = {
        "total_records_read": len(events),
        "exported_count": exported_count,
        "withheld_count": withheld_count,
        "out_file": out_path,
        "anonymization_filters_applied": ["ip_redaction", "host_redaction", "user_redaction", "sensitive_text_scrub"],
    }
    return report
