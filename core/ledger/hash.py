"""Cryptographic hash chain computation and verification for the Vigil Ledger."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


GENESIS_HASH = "0" * 64


def canonical_payload(payload: Any) -> bytes:
    """Deterministic, compact JSON representation of a payload."""
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except Exception:
            return payload.encode("utf-8")
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_event_hash(prev_hash: Optional[str], payload: Any) -> str:
    """Compute sha256(prev_hash || canonical(payload))."""
    p_hash = prev_hash or GENESIS_HASH
    content = p_hash.encode("utf-8") + canonical_payload(payload)
    return hashlib.sha256(content).hexdigest()


def verify_chain(events: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Verify that a sequence of events forms an untampered hash chain.

    Events must be ordered by seq ascending.
    Returns (is_valid, error_message).
    """
    expected_prev = GENESIS_HASH
    for i, event in enumerate(events):
        seq = event.get("seq", i)
        stored_prev = event.get("prev_hash") or GENESIS_HASH
        stored_hash = event.get("event_hash")

        if stored_prev != expected_prev:
            return False, f"Broken hash chain at seq {seq}: expected prev_hash {expected_prev}, got {stored_prev}"

        computed = compute_event_hash(stored_prev, event.get("payload", {}))
        if stored_hash and stored_hash != computed:
            return False, f"Tampered payload at seq {seq}: expected hash {computed}, stored {stored_hash}"

        expected_prev = stored_hash or computed

    return True, None
