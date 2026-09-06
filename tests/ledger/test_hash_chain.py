"""Tests for cryptographic hash chain integrity and tamper detection in the Ledger."""

import json
import uuid
import pytest
from core.ledger.hash import GENESIS_HASH, compute_event_hash, verify_chain


def test_hash_chain_sequential_integrity():
    """Verify that sequentially chained events pass verification."""
    payload1 = {"action": "scan", "target": "10.0.0.1"}
    h1 = compute_event_hash(GENESIS_HASH, payload1)

    payload2 = {"action": "exploit", "target": "10.0.0.1"}
    h2 = compute_event_hash(h1, payload2)

    payload3 = {"action": "exfil", "bytes": 1024}
    h3 = compute_event_hash(h2, payload3)

    events = [
        {"seq": 0, "prev_hash": GENESIS_HASH, "event_hash": h1, "payload": payload1},
        {"seq": 1, "prev_hash": h1, "event_hash": h2, "payload": payload2},
        {"seq": 2, "prev_hash": h2, "event_hash": h3, "payload": payload3},
    ]

    valid, err = verify_chain(events)
    assert valid is True
    assert err is None


def test_hash_chain_detects_tampered_payload():
    """Verify that tampering with any payload in the chain is detected."""
    payload1 = {"action": "scan", "target": "10.0.0.1"}
    h1 = compute_event_hash(GENESIS_HASH, payload1)

    payload2 = {"action": "exploit", "target": "10.0.0.1"}
    h2 = compute_event_hash(h1, payload2)

    # Malicious actor changes payload2 after the fact
    tampered_payload2 = {"action": "exploit", "target": "10.0.0.99"}

    events = [
        {"seq": 0, "prev_hash": GENESIS_HASH, "event_hash": h1, "payload": payload1},
        {"seq": 1, "prev_hash": h1, "event_hash": h2, "payload": tampered_payload2},
    ]

    valid, err = verify_chain(events)
    assert valid is False
    assert "Tampered payload at seq 1" in err


def test_hash_chain_detects_broken_chain_link():
    """Verify that a broken prev_hash link is detected."""
    payload1 = {"action": "scan"}
    h1 = compute_event_hash(GENESIS_HASH, payload1)

    events = [
        {"seq": 0, "prev_hash": GENESIS_HASH, "event_hash": h1, "payload": payload1},
        {"seq": 1, "prev_hash": "wrong_hash" + "0"*54, "event_hash": "dummy", "payload": {}},
    ]

    valid, err = verify_chain(events)
    assert valid is False
    assert "Broken hash chain at seq 1" in err
