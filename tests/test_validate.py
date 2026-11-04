"""Tests for the StarkCore MTE Validator v1.2.

Covers the Cap 10 corrections:
  V1  sensor completeness (events_lost) and invariant conservation
  V2  Sybil / collusion thresholds (N >= 3f+1)
  V3  causal order by hash, not by clock
  V4  irreversible expulsion only with cryptographic proof
  I5  exact-match consistency, never a numeric subtraction
Plus real Ed25519 (PyNaCl) signature verification.
"""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.validate import (  # noqa: E402
    GENESIS_PREV,
    app,
    calc_H,
    default_f,
    required_nodes,
)

client = TestClient(app)

SIGNING_KEY = SigningKey.generate()
VERIFY_KEY_HEX = bytes(SIGNING_KEY.verify_key).hex()


def sign(prev: str, tid: str, ts: str, thash: str, seq: int) -> str:
    payload = "||".join([prev, tid, ts, thash, str(seq)]).encode()
    return base64.b64encode(SIGNING_KEY.sign(payload).signature).decode()


def chain_hash_of(prev: str, t: dict) -> str:
    """Chain commitment produced by transform ``t`` linked to ``prev``."""
    return calc_H(prev, t["transform_id"], t["timestamp_utc"], t["actor_signature"], t["transformation_hash"])


def build_trajectory(
    n: int = 3,
    system_id: str = "sys-001",
    actor_id: str = "actor-A",
    start_prev: str = GENESIS_PREV,
    signed: bool = True,
) -> list[dict]:
    """Build a cryptographically consistent trajectory."""
    transforms: list[dict] = []
    prev = start_prev
    for i in range(n):
        seq = i + 1
        tid = f"T{seq}"
        ts = f"2026-10-22T00:00:{seq:02d}Z"
        thash = hashlib.sha256(f"state-{seq}".encode()).hexdigest()
        sig = sign(prev, tid, ts, thash, seq) if signed else ""
        transforms.append(
            {
                "transform_id": tid,
                "transformation_hash": thash,
                "actor_signature": sig,
                "actor_id": actor_id,
                "prev_hash": prev,
                "timestamp_utc": ts,
                "seq": seq,
                "system_id": system_id,
                "events_lost": 0,
                "invariant_check": {"I1": True, "I2": True, "I3": True, "I4": True},
            }
        )
        prev = chain_hash_of(prev, transforms[-1])
    return transforms


def rechain(trajectory: list[dict]) -> list[dict]:
    """Re-sign and re-link a trajectory so it stays internally valid."""
    prev = trajectory[0]["prev_hash"]
    for t in trajectory:
        t["prev_hash"] = prev
        t["actor_signature"] = sign(
            prev, t["transform_id"], t["timestamp_utc"], t["transformation_hash"], t["seq"]
        )
        prev = chain_hash_of(prev, t)
    return trajectory


def anchors_from(
    trajectory: list[dict],
    count: int,
    diverge: int = 0,
    style: str = "chain",
) -> dict:
    """Build a witness lattice of ``count`` witnesses for the last transform.

    ``diverge`` witnesses report a value that contradicts the node. ``style``
    selects whether witnesses report the full ``chain_hash`` or the raw
    ``hash`` (transformation_hash) they observed.
    """
    last = trajectory[-1]
    honest = chain_hash_of(last["prev_hash"], last) if style == "chain" else last["transformation_hash"]
    key = "chain_hash" if style == "chain" else "hash"
    lying = "f" * 64 if honest != "f" * 64 else "0" * 64

    witnesses = []
    for i in range(count):
        commitment = lying if i < diverge else honest
        witnesses.append({"witness_id": f"w{i}", "seq": last["seq"], key: commitment})
    return {last["system_id"]: witnesses}


def post(payload: dict) -> dict:
    resp = client.post("/api/validate", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_accepts_consistent_chain():
    traj = build_trajectory(4)
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "ACCEPT"
    assert body["trajectory_hash"] == chain_hash_of(traj[-1]["prev_hash"], traj[-1])


def test_trajectory_hash_is_not_the_empty_string_hash():
    """The v1.2 draft returned SHA256("") as the trajectory hash; it must be real."""
    traj = build_trajectory(2)
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["trajectory_hash"] != hashlib.sha256(b"").hexdigest()


def test_accepts_with_anchored_witness():
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 4)}
    body = post(payload)
    assert body["verdict"] == "ACCEPT"
    assert body["I5"] == 1


def test_raw_transformation_hash_anchors_are_accepted():
    """A witness that observed the raw transformation_hash must not be flagged."""
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 4, style="raw")}
    body = post(payload)
    assert body["verdict"] == "ACCEPT"
    assert body["I5"] == 1


# --------------------------------------------------------------------------- #
# V1 - sensor completeness and invariant conservation
# --------------------------------------------------------------------------- #


def test_events_lost_blocks_batch():
    traj = build_trajectory(3)
    traj[1]["events_lost"] = 2
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "BLOCK"
    assert body["level"] == 0
    assert body["action"] == "FREEZE"
    assert body["I5"] is None


def test_negative_events_lost_blocks_batch():
    traj = build_trajectory(2)
    traj[0]["events_lost"] = -1
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "BLOCK"
    assert body["action"] == "FREEZE"


def test_monotonic_sequence_is_accepted():
    """A well-formed counter (1, 2, 3, ...) must not be a false positive."""
    assert post({"system_id": "sys-001", "trajectory": build_trajectory(3)})["verdict"] == "ACCEPT"


def test_gapped_sequence_blocks_batch():
    """Cap 10 V1: the counter is what proves completeness, so a gap is indeterminate."""
    traj = build_trajectory(3)
    traj[1]["seq"] = 5  # 1 -> 5 -> 3
    rechain(traj)
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "BLOCK"
    assert body["level"] == 0
    assert body["action"] == "FREEZE"
    assert "monotonic" in body["reason"]


def test_duplicate_sequence_blocks_batch():
    traj = build_trajectory(3)
    traj[1]["seq"] = traj[0]["seq"]
    rechain(traj)
    assert post({"system_id": "sys-001", "trajectory": traj})["verdict"] == "BLOCK"


def test_reordered_sequence_blocks_batch():
    traj = build_trajectory(3)
    traj[0]["seq"], traj[1]["seq"], traj[2]["seq"] = 3, 2, 1
    rechain(traj)
    assert post({"system_id": "sys-001", "trajectory": traj})["verdict"] == "BLOCK"


def test_invariant_fail_is_rejected():
    traj = build_trajectory(3)
    traj[2]["invariant_check"]["I2"] = False
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "REJECT"
    assert body["level"] == 3
    assert "I2" in body["failing"]


def test_pass_fail_string_form_is_supported():
    traj = build_trajectory(2)
    for t in traj:
        t["invariant_check"] = {
            "I1_structure": "PASS",
            "I2_authorization": "PASS",
            "I3_relations": "PASS",
            "I4_log": "PASS",
        }
    assert post({"system_id": "sys-001", "trajectory": traj})["verdict"] == "ACCEPT"

    traj[0]["invariant_check"]["I4_log"] = "FAIL"
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "REJECT"
    assert "I4" in body["failing"]


def test_unevaluated_invariants_are_warned_not_silently_passed():
    traj = build_trajectory(2)
    for t in traj:
        t["invariant_check"] = {}
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "ACCEPT"
    assert any("not evaluated" in w for w in body["warnings"])


# --------------------------------------------------------------------------- #
# V3 - causal order by hash, not by clock
# --------------------------------------------------------------------------- #


def test_broken_chain_is_rejected():
    traj = build_trajectory(4)
    traj[2]["prev_hash"] = "a" * 64
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "REJECT"
    assert "I6" in body["reason"]


def test_rewriting_a_past_block_breaks_the_chain():
    """The quantum-eraser claim: erasing a record leaves a cryptographic trace.

    The chain hash commits to the transformation_hash, so editing the payload of
    an already-linked block invalidates its successor's prev_hash.
    """
    traj = build_trajectory(5)
    traj[1]["transformation_hash"] = "b" * 64  # silently edit history
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "REJECT"


def test_clock_skew_does_not_break_causal_order():
    """Timestamps are corroboration only; the hash chain defines order."""
    traj = build_trajectory(3)
    traj[2]["timestamp_utc"] = "1999-01-01T00:00:00Z"  # wrong clock, chain recomputed
    traj[2]["actor_signature"] = sign(
        traj[2]["prev_hash"],
        traj[2]["transform_id"],
        traj[2]["timestamp_utc"],
        traj[2]["transformation_hash"],
        traj[2]["seq"],
    )
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "ACCEPT"


def test_unknown_origin_is_blocked():
    traj = build_trajectory(3, start_prev="c" * 64)
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] == "BLOCK"
    assert "origin" in body["reason"]


def test_declared_origin_is_honoured():
    origin = "d" * 64
    traj = build_trajectory(3, start_prev=origin)
    body = post({"system_id": "sys-001", "trajectory": traj, "origin_state_S0": origin})
    assert body["verdict"] == "ACCEPT"


def test_empty_trajectory_is_blocked():
    body = post({"system_id": "sys-001", "trajectory": []})
    assert body["verdict"] == "BLOCK"


# --------------------------------------------------------------------------- #
# I5 - exact match, never a numeric subtraction
# --------------------------------------------------------------------------- #


def test_i5_is_exact_match_not_numeric_subtraction():
    """'0abc' vs 'abc' must diverge; a subtraction would call them equal."""
    traj = build_trajectory(2)
    last = traj[-1]
    honest = chain_hash_of(last["prev_hash"], last)
    lying = honest[1:]  # drop one leading character
    payload = {
        "system_id": "sys-001",
        "trajectory": traj,
        "witness_db": {
            "sys-001": [{"witness_id": f"w{i}", "seq": last["seq"], "chain_hash": lying} for i in range(7)]
        },
        "f": 2,
    }
    body = post(payload)
    assert body["I5"] == 0
    assert body["verdict"] == "REJECT"


def test_witness_divergence_detected():
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 7, diverge=5), "f": 2}
    body = post(payload)
    assert body["I5"] == 0
    assert body["verdict"] == "REJECT"
    assert body["action"] == "BYZANTINE"
    assert body["level"] == 4


# --------------------------------------------------------------------------- #
# V2 / V4 - Sybil, collusion and threshold arithmetic
# --------------------------------------------------------------------------- #


def test_threshold_arithmetic():
    assert required_nodes(0) == 1
    assert required_nodes(1) == 4
    assert required_nodes(2) == 7  # 7 nodes tolerate 2 Byzantine faults
    assert default_f(5) == 1
    assert default_f(7) == 2
    assert default_f(4) == 1


def test_undersized_lattice_cannot_expel():
    """N=5 with f=2 is not a valid configuration: 5 < 3*2+1."""
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 5, diverge=5), "f": 2}
    body = post(payload)
    assert body["verdict"] == "BLOCK"
    assert body["action"] == "FREEZE"
    assert body["theta_ev"]["consensus_sufficient"] is False


def test_two_colluding_witnesses_out_of_seven_are_contained():
    """N=7, f=2: two colluding liars cannot force expulsion of an honest node."""
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 7, diverge=2), "f": 2}
    body = post(payload)
    assert body["I5"] == 0
    assert body["action"] == "BLOCK"  # 2 < f+1 = 3, so no isolation
    assert body["theta_ev"]["divergences"] == 2
    assert body["theta_ev"]["consensus_sufficient"] is True


def test_f_plus_one_colluders_trigger_isolation():
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 7, diverge=3), "f": 2}
    body = post(payload)
    assert body["action"] == "ISOLATE"
    assert body["level"] == 3


def test_two_f_plus_one_colluders_trigger_expulsion():
    """N=7, f=2: 2f+1 = 5 witnesses are irrefutable proof."""
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 7, diverge=5), "f": 2}
    body = post(payload)
    assert body["action"] == "BYZANTINE"
    assert body["level"] == 4


def test_two_liars_out_of_seven_never_reach_expulsion():
    """N=7, f=2: two colluding liars (f) stay below f+1, so no irreversible action."""
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 7, diverge=2), "f": 2}
    body = post(payload)
    assert body["action"] not in ("BYZANTINE", "ISOLATE")


def test_single_witness_disagreement_is_only_containment():
    """Cap 9.2: a lone dissenting witness is not enough for isolation."""
    traj = build_trajectory(3)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 7, diverge=1), "f": 2}
    body = post(payload)
    assert body["action"] == "BLOCK"
    assert body["theta_ev"]["level"] == 2


def test_f_is_derived_when_not_supplied():
    traj = build_trajectory(2)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": anchors_from(traj, 7, diverge=0)}
    body = post(payload)
    assert body["theta_ev"]["f"] == 2


def test_witness_db_without_anchor_for_system_is_warned():
    traj = build_trajectory(2)
    payload = {"system_id": "sys-001", "trajectory": traj, "witness_db": {"other": []}}
    body = post(payload)
    assert body["verdict"] == "ACCEPT"
    assert body["I5"] is None


# --------------------------------------------------------------------------- #
# Ed25519 (P0.1)
# --------------------------------------------------------------------------- #


def test_valid_ed25519_signatures_are_accepted():
    traj = build_trajectory(3)
    payload = {
        "system_id": "sys-001",
        "trajectory": traj,
        "actor_keys": {"actor-A": VERIFY_KEY_HEX},
        "require_signatures": True,
    }
    assert post(payload)["verdict"] == "ACCEPT"


def test_invalid_ed25519_signature_is_rejected():
    traj = build_trajectory(3)
    traj[1]["actor_signature"] = base64.b64encode(b"\x00" * 64).decode()
    payload = {
        "system_id": "sys-001",
        "trajectory": traj,
        "actor_keys": {"actor-A": VERIFY_KEY_HEX},
        "require_signatures": True,
    }
    body = post(payload)
    assert body["verdict"] == "REJECT"
    assert body["action"] == "BYZANTINE"
    assert "signature" in body["reason"]


def test_missing_signature_blocks_when_required():
    traj = build_trajectory(3, signed=False)
    payload = {
        "system_id": "sys-001",
        "trajectory": traj,
        "actor_keys": {"actor-A": VERIFY_KEY_HEX},
        "require_signatures": True,
    }
    body = post(payload)
    assert body["verdict"] == "BLOCK"


def test_unknown_actor_key_blocks():
    traj = build_trajectory(2)
    payload = {"system_id": "sys-001", "trajectory": traj, "actor_keys": {}, "require_signatures": True}
    body = post(payload)
    assert body["verdict"] == "BLOCK"


def test_malformed_public_key_blocks():
    traj = build_trajectory(2)
    payload = {
        "system_id": "sys-001",
        "trajectory": traj,
        "actor_keys": {"actor-A": "not-a-key"},
        "require_signatures": True,
    }
    body = post(payload)
    assert body["verdict"] == "BLOCK"
    assert "malformed" in body["reason"]


def test_signature_is_bound_to_the_transformation_hash():
    """A valid signature replayed onto a different block must not verify."""
    traj = build_trajectory(3)
    traj[1]["transformation_hash"] = "e" * 64  # keep the old signature
    payload = {
        "system_id": "sys-001",
        "trajectory": traj,
        "actor_keys": {"actor-A": VERIFY_KEY_HEX},
        "require_signatures": True,
    }
    body = post(payload)
    assert body["verdict"] == "REJECT"
    assert "signature" in body["reason"]


def test_base64_public_key_form_is_accepted():
    traj = build_trajectory(2)
    key_b64 = base64.b64encode(bytes(SIGNING_KEY.verify_key)).decode()
    payload = {
        "system_id": "sys-001",
        "trajectory": traj,
        "actor_keys": {"actor-A": key_b64},
        "require_signatures": True,
    }
    assert post(payload)["verdict"] == "ACCEPT"


def test_twin_states_with_divergent_trajectories():
    """Cap 7.4: S1_A == S1_B is insufficient; the trajectory decides."""
    a = build_trajectory(3, start_prev=GENESIS_PREV)
    b = build_trajectory(3, start_prev=GENESIS_PREV)
    b[1]["transformation_hash"] = "9" * 64
    rechain(b[1:])

    body_a = post({"system_id": "sys-001", "trajectory": a})
    body_b = post({"system_id": "sys-001", "trajectory": b})
    assert body_a["verdict"] == body_b["verdict"] == "ACCEPT"
    assert body_a["trajectory_hash"] != body_b["trajectory_hash"]


# --------------------------------------------------------------------------- #
# Fail-closed posture
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t[0].__setitem__("prev_hash", "f" * 64),
        lambda t: t[-1].__setitem__("invariant_check", {"I1": False}),
        lambda t: t[0].__setitem__("events_lost", 1),
    ],
)
def test_no_input_yields_a_silent_accept(mutate):
    traj = build_trajectory(3)
    mutate(traj)
    assert post({"system_id": "sys-001", "trajectory": traj})["verdict"] != "ACCEPT"


def test_verdict_never_accepts_on_snapshot_alone():
    """A clean-looking final block does not rescue a broken history."""
    traj = build_trajectory(4)
    traj[0]["prev_hash"] = "7" * 64  # root tampered
    body = post({"system_id": "sys-001", "trajectory": traj})
    assert body["verdict"] != "ACCEPT"


def test_response_shape_is_stable():
    body = post({"system_id": "sys-001", "trajectory": build_trajectory(1)})
    for field in ("verdict", "level", "action", "reason", "trajectory_hash", "I5", "failing", "theta_ev", "warnings"):
        assert field in body
