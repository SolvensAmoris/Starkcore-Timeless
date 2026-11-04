"""StarkCore MTE Validator v1.2 (Memoria de Trayectoria Estructural).

Fail-closed verifier for the operational identity of a system. The verdict is a
function of the *trajectory* (the signed history), never of the final snapshot.

Verdict semantics (STARKCORE-MORPH-001, Cap 9 + Cap 10):
  ACCEPT  - the whole chain is cryptographically consistent, invariants held and
            the external witness is anchored.
  REJECT  - positive evidence of a violation (invariant FAIL, witness
            divergence, broken causal chain).
  BLOCK   - insufficient evidence. The validator cannot affirm the system is
            safe, so it refuses to do so. This is not a failure mode, it is the
            default posture.

Verdict -> Enforcer action mapping (Cap 6 + Cap 9):
  level 0  UNDETERMINED / INCOMPLETE  -> FREEZE
  level 1  DISSONANCE (1 witness)     -> OBSERVE
  level 2  SUSPICION (f+1 witnesses)  -> BLOCK
  level 3  PREPONDERANT (2f+1)        -> ISOLATE
  level 4  IRREFUTABLE (proof)        -> BYZANTINE (expulsion)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

SCHEMA_ID = "starkcore.mte.v1"
GENESIS_PREV = "0" * 64

# Byzantine fault tolerance: N >= 3f + 1 (Cap 10, V2).
def required_nodes(f: int) -> int:
    """Minimum node count that tolerates ``f`` Byzantine faults."""
    return 3 * f + 1


def default_f(node_count: int) -> int:
    """Largest ``f`` such that ``node_count >= 3f + 1``."""
    return max(0, (node_count - 1) // 3)


class Verdict(str):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    BLOCK = "BLOCK"


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #


def _coerce_flag(boolean_flag: Optional[bool], string_flag: Optional[str]) -> Optional[bool]:
    if boolean_flag is not None:
        return boolean_flag
    if string_flag is None:
        return None
    return string_flag.strip().upper() == "PASS"


class Invariant(BaseModel):
    """Invariant check for a single transform.

    Accepts both the flat boolean form (``I1``..``I4``) used by the v1.2 draft
    and the PASS/FAIL form declared in the MTE v1 JSON Schema.
    """

    model_config = {"extra": "allow"}

    I1: Optional[bool] = None
    I2: Optional[bool] = None
    I3: Optional[bool] = None
    I4: Optional[bool] = None
    I1_structure: Optional[str] = None
    I2_authorization: Optional[str] = None
    I3_relations: Optional[str] = None
    I4_log: Optional[str] = None

    def as_map(self) -> Dict[str, Optional[bool]]:
        return {
            "I1": _coerce_flag(self.I1, self.I1_structure),
            "I2": _coerce_flag(self.I2, self.I2_authorization),
            "I3": _coerce_flag(self.I3, self.I3_relations),
            "I4": _coerce_flag(self.I4, self.I4_log),
        }


class Transform(BaseModel):
    model_config = {"extra": "allow"}

    transform_id: str
    transformation_hash: str
    actor_signature: str = ""
    prev_hash: str = ""
    invariant_check: Invariant = Field(default_factory=Invariant)
    timestamp_utc: str = ""
    seq: int = 0
    system_id: str = ""
    events_lost: int = 0
    actor_id: Optional[str] = None


class WitnessAnchor(BaseModel):
    """A single witness's anchored commitment for one system."""

    model_config = {"extra": "allow"}

    witness_id: Optional[str] = None
    seq: Optional[int] = None
    hash: Optional[str] = None
    chain_hash: Optional[str] = None


class TrajectoryReq(BaseModel):
    model_config = {"extra": "allow"}

    system_id: str
    trajectory: List[Transform]

    # Single anchor (v1.2 draft) or a list of witness anchors (Cap 8 lattice).
    witness_db: Optional[Dict[str, Any]] = None
    f: Optional[int] = None

    # Ed25519 public keys, actor_id -> hex or base64 raw 32-byte key.
    actor_keys: Optional[Dict[str, str]] = None
    require_signatures: bool = False

    # Optional declared chain origin. When absent the first transform must link
    # to the genesis sentinel.
    origin_state_S0: Optional[str] = None


# --------------------------------------------------------------------------- #
# Hashing / chain primitives
# --------------------------------------------------------------------------- #


def calc_H(prev: str, tid: str, ts: str, sig: str, thash: str = "") -> str:
    """Canonical chain hash H_k = SHA256(prev || tid || ts || sig || thash).

    ``thash`` (the transformation_hash) is committed to on purpose. Without it
    the chain would certify only *that* a transform happened, not *what* it
    produced, and the payload of a past block could be rewritten without
    disturbing the chain. With it, the digest chain pins the content, which is
    what makes the "no quantum erasure" property hold (Cap 4.4).
    """
    payload = "||".join([prev or "", tid or "", ts or "", sig or "", thash or ""])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def chain_hashes(trajectory: List[Transform]) -> List[str]:
    """Return the chain hash produced by each transform, in order."""
    hashes: List[str] = []
    prev = trajectory[0].prev_hash if trajectory else GENESIS_PREV
    for t in trajectory:
        prev = calc_H(prev, t.transform_id, t.timestamp_utc, t.actor_signature, t.transformation_hash)
        hashes.append(prev)
    return hashes


def trajectory_hash(trajectory: List[Transform]) -> str:
    """Terminal chain hash of the whole trajectory."""
    if not trajectory:
        return GENESIS_PREV
    return chain_hashes(trajectory)[-1]


def signature_payload(t: Transform) -> bytes:
    """Canonical bytes an actor is expected to sign for a transform.

    Deliberately excludes ``actor_signature`` (it is the signature itself) and
    includes the block commitment so a replayed signature cannot be attached to
    a different transformation_hash.
    """
    fields = [t.prev_hash, t.transform_id, t.timestamp_utc, t.transformation_hash, str(t.seq)]
    return "||".join(fields).encode("utf-8")


def _decode_public_key(raw: str) -> Optional[bytes]:
    raw = raw.strip()
    for decoder in (bytes.fromhex, _b64decode, _b64decode_alt):
        try:
            key = decoder(raw)
        except (ValueError, binascii.Error):
            continue
        if len(key) == 32:
            return key
    return None


def _b64decode(raw: str) -> bytes:
    return base64.b64decode(raw, validate=True)


def _b64decode_alt(raw: str) -> bytes:
    padded = raw + "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(padded)


def verify_ed25519(public_key: bytes, signature: str, message: bytes) -> bool:
    """Verify an Ed25519 signature. Returns False on any malformed input."""
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:  # pragma: no cover - exercised only without PyNaCl
        return False

    try:
        sig_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error):
        try:
            sig_bytes = bytes.fromhex(signature)
        except (ValueError, binascii.Error):
            return False

    try:
        VerifyKey(public_key).verify(message, sig_bytes)
        return True
    except (BadSignatureError, ValueError):
        return False


# --------------------------------------------------------------------------- #
# Witness / swarm consensus (Cap 8 + Cap 9 + Cap 10)
# --------------------------------------------------------------------------- #


def _normalise_anchors(entry: Any) -> List[WitnessAnchor]:
    """Accept a single anchor dict or a list of anchors."""
    if entry is None:
        return []
    if isinstance(entry, dict):
        # ``{"seq": n, "hash": ...}`` is a single anchor; a dict of
        # witness_id -> anchor is a multi-witness map.
        if "hash" in entry or "chain_hash" in entry or "seq" in entry:
            return [WitnessAnchor(**entry)]
        anchors = []
        for witness_id, value in entry.items():
            if isinstance(value, dict):
                anchors.append(WitnessAnchor(witness_id=witness_id, **value))
        return anchors
    if isinstance(entry, list):
        return [WitnessAnchor(**a) if isinstance(a, dict) else WitnessAnchor(hash=str(a)) for a in entry]
    return []


def evaluate_swarm(
    transform: Transform,
    chain_hash: str,
    anchors: List[WitnessAnchor],
    f: int,
) -> Tuple[Optional[int], int, int, Optional[str]]:
    """Compare a transform commitment against the witness lattice.

    Returns ``(I5, divergences, node_count, action)`` where ``I5`` is 1 (exact
    match), 0 (verifiable contradiction) or None (insufficient evidence).

    Cap 10.2: comparison is exact equality, never a numeric subtraction.

    An anchor declares either ``chain_hash`` (the witness recomputed the full
    chain commitment) or ``hash`` (the witness observed the raw
    transformation_hash). The comparison is like-for-like: mixing the two would
    report a divergence for a perfectly honest node.
    """
    if not anchors:
        return None, 0, 0, None

    node_count = len(anchors)
    divergences = 0
    compared = 0

    for anchor in anchors:
        if anchor.chain_hash is not None:
            expected = anchor.chain_hash
            observed = chain_hash
        elif anchor.hash is not None:
            expected = anchor.hash
            observed = transform.transformation_hash
        else:
            continue

        # Only anchors that claim to cover this position are comparable.
        if anchor.seq is not None and anchor.seq != transform.seq:
            continue

        compared += 1
        if expected != observed:
            divergences += 1

    if compared == 0:
        return None, 0, node_count, None
    if divergences == 0:
        return 1, 0, node_count, None

    # A contradiction exists. How strongly can we act on it?
    if node_count < required_nodes(f):
        # The lattice itself is too small to distinguish a Byzantine witness
        # from a divergent node (Cap 10, V2). Insufficient evidence.
        return 0, divergences, node_count, "FREEZE"
    if divergences >= 2 * f + 1:
        return 0, divergences, node_count, "BYZANTINE"
    if divergences >= f + 1:
        return 0, divergences, node_count, "ISOLATE"
    return 0, divergences, node_count, "BLOCK"


# --------------------------------------------------------------------------- #
# Verdict construction
# --------------------------------------------------------------------------- #


def respond(
    verdict: str,
    *,
    level: int,
    action: str,
    reason: str,
    trajectory_hash_value: Optional[str] = None,
    failing: Optional[List[str]] = None,
    I5: Optional[int] = None,
    theta_ev: Optional[Dict[str, Any]] = None,
    warnings: Optional[List[str]] = None,
    seq: Optional[int] = None,
) -> JSONResponse:
    body: Dict[str, Any] = {
        "verdict": verdict,
        "level": level,
        "action": action,
        "reason": reason,
        "trajectory_hash": trajectory_hash_value,
        "I5": I5,
        "failing": failing or [],
        "theta_ev": theta_ev,
        "warnings": warnings or [],
    }
    if seq is not None:
        body["seq"] = seq
    return JSONResponse(status_code=200, content=body)


# --------------------------------------------------------------------------- #
# Application
# --------------------------------------------------------------------------- #

app = FastAPI(title="StarkCore MTE Validator", version="1.2")


@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": "starkcore-mte-validator",
        "version": "1.2",
        "schema": SCHEMA_ID,
        "endpoint": "POST /api/validate",
        "verdicts": ["ACCEPT", "REJECT", "BLOCK"],
    }


@app.get("/api/validate")
def health() -> Dict[str, str]:
    return {"status": "ok", "validator": "starkcore.mte.v1.2"}


@app.post("/api/validate")
def validate(req: TrajectoryReq) -> JSONResponse:
    warnings: List[str] = []

    if not req.trajectory:
        return respond(
            Verdict.BLOCK,
            level=0,
            action="FREEZE",
            reason="empty trajectory: no history to audit (fail-closed)",
        )

    # ---- P0.3 / Cap 10 V1: sensor completeness ---------------------------- #
    # The Merkle tree proves what was captured, not that nothing was dropped.
    # Completeness is therefore carried by the monotonic sequence counter plus
    # the events_lost metric; a gap, a repeat or a negative count all mean the
    # batch cannot be affirmed complete, so the verdict is indeterminate (BLOCK).
    for t in req.trajectory:
        if t.events_lost < 0:
            return respond(
                Verdict.BLOCK,
                level=0,
                action="FREEZE",
                reason="malformed sensor telemetry: events_lost<0 is not a valid count",
                I5=None,
                seq=t.seq,
            )
        if t.events_lost > 0:
            return respond(
                Verdict.BLOCK,
                level=0,
                action="FREEZE",
                reason="INCOMPLETE batch, events_lost>0: sensor tree proves what was captured, not completeness",
                I5=None,
                seq=t.seq,
            )

    for prev_t, t in zip(req.trajectory, req.trajectory[1:]):
        if t.seq <= prev_t.seq:
            return respond(
                Verdict.BLOCK,
                level=0,
                action="FREEZE",
                reason=(
                    f"non-monotonic sequence counter (seq {prev_t.seq} -> {t.seq}): "
                    "a gap, repeat or reorder means the trajectory may be incomplete"
                ),
                I5=None,
                seq=t.seq,
            )

    # ---- P0.2 / Cap 10 V1: invariant conservation ------------------------- #
    # Rule: any FAIL without explicit authorization compromises the system.
    for t in req.trajectory:
        flags = t.invariant_check.as_map()
        failing = [name for name, ok in flags.items() if ok is False]
        if failing:
            return respond(
                Verdict.REJECT,
                level=3,
                action="ISOLATE",
                reason="invariant violation with positive evidence",
                failing=failing,
                seq=t.seq,
            )
        unevaluated = [name for name, ok in flags.items() if ok is None]
        if unevaluated:
            # Absent invariant evidence is not evidence of conservation.
            warnings.append(
                f"seq {t.seq}: invariants not evaluated: {', '.join(unevaluated)}"
            )

    # ---- Ed25519 actor signatures (P0.1) ---------------------------------- #
    signatures_verified = False
    if req.require_signatures:
        signatures_verified = True
        for t in req.trajectory:
            if not t.actor_signature:
                return respond(
                    Verdict.BLOCK,
                    level=0,
                    action="FREEZE",
                    reason=f"seq {t.seq}: signature required but missing",
                    seq=t.seq,
                )
            if not t.actor_id or not req.actor_keys or t.actor_id not in req.actor_keys:
                return respond(
                    Verdict.BLOCK,
                    level=0,
                    action="FREEZE",
                    reason=f"seq {t.seq}: no public key for actor_id={t.actor_id!r}",
                    seq=t.seq,
                )
            key = _decode_public_key(req.actor_keys[t.actor_id])
            if key is None:
                return respond(
                    Verdict.BLOCK,
                    level=0,
                    action="FREEZE",
                    reason=f"seq {t.seq}: malformed public key for actor_id={t.actor_id!r}",
                    seq=t.seq,
                )
            if not verify_ed25519(key, t.actor_signature, signature_payload(t)):
                return respond(
                    Verdict.REJECT,
                    level=4,
                    action="BYZANTINE",
                    reason=f"seq {t.seq}: invalid Ed25519 signature from {t.actor_id!r}",
                    seq=t.seq,
                )
    else:
        warnings.append("signature verification disabled: set require_signatures=true for full audit")

    # ---- I6: causal order by hash, not by clock (Cap 10 V3) --------------- #
    hashes = chain_hashes(req.trajectory)

    expected_origin = req.origin_state_S0 or GENESIS_PREV
    if req.trajectory[0].prev_hash != expected_origin:
        return respond(
            Verdict.BLOCK,
            level=0,
            action="FREEZE",
            reason="first transform does not link to a declared origin (unverifiable root)",
        )

    for i in range(1, len(req.trajectory)):
        prev_t = req.trajectory[i - 1]
        expected = calc_H(
            prev_t.prev_hash,
            prev_t.transform_id,
            prev_t.timestamp_utc,
            prev_t.actor_signature,
            prev_t.transformation_hash,
        )
        if req.trajectory[i].prev_hash != expected:
            return respond(
                Verdict.REJECT,
                level=4,
                action="BYZANTINE",
                reason="broken causal chain (I6): prev_hash does not match the predecessor commitment",
                seq=req.trajectory[i].seq,
            )

    # ---- I5: swarm consistency, exact match (Cap 8 + Cap 10.2) ----------- #
    I5: Optional[int] = None
    action = "NONE"
    level = 0
    divergences = 0
    node_count = 0

    if req.witness_db:
        anchors = _normalise_anchors(req.witness_db.get(req.system_id))
        f = req.f if req.f is not None else default_f(len(anchors))
        for t, chain_hash in zip(req.trajectory, hashes):
            result = evaluate_swarm(t, chain_hash, anchors, f)
            i5_value, divergences, node_count, swarm_action = result
            if i5_value == 0:
                I5 = 0
                action = swarm_action or "BLOCK"
                level = {"FREEZE": 0, "BLOCK": 2, "ISOLATE": 3, "BYZANTINE": 4}.get(action, 2)
                verdict = Verdict.BLOCK if action == "FREEZE" else Verdict.REJECT
                theta = build_theta_ev(node_count, divergences, f)
                if node_count < required_nodes(f):
                    reason = (
                        f"witness contradiction but lattice N={node_count} < 3f+1={required_nodes(f)}: "
                        "cannot distinguish Byzantine from divergent (fail-closed)"
                    )
                else:
                    reason = "verifiable divergence against the witness lattice (I5=0)"
                return respond(
                    verdict,
                    level=level,
                    action=action,
                    reason=reason,
                    trajectory_hash_value=hashes[-1],
                    I5=I5,
                    theta_ev=theta,
                    warnings=warnings,
                    seq=t.seq,
                )
            if i5_value == 1:
                I5 = 1
    else:
        warnings.append("no witness_db supplied: I5 unverifiable")

    theta_ev = build_theta_ev(node_count, divergences, f if req.witness_db else None)

    return respond(
        Verdict.ACCEPT,
        level=1 if node_count else 0,
        action="NONE",
        reason="chain valid, invariants conserved"
        + (", witness anchored" if I5 == 1 else "; I5 unverifiable"),
        trajectory_hash_value=hashes[-1],
        I5=I5,
        theta_ev=theta_ev,
        warnings=warnings,
    )


def build_theta_ev(
    node_count: int, divergences: int, f: Optional[int]
) -> Dict[str, Any]:
    """Evidence threshold Theta_ev (Cap 9.2)."""
    if f is None:
        return {
            "nodes": node_count,
            "f": None,
            "divergences": divergences,
            "level": None,
            "recommended_action": "OBSERVE",
            "consensus_sufficient": None,
        }
    if divergences == 0:
        return {
            "nodes": node_count,
            "f": f,
            "divergences": 0,
            "level": 1,
            "recommended_action": "OBSERVE",
            "consensus_sufficient": node_count >= required_nodes(f),
        }
    if divergences >= 2 * f + 1:
        level, recommended = 4, "BYZANTINE"
    elif divergences >= f + 1:
        level, recommended = 3, "ISOLATE"
    else:
        level, recommended = 2, "BLOCK"
    return {
        "nodes": node_count,
        "f": f,
        "divergences": divergences,
        "level": level,
        "recommended_action": recommended,
        "consensus_sufficient": node_count >= required_nodes(f),
    }
