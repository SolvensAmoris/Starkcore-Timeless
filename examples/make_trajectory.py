"""Generate example MTE payloads for the StarkCore validator.

Usage:
    python examples/make_trajectory.py > trajectory.json
    curl -X POST https://<deployment>/api/validate -H 'content-type: application/json' -d @trajectory.json

The generated payload carries real Ed25519 signatures, so it can also be run
with ``require_signatures: true``. The public key is printed to stderr.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nacl.signing import SigningKey  # noqa: E402

from api.validate import GENESIS_PREV, calc_H  # noqa: E402

SYSTEM_ID = "sys-demo-001"
ACTOR_ID = "actor-A"


def build(n: int = 4):
    key = SigningKey.generate()
    prev = GENESIS_PREV
    trajectory = []
    for i in range(n):
        seq = i + 1
        tid = f"T{seq}"
        ts = f"2026-10-22T00:00:{seq:02d}Z"
        thash = hashlib.sha256(f"state-{seq}".encode()).hexdigest()
        payload = "||".join([prev, tid, ts, thash, str(seq)]).encode()
        sig = base64.b64encode(key.sign(payload).signature).decode()
        trajectory.append(
            {
                "transform_id": tid,
                "transformation_hash": thash,
                "actor_signature": sig,
                "actor_id": ACTOR_ID,
                "prev_hash": prev,
                "timestamp_utc": ts,
                "seq": seq,
                "system_id": SYSTEM_ID,
                "events_lost": 0,
                "invariant_check": {
                    "I1_structure": "PASS",
                    "I2_authorization": "PASS",
                    "I3_relations": "PASS",
                    "I4_log": "PASS",
                },
            }
        )
        prev = calc_H(prev, tid, ts, sig, thash)

    # Two honest witnesses anchor the head of the chain.
    witnesses = [
        {"witness_id": f"w{i}", "seq": n, "chain_hash": prev} for i in range(4)
    ]

    request = {
        "system_id": SYSTEM_ID,
        "trajectory": trajectory,
        "witness_db": {SYSTEM_ID: witnesses},
        "actor_keys": {ACTOR_ID: bytes(key.verify_key).hex()},
        "require_signatures": True,
    }
    return request


if __name__ == "__main__":
    req = build()
    print(json.dumps(req, indent=2))
