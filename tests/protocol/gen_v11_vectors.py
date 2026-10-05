#!/usr/bin/env python3
"""Generate protocol/vectors/v11.json golden vectors from the reference."""
import json
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
import ulp_v11 as v11  # noqa: E402

# fixed inputs (deterministic golden values)
PRIV = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUB = bytes.fromhex(
    "d3b0187b9afbc46a8f27be5c75f6a13fbf6d431e18364a2a486b39b0c7a2e200")
DEVICE_ID = v11.device_id_from_pub(PUB)
SECRET = bytes(range(32))
KEY_MAC = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
TRANSCRIPT = bytes.fromhex("deadbeef" * 8)
SID = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
NONCE = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

vecs = {
    "protocol": "unilink-v11",
    "version": 1,
    "constants": {
        "feat_versioned": v11.FEAT_VERSIONED,
        "msg_device_id": v11.MSG_DEVICE_ID,
        "msg_device_auth": v11.MSG_DEVICE_AUTH,
        "msg_resume_req": v11.MSG_RESUME_REQ,
        "msg_resume_ok": v11.MSG_RESUME_OK,
        "err_codes": {
            "auth": v11.ERR_AUTH, "cipher": v11.ERR_CIPHER,
            "version": v11.ERR_VERSION, "format": v11.ERR_FORMAT,
            "limit": v11.ERR_LIMIT, "timeout": v11.ERR_TIMEOUT,
            "identity_required": v11.ERR_IDENTITY_REQUIRED,
            "throttled": v11.ERR_THROTTLED, "revoked": v11.ERR_REVOKED,
            "resume_invalid": v11.ERR_RESUME_INVALID,
            "upgrade_required": v11.ERR_UPGRADE_REQUIRED,
        },
        "decisions": {"trusted": 0, "trusted_new": 1,
                      "revoked": 2, "throttled": 3},
    },
    "vectors": [
        {
            "name": "device_id",
            "kind": "device_id",
            "device_id": DEVICE_ID.hex(),
            "identity_pub": PUB.hex(),
            "name": "Pixel 8",
            "platform": "android",
            "app_ver": "0.2.0",
            "caps": v11.CAP_NETWORK | v11.CAP_CAMERA | v11.CAP_MIC,
            "transcript": TRANSCRIPT.hex(),
            "key_mac": KEY_MAC.hex(),
            "expected": v11.device_id_body(
                DEVICE_ID, PUB, "Pixel 8", "android", "0.2.0",
                v11.CAP_NETWORK | v11.CAP_CAMERA | v11.CAP_MIC,
                TRANSCRIPT, KEY_MAC).hex(),
        },
        {
            "name": "device_auth",
            "kind": "device_auth",
            "decision": v11.DECISION_TRUSTED_NEW,
            "session_id": SID.hex(),
            "sender_id": DEVICE_ID.hex(),
            "transcript": TRANSCRIPT.hex(),
            "key_mac": KEY_MAC.hex(),
            "expected": v11.device_auth_body(
                v11.DECISION_TRUSTED_NEW, SID, DEVICE_ID,
                TRANSCRIPT, KEY_MAC).hex(),
        },
        {
            "name": "resume_req",
            "kind": "resume_req",
            "session_id": SID.hex(),
            "fresh_pub": PUB.hex(),
            "resume_nonce": NONCE.hex(),
            "secret": SECRET.hex(),
            "expected": v11.resume_req_body(SID, PUB, NONCE, SECRET).hex(),
        },
        {
            "name": "resume_ok",
            "kind": "resume_ok",
            "fresh_pub": PUB.hex(),
            "session_id": SID.hex(),
            "req_pub": PUB.hex(),
            "secret": SECRET.hex(),
            "expected": v11.resume_ok_body(PUB, SID, PUB, SECRET).hex(),
        },
        {
            "name": "error_throttled",
            "kind": "error",
            "fatal": True,
            "code": v11.ERR_THROTTLED,
            "msg": "too many attempts",
            "expected": v11.error_body(True, v11.ERR_THROTTLED,
                                       "too many attempts").hex(),
        },
        {
            "name": "error_nonfatal_limit",
            "kind": "error",
            "fatal": False,
            "code": v11.ERR_LIMIT,
            "msg": "queue full",
            "expected": v11.error_body(False, v11.ERR_LIMIT,
                                       "queue full").hex(),
        },
    ],
    "negatives": [
        {"kind": "device_id", "tamper": "last_byte",
         "expect": "mac mismatch"},
        {"kind": "device_id", "tamper": "transcript",
         "expect": "mac mismatch"},
        {"kind": "resume_req", "tamper": "wrong_secret",
         "expect": "mac mismatch"},
        {"kind": "resume_ok", "tamper": "wrong_req_pub",
         "expect": "mac mismatch"},
        {"kind": "device_auth", "tamper": "wrong_key",
         "expect": "mac mismatch"},
    ],
}
out = os.path.join(HERE, "..", "..", "protocol", "vectors", "v11.json")
with open(out, "w") as f:
    json.dump(vecs, f, indent=2, sort_keys=True)
print(f"wrote {out}")
