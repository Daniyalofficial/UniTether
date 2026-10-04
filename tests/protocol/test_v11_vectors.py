#!/usr/bin/env python3
"""Pin the Python reference to the v1.1 golden vectors (v11.json)."""
import json
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
import ulp_v11 as v11  # noqa: E402

SPEC = json.load(open(os.path.join(HERE, "..", "..", "protocol", "vectors",
                                   "v11.json")))
PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def main():
    c = SPEC["constants"]
    check("constants:feat_versioned", v11.FEAT_VERSIONED == c["feat_versioned"])
    check("constants:msg ids",
          v11.MSG_DEVICE_ID == c["msg_device_id"]
          and v11.MSG_DEVICE_AUTH == c["msg_device_auth"]
          and v11.MSG_RESUME_REQ == c["msg_resume_req"]
          and v11.MSG_RESUME_OK == c["msg_resume_ok"])
    for k, v in c["err_codes"].items():
        check(f"constants:err {k}", getattr(v11, "ERR_" + k.upper()) == v)
    for vec in SPEC["vectors"]:
        kind = vec["kind"]
        if kind == "device_id":
            got = v11.device_id_body(bytes.fromhex(vec["device_id"]),
                                     bytes.fromhex(vec["identity_pub"]),
                                     vec["name"], vec["platform"],
                                     vec["app_ver"], vec["caps"],
                                     bytes.fromhex(vec["transcript"]),
                                     bytes.fromhex(vec["key_mac"]))
            check(f"{vec['name']}:encode", got.hex() == vec["expected"])
            d = v11.device_id_parse(got, bytes.fromhex(vec["transcript"]),
                                    bytes.fromhex(vec["key_mac"]))
            check(f"{vec['name']}:decode", d["name"] == vec["name"]
                  and d["caps"] == vec["caps"])
        elif kind == "device_auth":
            got = v11.device_auth_body(vec["decision"],
                                       bytes.fromhex(vec["session_id"]),
                                       bytes.fromhex(vec["sender_id"]),
                                       bytes.fromhex(vec["transcript"]),
                                       bytes.fromhex(vec["key_mac"]))
            check(f"{vec['name']}:encode", got.hex() == vec["expected"])
            d = v11.device_auth_parse(got, bytes.fromhex(vec["transcript"]),
                                      bytes.fromhex(vec["key_mac"]))
            check(f"{vec['name']}:decode", d["decision"] == vec["decision"])
        elif kind == "resume_req":
            got = v11.resume_req_body(bytes.fromhex(vec["session_id"]),
                                      bytes.fromhex(vec["fresh_pub"]),
                                      bytes.fromhex(vec["resume_nonce"]),
                                      bytes.fromhex(vec["secret"]))
            check(f"{vec['name']}:encode", got.hex() == vec["expected"])
        elif kind == "resume_ok":
            got = v11.resume_ok_body(bytes.fromhex(vec["fresh_pub"]),
                                     bytes.fromhex(vec["session_id"]),
                                     bytes.fromhex(vec["req_pub"]),
                                     bytes.fromhex(vec["secret"]))
            check(f"{vec['name']}:encode", got.hex() == vec["expected"])
        elif kind == "error":
            got = v11.error_body(vec["fatal"], vec["code"], vec["msg"])
            check(f"{vec['name']}:encode", got.hex() == vec["expected"])
            d = v11.error_parse(got)
            check(f"{vec['name']}:decode", d["code"] == vec["code"]
                  and d["msg"] == vec["msg"] and d["fatal"] == vec["fatal"])
    print(f"V1.1 VECTORS: {PASS} pass, {FAIL} fail")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
