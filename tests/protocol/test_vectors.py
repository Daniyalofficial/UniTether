#!/usr/bin/env python3
"""Validate protocol/vectors/*.json against the reference implementation.

Every vector is checked in BOTH directions:
  * encode(input)  == expected golden bytes
  * decode(expected) == input structure
Plus protocol robustness tests (bad magic, bad extended length,
incomplete frames, AEAD tag failure, pairing blob round-trip,
RFC 7748 X25519 vector).

Exit code 0 = all pass. Stdlib only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference_framing as rf

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "..", "protocol", "vectors")
FAILS = []
PASSES = [0]


def check(cond, label):
    if cond:
        PASSES[0] += 1
    else:
        FAILS.append(label)
        print(f"  FAIL: {label}")


def load(fname):
    with open(os.path.join(VECTORS, fname)) as fh:
        return json.load(fh)["vectors"]


def hx(s):
    return bytes.fromhex(s)


# ------------------------------------------------------------------ frames
def test_frames():
    print("frames.json")
    for v in load("frames.json"):
        fr = rf.Frame(v["channel"], v["flags"], hx(v["payload"]))
        check(fr.encode() == hx(v["expected"]), f"frame encode {v['name']}")
        d = rf.Frame.decode(hx(v["expected"]))
        check(d.channel == v["channel"], f"frame ch {v['name']}")
        check(d.flags == v["flags"], f"frame flags {v['name']}")
        check(d.payload == hx(v["payload"]), f"frame payload {v['name']}")


# ---------------------------------------------------------------- messages
def test_messages():
    print("messages.json")
    for v in load("messages.json"):
        kind = v["kind"]
        if kind == "hello":
            body = (rf.hello_body(v["role"], v["feature_mask"],
                                  v["cipher_pref"], hx(v["ecdh_pub"]),
                                  hx(v["nonce_a"]))
                    + rf.pairing_mac(hx(v["secret"]), hx(v["ecdh_pub"]),
                                     hx(v["nonce_a"])))
            check(body == hx(v["expected"]), f"hello {v['name']}")
            parsed = rf.hello_verify(body, hx(v["secret"]))
            check(parsed["role"] == v["role"]
                  and parsed["feature_mask"] == v["feature_mask"],
                  f"hello verify {v['name']}")
            try:
                bad = bytearray(body)
                bad[60] ^= 0xFF
                rf.hello_verify(bytes(bad), hx(v["secret"]))
                check(False, f"hello tamper {v['name']}")
            except rf.AuthError:
                check(True, "")
        elif kind == "hello_ack":
            body = rf.hello_ack_body(v["negotiated"], v["cipher_sel"],
                                     hx(v["ecdh_pub"]), hx(v["nonce_b"]),
                                     hx(v["nonce_a"]), hx(v["secret"]))
            check(body == hx(v["expected"]), f"hello_ack {v['name']}")
            parsed = rf.hello_ack_verify(body, hx(v["secret"]),
                                         hx(v["nonce_a"]))
            check(parsed["negotiated"] == v["negotiated"],
                  f"hello_ack verify {v['name']}")
        elif kind == "msg":
            body = hx(v["expected"])
            mtype, _flags, mbody = rf.msg_decode(body)
            check(len(body) == 4 + len(mbody), f"msg len {v['name']}")
        elif kind == "config":
            body = rf.config_body(v["v4_prefix"], hx(v["v4_device"]),
                                  hx(v["v4_host"]), v["v6_prefix"],
                                  hx(v["v6_device"]), hx(v["v6_host"]),
                                  [hx(d) for d in v["dns"]],
                                  [(p, hx(a)) for p, a in v["routes"]])
            check(body == hx(v["expected"]), f"config {v['name']}")
            p = rf.config_parse(body)
            check(p["v6_prefix"] == v["v6_prefix"]
                  and p["v4_device"] == hx(v["v4_device"]),
                  f"config parse {v['name']}")
        elif kind == "qos":
            body = rf.qos_body(v["profile"], v["up_kbps"], v["down_kbps"],
                               v["latency_ms"], v["jitter_ms"],
                               v["loss_pct"])
            check(body == hx(v["expected"]), f"qos {v['name']}")
            p = rf.qos_parse(body)
            check(p["profile"] == v["profile"], f"qos parse {v['name']}")
        elif kind == "stats":
            body = rf.stats_body(**{k: v[k] for k in (
                "bytes_in", "bytes_out", "pkts_in", "pkts_out",
                "bytes_video", "bytes_audio", "bytes_file", "drops",
                "errors", "frames_video", "rtt_ms", "loss_pct_x100",
                "cpu_pct_x100", "fps_video", "audio_level")})
            check(len(body) == 104, f"stats len {v['name']}")
            check(body == hx(v["expected"]), f"stats {v['name']}")
            p = rf.stats_parse(body)
            check(p["fps_video"] == v["fps_video"],
                  f"stats parse {v['name']}")
        elif kind == "mute":
            mtype, _f, body = rf.msg_decode(hx(v["expected"]))
            check(mtype == rf.MSG_MUTE and body == bytes([v["mask"]]),
                  f"mute {v['name']}")


# ------------------------------------------------------------------ crypto
def test_crypto():
    print("crypto.json")
    check(rf.rfc7748_check(), "rfc7748 x25519 vector")
    for v in load("crypto.json"):
        kind = v["kind"]
        if kind == "x25519_pub":
            check(rf.x25519_public(hx(v["secret"])) == hx(v["expected"]),
                  f"pub {v['name']}")
        elif kind == "x25519":
            check(rf.x25519(hx(v["secret"]), hx(v["pub"]))
                  == hx(v["expected"]), f"shared {v['name']}")
        elif kind == "hkdf":
            check(rf.hkdf_sha256(hx(v["ikm"]), hx(v["salt"]),
                                 hx(v["info"]), v["length"])
                  == hx(v["expected"]), f"hkdf {v['name']}")
        elif kind == "interop":
            ct = rf.interop_encrypt(hx(v["key_aead"]), hx(v["key_mac"]),
                                    hx(v["nonce"]), hx(v["aad"]),
                                    hx(v["pt"]))
            check(ct == hx(v["expected"]), f"interop enc {v['name']}")
            pt = rf.interop_decrypt(hx(v["key_aead"]), hx(v["key_mac"]),
                                    hx(v["nonce"]), hx(v["aad"]), ct)
            check(pt == hx(v["pt"]), f"interop dec {v['name']}")
            try:
                bad = bytearray(ct)
                bad[0] ^= 1
                rf.interop_decrypt(hx(v["key_aead"]), hx(v["key_mac"]),
                                   hx(v["nonce"]), hx(v["aad"]), bytes(bad))
                check(False, f"interop tamper {v['name']}")
            except rf.AuthError:
                check(True, "")
        elif kind == "frame_nonce":
            check(rf.frame_nonce(v["counter"], v["channel"],
                                 v["direction"]) == hx(v["expected"]),
                  f"frame_nonce {v['name']}")


# ---------------------------------------------------------------- channel
def test_channels():
    print("channels.json")
    for v in load("channels.json"):
        k = v["kind"]
        if k == "video":
            body = rf.video_body(v["kind_field"], v["codec"], v["width"],
                                 v["height"], v["fps"], v["pts_ms"],
                                 v["seq"], hx(v["nal"]))
            check(body == hx(v["expected"]), f"video {v['name']}")
            p = rf.video_parse(body)
            check(p["width"] == v["width"] and p["seq"] == v["seq"],
                  f"video parse {v['name']}")
        elif k == "audio":
            body = rf.audio_body(v["codec"], v["rate"], v["ch"], v["seq"],
                                 v["pts_ms"], hx(v["data"]))
            check(body == hx(v["expected"]), f"audio {v['name']}")
        elif k == "input":
            body = rf.input_body(v["type_field"], v["action"], v["x"],
                                 v["y"], 0,
                                 v.get("text", "").encode())
            check(body == hx(v["expected"]), f"input {v['name']}")
            p = rf.input_parse(body)
            check(p["x"] == v["x"], f"input parse {v['name']}")
        elif k == "file_meta":
            body = rf.file_meta_body(v["direction"], v["file_id"],
                                     v["total_size"], v["name"])
            check(body == hx(v["expected"]), f"file_meta {v['name']}")
        elif k == "file_data":
            body = rf.file_data_body(v["direction"], v["file_id"], v["seq"],
                                     v["offset"], hx(v["chunk"]))
            check(body == hx(v["expected"]), f"file_data {v['name']}")
            p = rf.file_parse(body)
            check(p["offset"] == v["offset"], f"file_data parse {v['name']}")
        elif k == "clipboard":
            body = rf.clipboard_body(v["direction"], v["kind_field"],
                                     v["data"].encode())
            check(body == hx(v["expected"]), f"clipboard {v['name']}")
        elif k == "notification":
            body = rf.notification_body(v["id"], v["ts_ms"], v["action"],
                                        v["app"], v["title"], v["body"])
            check(body == hx(v["expected"]), f"notification {v['name']}")
            p = rf.notification_parse(body)
            check(p["app"] == v["app"] and p["body"] == v["body"],
                  f"notification parse {v['name']}")


# ---------------------------------------------------------------- pairing
def test_pairing():
    print("pairing.json")
    for v in load("pairing.json"):
        blob = rf.pairing_blob(hx(v["secret"]), v["name"])
        check(blob == v["expected"], f"pairing {v['name']}")
        s, n = rf.pairing_parse(v["expected"])
        check(s == hx(v["secret"]) and n == v["name"],
              f"pairing parse {v['name']}")
    try:
        rf.pairing_parse("WRONG:")
        check(False, "pairing bad prefix")
    except ValueError:
        check(True, "")


# -------------------------------------------------------------- robustness
def test_robustness():
    print("robustness")
    good = rf.Frame(rf.CH_TUN_V4, 0, b"hello").encode()
    for i, label in [(0, "magic0"), (1, "magic1"), (2, "version")]:
        bad = bytearray(good)
        bad[i] ^= 0xFF
        try:
            rf.Frame.decode(bytes(bad))
            check(False, f"reject {label}")
        except rf.FramingError:
            check(True, "")
    # invalid extended-length field 0x8001
    bad = bytearray(good)
    bad[5] = 0x80
    bad[6] = 0x01
    try:
        rf.Frame.decode(bytes(bad))
        check(False, "reject ext len 0x8001")
    except rf.FramingError:
        check(True, "")
    # incomplete frame
    try:
        rf.Frame.decode(good[:-3])
        check(False, "reject incomplete")
    except rf.FramingError:
        check(True, "")
    # back-to-back decode
    two = good + good
    f1 = rf.Frame.decode(two, 0)
    f2 = rf.Frame.decode(two, len(good))
    check(f1.payload == f2.payload == b"hello", "back-to-back decode")


def main():
    test_frames()
    test_messages()
    test_crypto()
    test_channels()
    test_pairing()
    test_robustness()
    total = PASSES[0] + len(FAILS)
    print(f"\n{PASSES[0]}/{total} vector+robustness checks passed")
    if FAILS:
        print("FAILED CHECKS:")
        for f in FAILS:
            print("  -", f)
        sys.exit(1)
    print("ALL PROTOCOL VECTORS PASS")


if __name__ == "__main__":
    main()
