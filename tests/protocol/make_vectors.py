#!/usr/bin/env python3
"""Generate canonical UniLink Protocol test vectors (protocol/vectors/*.json).

Deterministic inputs -> golden wire bytes. The Rust, Kotlin and Node/TS
codecs must reproduce these exactly. Re-run only when the spec changes;
the generated JSON is committed and validated in CI.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference_framing as rf

# ------------------------------------------------ fixed test constants
SECRET = bytes(range(32))                      # pairing secret (test only)
ALICE_PRIV = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
BOB_PRIV = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
ALICE_PUB = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_PUB = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
NONCE_A = bytes([0xA1, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
NONCE_B = bytes([0xB1, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])
FEATURES = 0x00FF
CIPHER = rf.CIPHER_INTEROP

def hx(b):
    return b.hex()

def e(_name, **fields):
    out = {"name": _name}
    out.update(fields)
    return out

def build():
    out = {}

    # ------------------------------------------------------------- frames
    frames = [
        e("ping_control", channel=rf.CH_CONTROL, flags=0,
          payload=hx(rf.msg_encode(rf.MSG_PING, (111).to_bytes(8, "big")))),
        e("video_keyframe", channel=rf.CH_VIDEO, flags=rf.F_PRIORITY,
          payload=hx(rf.video_body(0, 0, 1920, 1080, 60, 33, 7,
                                   bytes(range(256)) * 4))),
        e("audio_in", channel=rf.CH_AUDIO_IN, flags=0,
          payload=hx(rf.audio_body(0, 48000, 1, 5, 100, bytes(range(64))))),
        e("tun_v4", channel=rf.CH_TUN_V4, flags=0,
          payload=hx(bytes([0x45, 0, 0, 62, 0x12, 0x34, 0, 64, 1, 0, 0x00]
                           + [0] * 6 + [10, 8, 0, 1, 10, 8, 0, 2]
                           + [8, 0, 0, 0, 0, 1, 0, 2]
                           + list(b"abcdefgh")))),

        e("tun_v6", channel=rf.CH_TUN_V6, flags=0,
          payload=hx(bytes([0x60, 0, 0, 0, 0, 40, 58, 64])
                     + bytes.fromhex("fd004c55010000000000000000000001")
                     + bytes.fromhex("fd004c55010000000000000000000002")
                     + bytes([128, 0, 0, 0, 0, 1, 0, 2]) + b"xyz")),
        e("clipboard", channel=rf.CH_CLIPBOARD, flags=0,
          payload=hx(rf.clipboard_body(0, 0, "hello unilink".encode()))),
        e("extended_length_50k", channel=rf.CH_VIDEO, flags=0,
          payload=hx(rf.video_body(0, 0, 3840, 2160, 60, 0, 1,
                                   bytes(range(256)) * 195))),
    ]
    for f in frames:
        fr = rf.Frame(f["channel"], f["flags"], bytes.fromhex(f["payload"]))
        f["expected"] = hx(fr.encode())
    out["frames.json"] = frames

    # ----------------------------------------------------------- messages
    messages = [
        e("hello", kind="hello", role=rf.ROLE_HOST, feature_mask=FEATURES,
          cipher_pref=CIPHER, ecdh_pub=hx(ALICE_PUB),
          nonce_a=hx(NONCE_A), secret=hx(SECRET),
          expected=hx(rf.hello_body(rf.ROLE_HOST, FEATURES, CIPHER,
                                    ALICE_PUB, NONCE_A)
                      + rf.pairing_mac(SECRET, ALICE_PUB, NONCE_A))),
        e("hello_ack", kind="hello_ack", negotiated=0x00FF,
          cipher_sel=CIPHER, ecdh_pub=hx(BOB_PUB), nonce_b=hx(NONCE_B),
          nonce_a=hx(NONCE_A), secret=hx(SECRET),
          expected=hx(rf.hello_ack_body(0x00FF, CIPHER, BOB_PUB,
                                        NONCE_B, NONCE_A, SECRET))),
        e("auth_ok", kind="msg", mtype=rf.MSG_AUTH_OK, body=""),
        e("ping", kind="msg", mtype=rf.MSG_PING,
          body=hx((1712345678901).to_bytes(8, "big"))),
        e("config_dual_stack", kind="config", v4_prefix=20,
          v4_device=hx(bytes([10, 8, 0, 2])), v4_host=hx(bytes([10, 8, 0, 1])),
          v6_prefix=64,
          v6_device=hx(bytes.fromhex(
              "fd004c55010000000000000000000002")),
          v6_host=hx(bytes.fromhex(
              "fd004c55010000000000000000000001")),
          dns=[hx(bytes([1, 1, 1, 1])), hx(bytes([9, 9, 9, 9]))],
          routes=[[0, hx(bytes([0, 0, 0, 0]))], [64, hx(bytes([0, 0, 0, 0]))]]),
        e("qos_4g", kind="qos", profile=4, up_kbps=30000, down_kbps=50000,
          latency_ms=15, jitter_ms=0, loss_pct=0),
        e("qos_2g", kind="qos", profile=1, up_kbps=384, down_kbps=768,
          latency_ms=120, jitter_ms=20, loss_pct=2),
        e("stats", kind="stats", bytes_in=1000000, bytes_out=999999,
          pkts_in=5000, pkts_out=4999, bytes_video=123456, bytes_audio=789,
          bytes_file=10, drops=3, errors=0, frames_video=1800, rtt_ms=12,
          loss_pct_x100=5, cpu_pct_x100=1234, fps_video=60, audio_level=200),
        e("mute_all", kind="mute", mask=0x0F),
        e("bye", kind="msg", mtype=rf.MSG_BYE, body=hx(b"\x02")),
        e("error_auth", kind="msg", mtype=rf.MSG_ERROR,
          body=hx(bytes([11]) + (12).to_bytes(2, "big")
                  + "bad pairing".encode())),
    ]
    for m in messages:
        if m["kind"] == "msg":
            m["expected"] = hx(rf.msg_encode(m.pop("mtype"),
                                             bytes.fromhex(m.pop("body"))))
        elif m["kind"] == "hello":
            pass
        elif m["kind"] == "hello_ack":
            pass
        elif m["kind"] == "config":
            m["expected"] = hx(rf.config_body(
                m["v4_prefix"], bytes.fromhex(m["v4_device"]),
                bytes.fromhex(m["v4_host"]), m["v6_prefix"],
                bytes.fromhex(m["v6_device"]), bytes.fromhex(m["v6_host"]),
                [bytes.fromhex(d) for d in m["dns"]],
                [(p, bytes.fromhex(a)) for p, a in m["routes"]]))
        elif m["kind"] == "qos":
            m["expected"] = hx(rf.qos_body(m["profile"], m["up_kbps"],
                                           m["down_kbps"], m["latency_ms"],
                                           m["jitter_ms"], m["loss_pct"]))
        elif m["kind"] == "stats":
            m["expected"] = hx(rf.stats_body(**{k: m[k] for k in (
                "bytes_in", "bytes_out", "pkts_in", "pkts_out",
                "bytes_video", "bytes_audio", "bytes_file", "drops",
                "errors", "frames_video", "rtt_ms", "loss_pct_x100",
                "cpu_pct_x100", "fps_video", "audio_level")}))
        elif m["kind"] == "mute":
            m["expected"] = hx(rf.msg_encode(rf.MSG_MUTE,
                                             bytes([m["mask"]])))
    out["messages.json"] = messages

    # ------------------------------------------------------------- crypto
    shared = rf.x25519(ALICE_PRIV, BOB_PUB)
    ka, km = rf.session_keys(shared, NONCE_A, NONCE_B, CIPHER)
    nonce12 = rf.frame_nonce(7, rf.CH_TUN_V4, 0)
    pt = bytes(range(200))
    crypto = [
        e("rfc7748_public_alice", kind="x25519_pub",
          secret=hx(ALICE_PRIV), expected=hx(ALICE_PUB)),
        e("rfc7748_public_bob", kind="x25519_pub",
          secret=hx(BOB_PRIV), expected=hx(BOB_PUB)),
        e("rfc7748_shared", kind="x25519", secret=hx(ALICE_PRIV),
          pub=hx(BOB_PUB), expected=hx(rf.x25519(ALICE_PRIV, BOB_PUB))),
        e("rfc7748_shared_rev", kind="x25519", secret=hx(BOB_PRIV),
          pub=hx(ALICE_PUB),
          expected=hx(rf.x25519(BOB_PRIV, ALICE_PUB))),
        e("hkdf_session_keys", kind="hkdf", ikm=hx(shared),
          salt=hx(NONCE_A + NONCE_B), info=hx(rf.HKDF_INFO + b"\x01"),
          length=64, expected=hx(ka + km)),
        e("interop_aead", kind="interop", key_aead=hx(ka), key_mac=hx(km),
          nonce=hx(nonce12), aad=hx(b"\x55\x4c\x01\x09\x02" + (200).to_bytes(2, "big")),
          pt=hx(pt),
          expected=hx(rf.interop_encrypt(
              ka, km, nonce12,
              b"\x55\x4c\x01\x09\x02" + (200).to_bytes(2, "big"), pt))),
        e("frame_nonce_counter7", kind="frame_nonce", counter=7,
          channel=rf.CH_TUN_V4, direction=0, expected=hx(nonce12)),
    ]
    out["crypto.json"] = crypto

    # ------------------------------------------------------------- channel
    channels = [
        e("video_key_1080p60", kind="video", kind_field=0, codec=0,
          width=1920, height=1080, fps=60, pts_ms=33, seq=7,
          nal=hx(bytes([0, 33, 24, 8, 16]) + bytes(range(100)))),
        e("video_delta", kind="video", kind_field=1, codec=0,
          width=1920, height=1080, fps=60, pts_ms=50, seq=8,
          nal=hx(bytes(range(48)))),
        e("audio_opus", kind="audio", codec=0, rate=48000, ch=1, seq=5,
          pts_ms=100, data=hx(bytes(range(64)))),
        e("input_touch_down", kind="input", type_field=0, action=0, x=512,
          y=733),
        e("input_text", kind="input", type_field=3, action=0, x=0, y=0,
          text="hi ünïtëther"),
        e("file_meta", kind="file_meta", direction=0, file_id=42,
          total_size=123456, name="notes.txt"),
        e("file_data", kind="file_data", direction=0, file_id=42, seq=3,
          offset=98304, chunk=hx(bytes([0xDE, 0xAD, 0xBE, 0xEF]) * 16)),
        e("clipboard_text", kind="clipboard", direction=0, kind_field=0,
          data="clipboard payload"),
        e("notification_post", kind="notification", id=7, ts_ms=1712345678901,
          action=0, app="com.example.msgs", title="Alice",
          body="Hello from the phone!"),
    ]
    for c in channels:
        k = c["kind"]
        if k == "video":
            c["expected"] = hx(rf.video_body(c["kind_field"], c["codec"],
                                             c["width"], c["height"],
                                             c["fps"], c["pts_ms"], c["seq"],
                                             bytes.fromhex(c["nal"])))
        elif k == "audio":
            c["expected"] = hx(rf.audio_body(c["codec"], c["rate"], c["ch"],
                                             c["seq"], c["pts_ms"],
                                             bytes.fromhex(c["data"])))
        elif k == "input":
            c["expected"] = hx(rf.input_body(c["type_field"], c["action"],
                                             c["x"], c["y"], 0,
                                             c.get("text", "").encode()))
        elif k == "file_meta":
            c["expected"] = hx(rf.file_meta_body(c["direction"],
                                                 c["file_id"],
                                                 c["total_size"], c["name"]))
        elif k == "file_data":
            c["expected"] = hx(rf.file_data_body(c["direction"], c["file_id"],
                                                 c["seq"], c["offset"],
                                                 bytes.fromhex(c["chunk"])))
        elif k == "clipboard":
            c["expected"] = hx(rf.clipboard_body(c["direction"],
                                                 c["kind_field"],
                                                 c["data"].encode()))
        elif k == "notification":
            c["expected"] = hx(rf.notification_body(c["id"], c["ts_ms"],
                                                    c["action"], c["app"],
                                                    c["title"], c["body"]))
    out["channels.json"] = channels

    # ---------------------------------------------------------- handshake
    out["pairing.json"] = [
        e("pairing_blob", kind="pairing", secret=hx(SECRET), name="my-pc",
          expected=rf.pairing_blob(SECRET, "my-pc")),
        e("pairing_blob_urdu", kind="pairing", secret=hx(SECRET),
          name="فون-١",
          expected=rf.pairing_blob(SECRET, "فون-١")),
    ]
    return out


def main():
    data = build()
    dest = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "protocol", "vectors")
    os.makedirs(dest, exist_ok=True)
    for name, vecs in data.items():
        path = os.path.join(dest, name)
        with open(path, "w") as fh:
            json.dump({"protocol": "unilink", "version": 1, "vectors": vecs},
                      fh, indent=1, ensure_ascii=False)
        print(f"wrote {path} ({len(vecs)} vectors)")


if __name__ == "__main__":
    main()
