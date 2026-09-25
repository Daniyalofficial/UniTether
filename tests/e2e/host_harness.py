#!/usr/bin/env python3
"""Host-side E2E harness — drives a full ULP session against a device.

Scenario (mirrors the MVP acceptance script for protocol purposes):
  1. TCP connect -> X25519 handshake with pairing MAC (both verified)
  2. CONFIG (dual-stack v4+v6+DNS+routes) -> TUN_UP
  3. real IPv4 ICMP echo request  -> device must reply (checksums checked)
  4. real IPv6 ICMPv6 echo request -> device must reply (pseudo-hdr checked)
  5. PING/PONG RTT measurement
  6. receive video (keyframe first), audio, clipboard, notification
  7. send QOS(4G), MUTE(video), INPUT(touch+text), CLIPBOARD(h->d)
  8. STATS_REQ -> STATS_RSP (104-byte struct)
  9. clean BYE both ways

Usage: host_harness.py --port NNNN --secret HEX
Exit 0 = PASS. Prints a scenario table.
"""
from __future__ import annotations

import os

import argparse
import socket
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "protocol"))
import reference_framing as rf
from device_sim import icmpv6_checksum, ip_checksum
sys.path.insert(0, _HERE)
sys.path.insert(0, _HERE)
from ulp_link import Link, Session, ULPError  # noqa: E402

RESULTS = []


def report(step: str, ok: bool, detail: str = ""):
    RESULTS.append((step, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {step}" + (f"  [{detail}]"
                                                     if detail else ""),
          flush=True)


def build_ipv4_echo(seq: int, data: bytes) -> bytes:
    icmp = bytes([8, 0, 0, 0]) + (0x1234).to_bytes(2, "big") \
        + seq.to_bytes(2, "big") + data
    icmp = icmp[:2] + ip_checksum(icmp).to_bytes(2, "big") + icmp[4:]
    payload_len = len(icmp)
    hdr = bytearray(20)
    hdr[0] = 0x45
    hdr[2:4] = (20 + payload_len).to_bytes(2, "big")
    hdr[4:6] = (0xBEEF).to_bytes(2, "big")
    hdr[8] = 64                    # TTL
    hdr[9] = 1                     # proto = ICMP
    hdr[10:12] = ip_checksum(bytes(hdr)).to_bytes(2, "big")
    hdr[12:16] = bytes([10, 8, 0, 1])     # host tunnel addr
    hdr[16:20] = bytes([10, 8, 0, 2])     # device tunnel addr
    return bytes(hdr) + icmp


def build_ipv6_echo(seq: int, data: bytes) -> bytes:
    icmp = bytes([128, 0, 0, 0]) + (0x1234).to_bytes(2, "big") \
        + seq.to_bytes(2, "big") + data
    src = bytes.fromhex("fd004c55010000000000000000000001")
    dst = bytes.fromhex("fd004c55010000000000000000000002")
    csum = icmpv6_checksum(icmp, src, dst)
    icmp = icmp[:2] + csum.to_bytes(2, "big") + icmp[4:]
    hdr = (bytes([0x60, 0, 0, 0])          # v6 + tclass + flow
           + len(icmp).to_bytes(2, "big")  # payload length
           + bytes([58, 64])              # next-hdr ICMPv6, hop limit
           + src + dst)
    return hdr + icmp


def verify_ipv4_reply(pkt: bytes, seq: int, data: bytes) -> bool:
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return False
    ihl = (pkt[0] & 0xF) * 4
    if pkt[9] != 1:
        return False
    if ip_checksum(pkt[:ihl]) != 0:
        return False
    icmp = pkt[ihl:]
    if len(icmp) < 8 or icmp[0] != 0:
        return False
    if ip_checksum(icmp) != 0:
        return False
    if icmp[4:6] != (0x1234).to_bytes(2, "big") or icmp[6:8] != seq.to_bytes(2, "big"):
        return False
    return icmp[8:] == data


def verify_ipv6_reply(pkt: bytes, seq: int, data: bytes) -> bool:
    if len(pkt) < 48 or pkt[0] >> 4 != 6:
        return False
    if pkt[6] != 58:
        return False
    src, dst = pkt[8:24], pkt[24:40]
    icmp = pkt[40:]
    if len(icmp) < 8 or icmp[0] != 129:
        return False
    if icmpv6_checksum(icmp, src, dst) != 0:
        return False
    if icmp[4:6] != (0x1234).to_bytes(2, "big") or icmp[6:8] != seq.to_bytes(2, "big"):
        return False
    return icmp[8:] == data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--secret", required=True)
    a = ap.parse_args()
    secret = bytes.fromhex(a.secret)
    priv = bytes.fromhex(
        "0102030405060708090a0b0c0d0e0f10"
        "1112131415161718191a1b1c1d1e1f20")

    t0 = time.time()
    sock = socket.create_connection(("127.0.0.1", a.port), timeout=30)
    sess = Session(sock, rf.ROLE_HOST, secret, priv, "harness")
    sess.link = Link(sock, 0, b"\x00" * 32, b"\x00" * 32)
    try:
        sess.start_host()
        report("handshake (X25519 + pairing MAC)", True)
    except (ULPError, rf.ProtocolError) as e:
        report("handshake (X25519 + pairing MAC)", False, str(e))
        return 1

    link = sess.link
    link.send_msg(rf.MSG_CONFIG, rf.config_body(
        20, bytes([10, 8, 0, 2]), bytes([10, 8, 0, 1]), 64,
        bytes.fromhex("fd004c55010000000000000000000002"),
        bytes.fromhex("fd004c55010000000000000000000001"),
        [bytes([1, 1, 1, 1])],
        [(0, bytes([0, 0, 0, 0])), (64, bytes([0, 0, 0, 0]))]))
    link.send_msg(rf.MSG_TUN_UP, b"")
    report("CONFIG (dual-stack) + TUN_UP sent", True)

    # ---- receive proactive media while probing the tunnel
    video_frames, audio_frames = [], []
    clip_device, notif = None, None
    tun_reply4 = tun_reply6 = None
    pong = None
    stats = None
    clip_host_ack = False

    # send the probes, then read frames until we have what we need
    v4_data = b"UNITETHER-ECHO-4"
    v6_data = b"UNITETHER-ECHO-6"
    link.send_frame(rf.CH_TUN_V4, 0, build_ipv4_echo(7, v4_data))
    link.send_frame(rf.CH_TUN_V6, 0, build_ipv6_echo(9, v6_data))
    t_ping = time.time()
    link.send_msg(rf.MSG_PING, (int(t_ping * 1e9) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big"))
    link.send_msg(rf.MSG_QOS, rf.qos_body(4, 30000, 50000, 15, 0, 0))
    link.send_msg(rf.MSG_MUTE, bytes([0x01]))
    link.send_frame(rf.CH_INPUT, 0, rf.input_body(0, 0, 512, 733))
    link.send_frame(rf.CH_INPUT, 0, rf.input_body(3, 0, 0, 0, 0,
                                                  "typed from host".encode()))
    link.send_frame(rf.CH_CLIPBOARD, 0, rf.clipboard_body(1, 0,
                                                          "host→device text".encode()))
    link.send_msg(rf.MSG_STATS_REQ, b"")

    deadline = time.time() + 20
    while time.time() < deadline:
        have = (len(video_frames) >= 2 and len(audio_frames) >= 2
                and tun_reply4 and tun_reply6 and pong is not None
                and stats and clip_device and notif)
        if have:
            break
        try:
            frame = link.recv_frame(expect_encrypted=True)
        except ULPError as e:
            report("media/tunnel receive", False, str(e))
            return 1
        if frame.channel == rf.CH_VIDEO:
            video_frames.append(rf.video_parse(frame.payload))
        elif frame.channel == rf.CH_AUDIO_IN:
            audio_frames.append(rf.audio_parse(frame.payload))
        elif frame.channel == rf.CH_TUN_V4 and tun_reply4 is None:
            tun_reply4 = frame.payload
        elif frame.channel == rf.CH_TUN_V6 and tun_reply6 is None:
            tun_reply6 = frame.payload
        elif frame.channel == rf.CH_CLIPBOARD and clip_device is None:
            clip_device = rf.clipboard_parse(frame.payload)
        elif frame.channel == rf.CH_NOTIFICATION and notif is None:
            notif = rf.notification_parse(frame.payload)
        elif frame.channel == rf.CH_CONTROL:
            mtype, _f, body = rf.msg_decode(frame.payload)
            if mtype == rf.MSG_PONG and pong is None:
                pong = time.time()
            elif mtype == rf.MSG_STATS_RSP and stats is None:
                stats = rf.stats_parse(body)
            elif mtype == rf.MSG_BYE:
                pass
        if frame.channel == rf.CH_CLIPBOARD and frame.payload[0] == 0:
            clip_host_ack = True

    report("video frames received (2x, keyframe first)",
           len(video_frames) >= 2 and video_frames[0]["kind"] == 0
           and video_frames[0]["width"] == 1920,
           f"{len(video_frames)} frames, seq={[v['seq'] for v in video_frames]}")
    report("audio frames received (2x opus 48k mono)",
           len(audio_frames) >= 2
           and audio_frames[0]["codec"] == 0
           and audio_frames[0]["rate"] == 48000,
           f"{len(audio_frames)} frames")
    ok4 = tun_reply4 is not None and verify_ipv4_reply(tun_reply4, 7, v4_data)
    report("IPv4 ICMP echo round-trip (tunnel)", ok4,
           f"{len(tun_reply4)} B reply, checksums verified" if ok4
           else f"reply={tun_reply4.hex()[:40] if tun_reply4 else 'none'}")
    ok6 = tun_reply6 is not None and verify_ipv6_reply(tun_reply6, 9, v6_data)
    report("IPv6 ICMPv6 echo round-trip (tunnel)", ok6,
           f"{len(tun_reply6)} B reply, pseudo-header verified" if ok6
           else f"reply={tun_reply6.hex()[:40] if tun_reply6 else 'none'}")
    rtt_ms = (pong - t_ping) * 1000 if pong else -1
    report("PING/PONG RTT", pong is not None, f"{rtt_ms:.2f} ms")
    report("clipboard device→host", bool(clip_device),
           f"{clip_device['data']!r}" if clip_device else "missing")
    report("notification device→host", bool(notif),
           f"app={notif['app']!r} title={notif['title']!r}" if notif
           else "missing")
    report("STATS_RSP (104-byte struct)",
           bool(stats) and stats["frames_video"] == 2 and stats["rtt_ms"] == 3)

    # clean shutdown
    link.send_msg(rf.MSG_BYE, bytes([0]))
    bye = None
    try:
        for _ in range(3):
            frame = link.recv_frame(expect_encrypted=True)
            if frame.channel == rf.CH_CONTROL:
                mtype, _f, _b = rf.msg_decode(frame.payload)
                if mtype == rf.MSG_BYE:
                    bye = True
                    break
    except (ULPError, rf.ProtocolError):
        pass
    report("clean BYE both ways", bool(bye))

    sock.close()
    dt = time.time() - t0
    fails = [s for s, ok in RESULTS if not ok]
    print(f"\n{'E2E RESULT: ' + ('PASS' if not fails else 'FAIL')} "
          f"({len(RESULTS) - len(fails)}/{len(RESULTS)} steps, "
          f"{dt:.2f}s wall)", flush=True)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
