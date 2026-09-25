#!/usr/bin/env python3
"""Simulated UniTether *device* — full ULP protocol endpoint over TCP.

Implements the device side of docs/02-PROTOCOL.md well enough to be a
hardware-free stand-in for the Android app in integration tests:
  * X25519 + pairing-MAC handshake
  * CONFIG / TUN_UP handling
  * real IPv4/IPv6 ICMP echo responder on the tunnel channels
  * video/audio/clipboard/notification producers
  * PING/PONG, STATS, QOS, MUTE, INPUT, BYE

Usage: device_sim.py --port NNNN --secret HEX [--name NAME]
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "protocol"))
import reference_framing as rf
sys.path.insert(0, _HERE)
sys.path.insert(0, _HERE)
from ulp_link import Link, Session, ULPError  # noqa: E402


# ------------------------------------------------------------- ICMP utils
def ip_checksum(hdr: bytes) -> int:
    if len(hdr) % 2:
        hdr += b"\x00"
    s = sum(struct.unpack(f">{len(hdr)//2}H", hdr))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv4_echo_reply(pkt: bytes) -> bytes:
    if len(pkt) < 20:
        return b""
    ver_ihl = pkt[0]
    if (ver_ihl >> 4) != 4:
        return b""
    ihl = (ver_ihl & 0xF) * 4
    if pkt[9] != 1:            # not ICMP
        return b""
    icmp = pkt[ihl:]
    if len(icmp) < 8 or icmp[0] != 8:   # not echo request
        return b""
    hdr = bytearray(pkt[:ihl])
    hdr[8] = pkt[8]             # TTL
    src, dst = pkt[12:16], pkt[16:20]
    hdr[12:16], hdr[16:20] = dst, src
    hdr[10:12] = b"\x00\x00"
    hdr[10:12] = ip_checksum(bytes(hdr)).to_bytes(2, "big")
    rep = bytearray(icmp)
    rep[0] = 0                  # echo reply
    rep[2:4] = b"\x00\x00"
    rep[2:4] = ip_checksum(bytes(rep)).to_bytes(2, "big")
    return bytes(hdr) + bytes(rep)


def icmpv6_checksum(msg: bytes, src: bytes, dst: bytes) -> int:
    plen = len(msg)
    pseudo = src + dst + struct.pack(">IBBH", plen, 0, 0, 58)
    data = pseudo + msg
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv6_echo_reply(pkt: bytes) -> bytes:
    if len(pkt) < 48 or pkt[0] >> 4 != 6:
        return b""
    if pkt[6] != 58:            # not ICMPv6
        return b""
    src, dst = pkt[8:24], pkt[24:40]
    icmp = pkt[40:]
    if len(icmp) < 8 or icmp[0] != 128:
        return b""
    hdr = bytearray(pkt[:40])
    hdr[40:40] = b""
    rep = bytearray(icmp)
    rep[0] = 129                # echo reply
    rep[2:4] = b"\x00\x00"
    rep[2:4] = icmpv6_checksum(bytes(rep), dst, src).to_bytes(2, "big")
    return bytes(hdr) + bytes(rep)


# ------------------------------------------------------------- session
def run(port: int, secret: bytes, name: str) -> int:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(60)
    print(f"[device] listening on 127.0.0.1:{port} name={name!r}", flush=True)
    try:
        sock, _ = srv.accept()
    except socket.timeout:
        print("[device] timed out waiting for host", flush=True)
        return 2
    finally:
        srv.close()

    priv = os.urandom(32)
    sess = Session(sock, rf.ROLE_DEVICE, secret, priv, name)
    sess.link = Link(sock, 1, b"\x00" * 32, b"\x00" * 32)
    sess.start_device()
    print("[device] handshake ok (X25519 + pairing MAC verified)", flush=True)

    link = sess.link
    # ---- wait for CONFIG then TUN_UP
    cfg = None
    tun_up = False
    while not (cfg and tun_up):
        mtype, _f, body = link.recv_msg()
        if mtype == rf.MSG_CONFIG:
            cfg = rf.config_parse(body)
            print(f"[device] config v4=10.8.0.2/{cfg['v4_prefix']} "
                  f"v6_prefix={cfg['v6_prefix']} dns={len(cfg['dns'])} "
                  f"routes={len(cfg['routes'])}", flush=True)
        elif mtype == rf.MSG_TUN_UP:
            tun_up = True
            print("[device] tunnel up", flush=True)
        elif mtype == rf.MSG_PING:
            link.send_msg(rf.MSG_PONG, body)

    # ---- proactive media
    link.send_frame(rf.CH_VIDEO, rf.F_PRIORITY, rf.video_body(
        0, 0, 1920, 1080, 60, 0, 1, b"\x00\x01\x42SPS" + bytes(range(120))))
    link.send_frame(rf.CH_VIDEO, rf.F_PRIORITY, rf.video_body(
        1, 0, 1920, 1080, 60, 33, 2, bytes(range(96))))
    link.send_frame(rf.CH_AUDIO_IN, 0, rf.audio_body(
        0, 48000, 1, 1, 20, bytes(range(50))))
    link.send_frame(rf.CH_AUDIO_IN, 0, rf.audio_body(
        0, 48000, 1, 2, 40, bytes(range(50, 100))))
    link.send_frame(rf.CH_CLIPBOARD, 0,
                    rf.clipboard_body(0, 0, "from device 📱".encode()))
    link.send_frame(rf.CH_NOTIFICATION, 0, rf.notification_body(
        1, 1_700_000_000_000, 0, "com.example.sms", "Bob", "hi there"))
    print("[device] sent video/audio/clipboard/notification", flush=True)

    # ---- main loop
    video_seen = 0
    audio_seen = 0
    got_qos = got_mute = got_input = got_clip = got_stats_req = False
    exit_code = 0
    try:
        while True:
            frame = link.recv_frame(expect_encrypted=True)
            if frame.channel == rf.CH_TUN_V4:
                reply = ipv4_echo_reply(frame.payload)
                if reply:
                    link.send_frame(rf.CH_TUN_V4, 0, reply)
                    print(f"[device] ICMPv4 echo reply "
                          f"({len(reply)} B)", flush=True)
            elif frame.channel == rf.CH_TUN_V6:
                reply = ipv6_echo_reply(frame.payload)
                if reply:
                    link.send_frame(rf.CH_TUN_V6, 0, reply)
                    print(f"[device] ICMPv6 echo reply "
                          f"({len(reply)} B)", flush=True)
            elif frame.channel == rf.CH_CONTROL:
                mtype, _f, body = rf.msg_decode(frame.payload)
                if mtype == rf.MSG_PING:
                    link.send_msg(rf.MSG_PONG, body)
                elif mtype == rf.MSG_QOS:
                    q = rf.qos_parse(body)
                    got_qos = True
                    print(f"[device] QOS applied: profile={q['profile']} "
                          f"up={q['up_kbps']}kbps down={q['down_kbps']}kbps "
                          f"lat={q['latency_ms']}ms", flush=True)
                elif mtype == rf.MSG_MUTE:
                    got_mute = body[0]
                    print(f"[device] MUTE mask={body[0]:#04x}", flush=True)
                elif mtype == rf.MSG_STATS_REQ:
                    got_stats_req = True
                    link.send_msg(rf.MSG_STATS_RSP, rf.stats_body(
                        bytes_in=1234, bytes_out=567, pkts_in=8, pkts_out=9,
                        bytes_video=4096, bytes_audio=100, bytes_file=0,
                        drops=0, errors=0, frames_video=2, rtt_ms=3,
                        loss_pct_x100=0, cpu_pct_x100=2500, fps_video=60,
                        audio_level=128))
                elif mtype == rf.MSG_BYE:
                    link.send_msg(rf.MSG_BYE, bytes([0]))
                    print("[device] session closed cleanly", flush=True)
                    return 0
            elif frame.channel == rf.CH_INPUT:
                got_input = True
                i = rf.input_parse(frame.payload)
                print(f"[device] input: type={i['type']} "
                      f"action={i['action']} ({i['x']},{i['y']}) "
                      f"text={i['text']!r}", flush=True)
            elif frame.channel == rf.CH_CLIPBOARD:
                c = rf.clipboard_parse(frame.payload)
                if c["direction"] == 1:
                    got_clip = True
                    print(f"[device] clipboard h->d: {c['data']!r}",
                          flush=True)
    except (ULPError, rf.ProtocolError) as e:
        print(f"[device] protocol error: {e}", flush=True)
        exit_code = 3
    finally:
        try:
            link.send_msg(rf.MSG_BYE, bytes([0]))
        except Exception:
            pass
        sock.close()
    missing = [n for n, v in (
        ("qos", got_qos), ("mute", got_mute), ("input", got_input),
        ("clipboard", got_clip), ("stats_req", got_stats_req)) if not v]
    if missing:
        print(f"[device] WARNING missing: {missing}", flush=True)
    return exit_code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--secret", required=True, help="32-byte hex pairing secret")
    ap.add_argument("--name", default="sim-device")
    a = ap.parse_args()
    sys.exit(run(a.port, bytes.fromhex(a.secret), a.name))


if __name__ == "__main__":
    main()
