#!/usr/bin/env python3
"""ULP session link over a TCP socket — shared by device_sim and host_harness.

Implements exactly what the production Rust/Kotlin stacks do:
  * pre-handshake plaintext CONTROL frames (HELLO / HELLO_ACK / AUTH_OK)
  * post-handshake AEAD-encrypted frames (INTEROP cipher profile)
  * per-direction nonce counters, AAD = full frame header
"""
from __future__ import annotations

import os
import socket
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "protocol"))
sys.path.insert(0, _HERE)
import reference_framing as rf  # noqa: E402


class ULPError(Exception):
    pass


class Link:
    def __init__(self, sock: socket.socket, direction: int,
                 ka: bytes, km: bytes, encrypted: bool = False):
        self.sock = sock
        self.direction = direction          # 0 host, 1 device
        self.ka = ka                        # key_aead
        self.km = km                        # key_mac
        self.tx_counter = 0
        self.rx_counter = 0
        self.buf = b""
        self.deadline = 30.0
        self.encrypted = encrypted

    # ------------------------------------------------------------ I/O
    def _recv_exact(self, n: int) -> bytes:
        self.sock.settimeout(self.deadline)
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ULPError("peer closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_frame(self, channel: int, flags: int, payload: bytes,
                   encrypted: bool = None) -> None:
        if encrypted is None:
            encrypted = self.encrypted
        if encrypted:
            nonce = rf.frame_nonce(self.tx_counter, channel, self.direction)
            self.tx_counter += 1
            wire_len = len(payload) + 16      # + AEAD tag
            if wire_len >= 0x8000:
                header = (bytes([rf.MAGIC0, rf.MAGIC1, rf.VERSION, channel,
                                 flags | rf.F_ENCRYPTED])
                          + (0x8000).to_bytes(2, "big")
                          + wire_len.to_bytes(4, "big"))
            else:
                header = (bytes([rf.MAGIC0, rf.MAGIC1, rf.VERSION, channel,
                                 flags | rf.F_ENCRYPTED])
                          + wire_len.to_bytes(2, "big"))
            # AAD = the exact wire header (spec 7.5)
            ct = rf.interop_encrypt(self.ka, self.km, nonce, header, payload)
            assert len(ct) == wire_len
            self.sock.sendall(header + ct)
        else:
            frame = rf.Frame(channel, flags, payload)
            self.sock.sendall(frame.encode())

    def recv_frame(self, expect_encrypted: bool = None) -> rf.Frame:
        if expect_encrypted is None:
            expect_encrypted = self.encrypted
        hdr = self._recv_exact(7)
        ln = int.from_bytes(hdr[5:7], "big")
        if ln == 0x8000:
            hdr += self._recv_exact(4)
        if ln == 0x8000:
            size = int.from_bytes(hdr[7:11], "big")
        else:
            size = ln
        payload = self._recv_exact(size)
        if hdr[0] != rf.MAGIC0 or hdr[1] != rf.MAGIC1:
            raise ULPError("bad magic")
        if hdr[2] != rf.VERSION:
            raise ULPError("bad version")
        channel, flags = hdr[3], hdr[4]
        if bool(flags & rf.F_ENCRYPTED) != expect_encrypted:
            raise ULPError(
                f"encryption state mismatch (expected encrypted="
                f"{expect_encrypted}) hdr={hdr.hex()}")
        if flags & rf.F_ENCRYPTED:
            nonce = rf.frame_nonce(self.rx_counter, channel, 1 - self.direction)
            self.rx_counter += 1
            payload = rf.interop_decrypt(self.ka, self.km, nonce, hdr, payload)
        return rf.Frame(channel, flags & ~rf.F_ENCRYPTED, payload)

    def _peek(self, n: int) -> bytes:
        return self.buf[:n]

    # -------------------------------------------------- control helpers
    def send_msg(self, mtype: int, body: bytes, encrypted: bool = None):
        if encrypted is None:
            encrypted = self.encrypted
        self.send_frame(rf.CH_CONTROL, 0, rf.msg_encode(mtype, body), encrypted)

    def recv_msg(self, encrypted: bool = None) -> tuple:
        if encrypted is None:
            encrypted = self.encrypted
        while True:
            f = self.recv_frame(expect_encrypted=encrypted)
            if f.channel != rf.CH_CONTROL:
                raise ULPError(f"expected control, got channel {f.channel:#x}")
            return rf.msg_decode(f.payload)


class Session:
    """Handshake + encrypted session, either role."""

    def __init__(self, sock, role, secret, priv, name=""):
        self.role = role
        self.secret = secret
        self.priv = priv
        self.pub = rf.x25519_public(priv)
        self.nonce_a = (b"\x00" * 16) if role == rf.ROLE_HOST else None
        self.nonce_b = None
        self.features = 0x00FF
        self.link: Link = None

    def start_host(self) -> None:
        """Host initiates: sends HELLO, verifies HELLO_ACK, AUTH_OK."""
        self.nonce_a = _rand16()
        hello = (rf.hello_body(self.role, self.features, rf.CIPHER_INTEROP,
                               self.pub, self.nonce_a)
                 + rf.pairing_mac(self.secret, self.pub, self.nonce_a))
        assert self.link is not None, "set Session.link before start"
        self.link.send_msg(rf.MSG_HELLO, hello, encrypted=False)
        mtype, _f, body = self.link.recv_msg(encrypted=False)
        if mtype != rf.MSG_HELLO_ACK:
            raise ULPError(f"expected HELLO_ACK, got {mtype:#x}")
        ack = rf.hello_ack_verify(body, self.secret, self.nonce_a)
        shared = rf.x25519(self.priv, ack["ecdh_pub"])
        ka, km = rf.session_keys(shared, self.nonce_a, ack["nonce_b"],
                                 ack["cipher_sel"])
        self.link.ka, self.link.km = ka, km
        self.link.send_msg(rf.MSG_AUTH_OK, b"")
        mtype, _f, _b = self.link.recv_msg(encrypted=False)
        if mtype != rf.MSG_AUTH_OK:
            raise ULPError("missing peer AUTH_OK")
        self.link.encrypted = True
        self.peer_features = ack["negotiated"]

    def start_device(self) -> None:
        """Device responds: verifies HELLO, sends HELLO_ACK + AUTH_OK."""
        mtype, _f, body = self.link.recv_msg(encrypted=False)
        if mtype != rf.MSG_HELLO:
            raise ULPError(f"expected HELLO, got {mtype:#x}")
        hello = rf.hello_verify(body, self.secret)
        self.nonce_a = hello["nonce_a"]
        self.nonce_b = _rand16()
        sel = rf.CIPHER_INTEROP
        ack = rf.hello_ack_body(self.features, sel, self.pub, self.nonce_b,
                                self.nonce_a, self.secret)
        self.link.send_msg(rf.MSG_HELLO_ACK, ack, encrypted=False)
        shared = rf.x25519(self.priv, hello["ecdh_pub"])
        ka, km = rf.session_keys(shared, self.nonce_a, self.nonce_b, sel)
        self.link.ka, self.link.km = ka, km
        self.link.send_msg(rf.MSG_AUTH_OK, b"")
        mtype, _f, _b = self.link.recv_msg(encrypted=False)
        if mtype != rf.MSG_AUTH_OK:
            raise ULPError("missing peer AUTH_OK")
        self.link.encrypted = True
        self.peer_role = hello["role"]
        self.peer_features = hello["feature_mask"]


def _rand16() -> bytes:
    import os
    return os.urandom(16)
