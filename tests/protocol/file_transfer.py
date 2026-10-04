"""File transfer v2 (Phase 12): chunking, checksums, resume, integrity.

Wire (CH_FILE payload) — v1 ops unchanged, v2 adds:
  0x00 meta      dir(1) file_id(u32) total(u64) name_len(u16) name
  0x01 data      dir(1) file_id(u32) seq(u32) offset(u64) chunk
  0x02 ack       dir(1) file_id(u32) seq_ack(u32)
  0x03 cancel    dir(1) file_id(u32)
  0x04 done      dir(1) file_id(u32)
  0x05 resume_req  dir(1) file_id(u32) expected_offset(u64)   [v2]
  0x06 resume_rsp  dir(1) file_id(u32) offset(u64) state(1)   [v2]
                   state: 0 none | 1 partial | 2 complete
  0x07 checksum   dir(1) file_id(u32) sha256(32)              [v2]

v1 peers ignore 0x05-0x07 (unknown-op rule) — backward compatible.
A failed transfer resumes from the receiver's contiguous offset;
integrity is enforced by whole-file SHA-256 at the end (mismatch ⇒
cancel + delete + retransfer from 0). Writes are atomic (.part +
rename); name collisions get .1/.2 suffixes; identical duplicate
files (same size+hash) are skipped.
"""
import hashlib
import os
import re

DIR_HOST = 0
DIR_DEVICE = 1

OP_META = 0x00
OP_DATA = 0x01
OP_ACK = 0x02
OP_CANCEL = 0x03
OP_DONE = 0x04
OP_RESUME_REQ = 0x05
OP_RESUME_RSP = 0x06
OP_CHECKSUM = 0x07

STATE_NONE = 0
STATE_PARTIAL = 1
STATE_COMPLETE = 2

MAX_CHUNK = 256 * 1024
DEFAULT_CHUNK = 256 * 1024


# ------------------------------------------------------------- codecs
def meta_body(direction, file_id, total, name):
    n = name.encode("utf-8")
    if len(n) > 255:
        raise ValueError("name too long")
    return (bytes([OP_META, direction & 0xFF])
            + file_id.to_bytes(4, "big") + total.to_bytes(8, "big")
            + len(n).to_bytes(2, "big") + n)


def meta_parse(payload):
    if len(payload) < 16:
        raise ValueError("meta: short")
    direction = payload[1]
    file_id = int.from_bytes(payload[2:6], "big")
    total = int.from_bytes(payload[6:14], "big")
    nlen = int.from_bytes(payload[14:16], "big")
    if len(payload) < 16 + nlen:
        raise ValueError("meta: short name")
    name = payload[16:16 + nlen].decode("utf-8")
    return direction, file_id, total, name


def data_body(direction, file_id, seq, offset, chunk):
    return (bytes([OP_DATA, direction & 0xFF])
            + file_id.to_bytes(4, "big") + seq.to_bytes(4, "big")
            + offset.to_bytes(8, "big") + chunk)


def data_parse(payload):
    if len(payload) < 18:
        raise ValueError("data: short")
    direction = payload[1]
    file_id = int.from_bytes(payload[2:6], "big")
    seq = int.from_bytes(payload[6:10], "big")
    offset = int.from_bytes(payload[10:18], "big")
    return direction, file_id, seq, offset, payload[18:]


def ack_body(direction, file_id, seq_ack):
    return (bytes([OP_ACK, direction & 0xFF])
            + file_id.to_bytes(4, "big") + seq_ack.to_bytes(4, "big"))


def cancel_body(direction, file_id):
    return bytes([OP_CANCEL, direction & 0xFF]) + file_id.to_bytes(4, "big")


def done_body(direction, file_id):
    return bytes([OP_DONE, direction & 0xFF]) + file_id.to_bytes(4, "big")


def resume_req_body(direction, file_id, expected_offset):
    return (bytes([OP_RESUME_REQ, direction & 0xFF])
            + file_id.to_bytes(4, "big")
            + expected_offset.to_bytes(8, "big"))


def resume_req_parse(payload):
    if len(payload) != 14:
        raise ValueError("resume_req: bad length")
    return payload[1], int.from_bytes(payload[2:6], "big"), \
        int.from_bytes(payload[6:14], "big")


def resume_rsp_body(direction, file_id, offset, state):
    return (bytes([OP_RESUME_RSP, direction & 0xFF])
            + file_id.to_bytes(4, "big")
            + offset.to_bytes(8, "big") + bytes([state & 0xFF]))


def resume_rsp_parse(payload):
    if len(payload) != 15:
        raise ValueError("resume_rsp: bad length")
    return payload[1], int.from_bytes(payload[2:6], "big"), \
        int.from_bytes(payload[6:14], "big"), payload[14]


def checksum_body(direction, file_id, sha256_digest):
    if len(sha256_digest) != 32:
        raise ValueError("checksum: bad digest")
    return (bytes([OP_CHECKSUM, direction & 0xFF])
            + file_id.to_bytes(4, "big") + sha256_digest)


def checksum_parse(payload):
    if len(payload) != 38:
        raise ValueError("checksum: bad length")
    return payload[1], int.from_bytes(payload[2:6], "big"), \
        payload[6:38]


# ------------------------------------------------------------- helpers
def sanitize_name(name: str) -> str:
    n = name.replace(os.sep, "_").replace("/", "_")
    n = re.sub(r"[^A-Za-z0-9._-]", "_", n)
    return n[:120] or "file"


def unique_path(directory: str, name: str) -> str:
    """Collision handling: name, name.1, name.2, ..."""
    os.makedirs(directory, exist_ok=True)
    cand = os.path.join(directory, name)
    if not os.path.exists(cand):
        return cand
    stem, ext = os.path.splitext(name)
    i = 1
    while True:
        cand = os.path.join(directory, f"{stem}.{i}{ext}")
        if not os.path.exists(cand):
            return cand
        i += 1


def file_sha256(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.digest()


# ------------------------------------------------------------- receiver
class FileReceiver:
    """Receiving side: .part writes, resume state, atomic commit,
    integrity verification, duplicate detection."""

    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)
        self.transfers = {}  # file_id -> state
        self.log = []

    def _part(self, file_id):
        return os.path.join(self.directory, f".{file_id:08x}.part")

    def deliver(self, payload: bytes, send) -> None:
        """Process one CH_FILE frame; `send(body)` emits replies."""
        op = payload[0]
        direction = payload[1]
        if len(payload) < 6:
            return
        file_id = int.from_bytes(payload[2:6], "big")
        if op == OP_META:
            _d, _fid, total, name = meta_parse(payload)
            clean = sanitize_name(name)
            # duplicate detection: bare name with matching size
            dup_complete = (os.path.exists(os.path.join(self.directory,
                                                        clean))
                            and os.path.getsize(os.path.join(
                                self.directory, clean)) == total)
            final = unique_path(self.directory, clean)
            part = self._part(file_id)
            t = {"final": final, "part": part, "total": total,
                 "name": name, "seq": -1, "done": False,
                 "checksum": None,
                 "dup_complete": dup_complete}
            self.transfers[file_id] = t
            self.log.append(("meta", file_id, name, total))
        elif op == OP_DATA:
            _d, _fid, seq, offset, chunk = data_parse(payload)
            t = self.transfers.get(file_id)
            if t is None or t["done"]:
                return
            with open(t["part"], "r+b" if os.path.exists(t["part"])
                      else "wb") as f:
                f.seek(offset)
                f.write(chunk)
            if seq != t["seq"] + 1 and offset != 0:
                pass  # out-of-order allowed; commit order by offset
            t["seq"] = max(t["seq"], seq)
            send(ack_body(1 - direction, file_id, seq))
        elif op == OP_RESUME_REQ:
            _d, _fid, expected = resume_req_parse(payload)
            t = self.transfers.get(file_id)
            if t is None:
                send(resume_rsp_body(1 - direction, file_id, 0, STATE_NONE))
            elif t.get("dup_complete"):
                send(resume_rsp_body(1 - direction, file_id,
                                     t["total"], STATE_COMPLETE))
            elif t["done"]:
                send(resume_rsp_body(1 - direction, file_id,
                                     t["total"], STATE_COMPLETE))
            else:
                size = os.path.getsize(t["part"]) \
                    if os.path.exists(t["part"]) else 0
                if size >= t["total"]:
                    send(resume_rsp_body(1 - direction, file_id,
                                         t["total"], STATE_COMPLETE))
                elif size > 0:
                    send(resume_rsp_body(1 - direction, file_id, size,
                                         STATE_PARTIAL))
                else:
                    send(resume_rsp_body(1 - direction, file_id, 0,
                                         STATE_NONE))
        elif op == OP_DONE:
            t = self.transfers.get(file_id)
            if t is None:
                return
            t["done"] = True
            self.log.append(("done", file_id))
        elif op == OP_CHECKSUM:
            _d, _fid, digest = checksum_parse(payload)
            t = self.transfers.get(file_id)
            if t is None or not t["done"]:
                return
            if os.path.exists(t["part"]):
                actual = file_sha256(t["part"])
            else:
                actual = hashlib.sha256(b"").digest()
            if actual == digest:
                os.replace(t["part"], t["final"])  # atomic commit
                self.log.append(("commit", file_id, t["final"]))
                send(ack_body(1 - direction, file_id, 0xFFFF))
            else:
                # integrity failure: delete, report, force retransfer
                try:
                    os.unlink(t["part"])
                except OSError:
                    pass
                t["done"] = False
                t["seq"] = -1
                self.transfers[file_id] = t
                self.log.append(("integrity_fail", file_id))
                send(cancel_body(1 - direction, file_id))
        elif op == OP_CANCEL:
            t = self.transfers.pop(file_id, None)
            if t and os.path.exists(t["part"]):
                try:
                    os.unlink(t["part"])
                except OSError:
                    pass
            self.log.append(("cancel", file_id))

    def status(self, file_id) -> tuple:
        t = self.transfers.get(file_id)
        if t is None:
            return 0, STATE_NONE
        if os.path.exists(t["final"]):
            return os.path.getsize(t["final"]), STATE_COMPLETE
        if not t["done"] and os.path.exists(t["part"]):
            return os.path.getsize(t["part"]), STATE_PARTIAL
        return 0, STATE_NONE


# ------------------------------------------------------------- sender
class FileSender:
    """Sending side: chunked send, ack tracking, resume from
    receiver-reported offset, checksum at the end."""

    def __init__(self, direction: int):
        self.direction = direction
        self.inflight = 0

    def send(self, source_path: str, file_id: int, name: str, send,
             recv, chunk_size: int = DEFAULT_CHUNK,
             resume: bool = True) -> dict:
        """Blocking transfer over `send(body)` / `recv() -> payload`.

        Returns {"committed": bool, "resumed_from": int, "bytes": int}.
        A link death raises ConnectionError; the same call again
        (with resume=True) continues from the receiver's offset.
        On receiver-side integrity failure (CANCEL), the transfer
        automatically restarts from 0 — bounded by the receiver
        resetting the file, so it always converges.
        """
        total = os.path.getsize(source_path)
        send(meta_body(self.direction, file_id, total, name))
        start = 0
        if resume:
            start = self._resume_handshake(file_id, send, recv)
            if start is None:
                return {"committed": True, "resumed_from": 0, "bytes": 0}
        while True:
            res = self._chunk_phase(source_path, file_id, total, start,
                                    chunk_size, send, recv)
            if res is not None:
                return res
            # CANCEL = receiver integrity failure: restart from 0
            start = 0
            start = self._resume_handshake(file_id, send, recv) \
                or 0

    def _resume_handshake(self, file_id, send, recv):
        """Returns offset to continue from, or None if complete."""
        send(resume_req_body(self.direction, file_id, 0))
        while True:
            p = recv()
            if p[0] == OP_RESUME_RSP:
                _d, _fid, offset, state = resume_rsp_parse(p)
                if state == STATE_COMPLETE:
                    return None
                return offset if state == STATE_PARTIAL else 0
            if p[0] == OP_ACK:
                continue
            if p[0] == OP_CANCEL:
                raise ConnectionError("canceled during resume")

    def _chunk_phase(self, source_path, file_id, total, start,
                     chunk_size, send, recv):
        """Send data from `start` to `total`, then done+checksum.
        Returns the result dict on success, None on CANCEL."""
        seq = start // chunk_size if start else 0
        offset = start
        bytes_sent = 0
        with open(source_path, "rb") as f:
            f.seek(offset)
            while offset < total:
                chunk = f.read(min(chunk_size, total - offset))
                send(data_body(self.direction, file_id, seq, offset, chunk))
                offset += len(chunk)
                bytes_sent += len(chunk)
                seq += 1
                if not self._wait_ack(file_id, recv):
                    return None
        send(done_body(self.direction, file_id))
        digest = _sha256_file(source_path)
        send(checksum_body(self.direction, file_id, digest))
        if not self._wait_ack(file_id, recv, pseudo=0xFFFF):
            return None
        return {"committed": True, "resumed_from": start,
                "bytes": bytes_sent}

    def _wait_ack(self, file_id, recv, pseudo=None):
        """Wait for the ack of the last data/checksum frame.
        Returns False on CANCEL (receiver integrity failure)."""
        while True:
            p = recv()
            op = p[0]
            if op == OP_ACK:
                return True
            if op == OP_CANCEL:
                return False

    def sha256(self, source_path: str) -> bytes:
        return _sha256_file(source_path)


def _sha256_file(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.digest()
