"""File transfer v2 tests: chunking, checksums, resume after failure,
integrity failure retransfer, atomic commit, collision, duplicates."""
import os
import queue
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from file_transfer import (FileReceiver, FileSender, file_sha256,
                           meta_body, meta_parse, data_body, data_parse,
                           resume_req_body, resume_rsp_body, resume_rsp_parse,
                           checksum_body, checksum_parse, ack_body,
                           OP_CHECKSUM, OP_DATA, OP_META, STATE_COMPLETE)

PASS = []
FAIL = []


def check(name, cond):
    (PASS if cond else FAIL).append(name)


class Link:
    """In-memory bidirectional queue link; close() simulates drop."""

    def __init__(self):
        self.s2r = queue.Queue()
        self.r2s = queue.Queue()
        self.closed = False

    def close(self):
        self.closed = True

    def sender_send(self, body):
        if self.closed:
            raise ConnectionError("link down")
        self.s2r.put(body)

    def sender_recv(self):
        if self.closed:
            raise ConnectionError("link down")
        try:
            return self.r2s.get(timeout=0.5)
        except queue.Empty:
            raise ConnectionError("link down (timeout)")


def drain_receiver(link, rx):
    """Feed all currently queued frames to the receiver."""
    while not link.s2r.empty():
        body = link.s2r.get_nowait()
        rx.deliver(body, lambda b: link.r2s.put(b))


def transfer(src, file_id, name, chunk, kill_at=None, rxdir=None):
    """Run a transfer; kill_at = fraction of bytes after which the link
    drops (receiver keeps its .part). Returns (res, link, rx, link2...)."""
    link = Link()
    if rxdir is None:
        rxdir = tempfile.mkdtemp(prefix="ut-file-")
    rx = FileReceiver(rxdir)
    fd = FileSender(0)

    def receiver_loop():
        # feed frames as the sender produces them
        while True:
            try:
                body = link.s2r.get(timeout=0.2)
            except queue.Empty:
                if link.closed:
                    return
                continue
            if kill_at is not None:
                # count bytes received in data frames
                if body[0] == OP_DATA:
                    _d, _f, _s, off, chunkb = data_parse(body)
                    if off + len(chunkb) >= kill_at:
                        link.close()
                        return
            try:
                rx.deliver(body, lambda b: link.r2s.put(b))
            except Exception:
                link.close()
                return

    import threading
    t = threading.Thread(target=receiver_loop, daemon=True)
    t.start()
    try:
        res = fd.send(src, file_id, name,
                      link.sender_send, link.sender_recv,
                      chunk_size=chunk, resume=True)
    except ConnectionError:
        res = None
    t.join(timeout=2)
    return res, link, rx, rxdir


def main():
    tmp = tempfile.mkdtemp(prefix="ut-file-test-")
    try:
        # ---- 1. basic transfer + integrity + atomic commit
        src = os.path.join(tmp, "a.bin")
        total = 1_000_000
        with open(src, "wb") as f:
            f.write(os.urandom(total))
        res, link, rx, rxdir = transfer(src, 7, "report.bin", 256 * 1024)
        check("file:basic committed", res is not None and res["committed"])
        final = os.path.join(rxdir, "report.bin")
        check("file:basic file exists", os.path.exists(final))
        check("file:basic hash matches",
              os.path.exists(final) and file_sha256(final)
              == file_sha256(src))
        check("file:basic no .part left",
              not [n for n in os.listdir(rxdir) if n.endswith(".part")])
        check("file:basic all bytes sent",
              res is not None and res["bytes"] == total)

        # ---- 2. name collision
        res2, _, _, _ = transfer(src, 8, "report.bin", 256 * 1024)
        check("file:collision committed", res2 is not None
              and res2["committed"])
        # (fresh rxdir per call — collision needs same dir; do manually)
        shutil.rmtree([d for d in [rxdir]][0] if False else tmp,
                      ignore_errors=True) if False else None
        # real collision test in a fixed dir
        cdir = os.path.join(tmp, "coll")
        os.makedirs(cdir, exist_ok=True)
        rx = FileReceiver(cdir)
        s = FileSender(0)
        l1 = Link()
        import threading
        def run_rx(l):
            while not l.closed:
                try:
                    b = l.s2r.get(timeout=0.2)
                except queue.Empty:
                    continue
                try: rx.deliver(b, lambda x: l.r2s.put(x))
                except Exception: l.close(); return
        th = threading.Thread(target=run_rx, args=(l1,), daemon=True)
        th.start()
        s.send(src, 1, "x.txt", l1.sender_send, l1.sender_recv,
               chunk_size=64 * 1024)
        l1.close(); th.join(timeout=1)
        # different content (same name) → collision suffix, not dup skip
        srcb = os.path.join(tmp, "xb.bin")
        with open(srcb, "wb") as f:
            f.write(os.urandom(total + 777))
        rx2 = FileReceiver(cdir)
        l2 = Link()
        th2 = threading.Thread(target=run_rx, args=(l2,), daemon=True)
        th2.start()
        s.send(srcb, 2, "x.txt", l2.sender_send, l2.sender_recv,
               chunk_size=64 * 1024)
        l2.close(); th2.join(timeout=1)
        check("file:collision .1 created",
              os.path.exists(os.path.join(cdir, "x.txt"))
              and os.path.exists(os.path.join(cdir, "x.1.txt")))

        # ---- 3. resume after failure at ~97%
        big = os.path.join(tmp, "big.bin")
        big_total = 4 * 1024 * 1024 + 192 * 1024  # 34.25 chunks @128KiB
        with open(big, "wb") as f:
            f.write(os.urandom(big_total))
        chunk = 128 * 1024
        kill_at = 33 * chunk + 1  # keep 33 chunks (98.5%)
        res, link, rx, rxdir = transfer(big, 42, "movie.mkv", chunk,
                                        kill_at=kill_at)
        check("file:resume failed mid-transfer", res is None)
        part = os.path.join(rxdir, ".0000002a.part")
        check("file:resume .part kept", os.path.exists(part)
              and os.path.getsize(part) == 33 * chunk)
        # resume on a NEW link (new session, same receiver dir)
        res2, link2, rx, _ = transfer(big, 42, "movie.mkv", chunk, rxdir=rxdir)
        check("file:resume completed", res2 is not None
              and res2["committed"])
        check("file:resume resumed from 98.5%",
              res2 is not None and res2["resumed_from"] == 33 * chunk)
        check("file:resume only 1.5% retransferred",
              res2 is not None and res2["bytes"] < 0.05 * big_total)
        final = os.path.join(rxdir, "movie.mkv")
        check("file:resume integrity",
              os.path.exists(final) and file_sha256(final)
              == file_sha256(big))

        # ---- 4. duplicate skip (same size+name already committed)
        res3, _, _, _ = transfer(big, 42, "movie.mkv", chunk, rxdir=rxdir)
        check("file:dup skipped", res3 is not None
              and res3["committed"] and res3["bytes"] == 0)

        # ---- 5. integrity failure → cancel → full retransfer
        class Corrupt(FileReceiver):
            def __init__(self, d):
                super().__init__(d)
                self.will_corrupt = True

            def deliver(self, payload, send):
                if (self.will_corrupt and payload[0] == OP_CHECKSUM
                        and payload[2:6] == (99).to_bytes(4, "big")):
                    fid = int.from_bytes(payload[2:6], "big")
                    partp = self._part(fid)
                    with open(partp, "r+b") as f:
                        f.seek(100)
                        b = f.read(1)
                        f.seek(100)
                        f.write(bytes([b[0] ^ 0xFF]))
                    self.will_corrupt = False
                super().deliver(payload, send)

        cdir2 = os.path.join(tmp, "corr")
        os.makedirs(cdir2, exist_ok=True)
        rxc = Corrupt(cdir2)
        sc = FileSender(0)
        lc = Link()

        def run_rxc():
            while not lc.closed:
                try:
                    b = lc.s2r.get(timeout=0.2)
                except queue.Empty:
                    continue
                try: rxc.deliver(b, lambda x: lc.r2s.put(x))
                except Exception: lc.close(); return

        thc = threading.Thread(target=run_rxc, daemon=True)
        thc.start()
        src2 = os.path.join(tmp, "c.bin")
        with open(src2, "wb") as f:
            f.write(os.urandom(300 * 1024))
        try:
            resc = sc.send(src2, 99, "c.bin", lc.sender_send,
                           lc.sender_recv, chunk_size=64 * 1024)
        except ConnectionError:
            resc = None
        lc.close(); thc.join(timeout=2)
        check("file:integrity retransferred+committed",
              resc is not None and resc["committed"])
        finalc = os.path.join(cdir2, "c.bin")
        check("file:integrity final hash ok",
              os.path.exists(finalc) and file_sha256(finalc)
              == file_sha256(src2))
        check("file:integrity failure logged",
              any(e[0] == "integrity_fail" for e in rxc.log))

        # ---- 6. codec roundtrips + v1 shape preserved
        mb = meta_body(0, 0xDEADBEEF, 0x1122334455667788, "hello")
        d, fid, tot, nm = meta_parse(mb)
        check("file:meta roundtrip", d == 0 and fid == 0xDEADBEEF
              and tot == 0x1122334455667788 and nm == "hello"
              and mb[0] == 0x00)
        db = data_body(1, 5, 3, 12345, b"XYZ")
        d, fid, seq, off, ch = data_parse(db)
        check("file:data roundtrip", d == 1 and fid == 5 and seq == 3
              and off == 12345 and ch == b"XYZ" and db[0] == 0x01)
        rb = resume_req_body(0, 9, 123456)
        check("file:resume_req len", len(rb) == 14 and rb[0] == 0x05)
        rs = resume_rsp_body(1, 9, 123456, STATE_COMPLETE)
        check("file:resume_rsp roundtrip",
              resume_rsp_parse(rs) == (1, 9, 123456, STATE_COMPLETE)
              and len(rs) == 15)
        dig = file_sha256(src2)
        cb = checksum_body(0, 9, dig)
        check("file:checksum roundtrip",
              checksum_parse(cb) == (0, 9, dig) and len(cb) == 38)
        check("file:ack shape", len(ack_body(0, 9, 1)) == 10)

        print(f"FILE V2: {len(PASS)} pass, {len(FAIL)} fail")
        for n in FAIL:
            print(f"  FAIL {n}")
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
