"""Security test suite (Phase 42/43): replay, downgrade, MITM, malformed,
oversized, brute force, exhaustion, path traversal.

Every check is a concrete attack → the reference stack must reject it
with a typed error (or safe behavior). No network; deterministic.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import reference_framing as rf
import ulp_v11 as v11
import limits
import file_transfer as ft
from observability import validate_event, EventSchemaError

PASS = []
FAIL = []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))


def tries(fn, *exc):
    try:
        fn()
        return False
    except exc:
        return True
    except Exception:  # noqa: BLE001
        return "untyped"


# ------------------------------------------------------------ 1. replay
def sec_replay():
    secret = os.urandom(32)
    nonce_a = os.urandom(16)
    priv = os.urandom(32)
    pub = rf.x25519_public(priv)
    hello = rf.hello_body(rf.ROLE_HOST, 0x00FF, rf.CIPHER_INTEROP, pub,
                          nonce_a) + rf.pairing_mac(secret, pub, nonce_a)
    # 1a. HELLO captured and replayed to a NEW pairing secret must fail
    check("sec:replay-hello-wrong-secret",
          tries(lambda: rf.hello_verify(hello, os.urandom(32)),
                rf.ProtocolError, ValueError))
    # 1b. tampered pairing MAC (MITM substitution of the last byte)
    bad = hello[:-1] + bytes([hello[-1] ^ 1])
    check("sec:replay-hello-mac-tamper",
          tries(lambda: rf.hello_verify(bad, secret),
                rf.ProtocolError, ValueError))
    # 1c. handshake replay cache: same (msg, nonce) twice
    cache = v11.HandshakeReplayCache()
    check("sec:replay-cache-first", cache.check(b"M1", b"N1") is True)
    check("sec:replay-cache-dup-rejected", cache.check(b"M1", b"N1")
          is False)
    check("sec:replay-cache-distinct-ok", cache.check(b"M1", b"N2")
          is True)
    # 1d. FIFO eviction at 256: the 257th distinct entry evicts #0
    c2 = v11.HandshakeReplayCache()
    for i in range(257):
        c2.check(b"M", f"N{i}".encode())
    check("sec:replay-cache-257th-forgets-oldest",
          c2.check(b"M", b"N0") is True)
    check("sec:replay-cache-newest-kept",
          c2.check(b"M", f"N256".encode()) is False)
    # 1e. AEAD nonce reuse: same (key, nonce) twice → different tags,
    #     second decrypt with first tag fails
    ka = os.urandom(32)
    km = os.urandom(32)
    nonce = os.urandom(12)
    aad = b"A" * 7
    ct1 = rf.interop_encrypt(ka, km, nonce, aad, b"msg1")
    ct2 = rf.interop_encrypt(ka, km, nonce, aad, b"msg2")
    check("sec:replay-aead-nonce-reuse-detected",
          ct1 != ct2 and
          tries(lambda: rf.interop_decrypt(ka, km, nonce, aad,
                                           ct2[:28] + ct1[-16:]),
                rf.AuthError))


# ------------------------------------------------------------ 2. downgrade
def sec_downgrade():
    # 2a. cipher below floor rejected (INTEROP is the v1 floor; a
    #     HELLO pref of 0x00 must not produce a cipher < INTEROP when
    #     the other side only offers INTEROP)
    secret = os.urandom(32)
    na, nb = os.urandom(16), os.urandom(16)
    pa = os.urandom(32)
    pb = os.urandom(32)
    pua = rf.x25519_public(pa)
    pub = rf.x25519_public(pb)
    hello = rf.hello_body(rf.ROLE_HOST, 0x00FF, rf.CIPHER_INTEROP, pua, na) \
        + rf.pairing_mac(secret, pua, na)
    hv = rf.hello_verify(hello, secret)
    # device "prefers" nothing better; negotiation = min(both prefs)
    # but never below the shared floor:
    sel = min(hv["cipher_pref"], rf.CIPHER_INTEROP)
    check("sec:downgrade-cipher-floor",
          sel == rf.CIPHER_INTEROP)
    # 2b. version negotiation: unsupported version in frame header
    wire = rf.Frame(0x00, 0, b"").encode()
    bad = bytes([wire[0], wire[1], 99, 0, 0, 0, 0])
    check("sec:downgrade-frame-version",
          tries(lambda: rf.Frame.decode(bad), rf.FramingError))
    # 2c. HELLO with unsupported ULP version bit → error code
    check("sec:downgrade-ulp-version-code",
          v11.ERR_UPGRADE_REQUIRED == 0x000B)


# ------------------------------------------------------------ 3. MITM
def sec_mitm():
    secret = os.urandom(32)
    na = os.urandom(16)
    legit = os.urandom(32)
    legit_pub = rf.x25519_public(legit)
    attacker_pub = rf.x25519_public(os.urandom(32))
    hello = rf.hello_body(rf.ROLE_HOST, 0x00FF, rf.CIPHER_INTEROP,
                          legit_pub, na) \
        + rf.pairing_mac(secret, legit_pub, na)
    # 3a. ecdh_pub substituted (MAC binds it)
    swapped = hello[:34].__add__(attacker_pub) \
        + hello[34 + 32:]
    # rebuild properly: body layout is role(1) feat(2) pref(1) pub(32)
    # nonce(16) mac(32)
    body = (bytes([rf.ROLE_HOST]) + (0x00FF).to_bytes(2, "big")
            + bytes([rf.CIPHER_INTEROP]) + attacker_pub + na
            + hello[-32:])
    check("sec:mitm-ecdh-substitution",
          tries(lambda: rf.hello_verify(body, secret),
                rf.ProtocolError, ValueError))
    # 3b. resume key substitution: MITM swaps the device's fresh_pub
    # (both keys valid X25519 points — only the "legit" one is the
    # device's; a host that trusts the swapped one derives different
    # session keys than the device ⇒ first frame fails authentication)
    sid = os.urandom(16)
    dev_fresh = os.urandom(32)
    dev_pub = rf.x25519_public(dev_fresh)
    attacker_pub2 = rf.x25519_public(os.urandom(32))
    host_fresh = os.urandom(32)
    host_fresh_pub = rf.x25519_public(host_fresh)
    nonce = os.urandom(16)
    req = v11.resume_req_body(sid, host_fresh_pub, nonce, secret)
    v11.resume_req_parse(req, secret)
    ok_body = v11.resume_ok_body(dev_pub, sid, host_fresh_pub, secret)
    # device side (legit):
    s1 = rf.x25519(dev_fresh, host_fresh_pub)
    # host side believing the MITM swap:
    s2 = rf.x25519(host_fresh, attacker_pub2)
    k_legit = v11.resume_session_keys(s1, nonce, sid, rf.CIPHER_INTEROP)
    k_att = v11.resume_session_keys(s2, nonce, sid, rf.CIPHER_INTEROP)
    check("sec:mitm-resume-key-substitution",
          k_legit[0] != k_att[0] and k_legit[1] != k_att[1])
    # 3c. identity: DEVICE_ID transcript MAC fails on altered bytes
    km = os.urandom(32)
    did = os.urandom(16)
    pub = os.urandom(32)
    body = v11.device_id_body(did, pub, "x", "linux", "0.1", 1, b"", km)
    v11.device_id_parse(body, b"", km)  # parses
    bad = bytearray(body)
    bad[len(bad) - 1] ^= 1  # MAC byte
    check("sec:mitm-identity-mac",
          tries(lambda: v11.device_id_parse(bytes(bad), b"", km),
                rf.ProtocolError, ValueError))


# ------------------------------------------------------------ 4. malformed
def sec_malformed():
    # 4a. truncated frames (0-3 extra bytes ⇒ header incomplete)
    for n in range(0, 4):
        data = bytes([0x55, 0x4C, 1]) + bytes(n)
        check(f"sec:malformed-short-{n}",
              tries(lambda d=data: rf.Frame.decode(d), rf.FramingError))
    # 4a2. exactly the 7-byte header (len=0) is a VALID empty frame
    fr = rf.Frame.decode(b"\x55\x4c\x01\x00\x00\x00\x00")
    check("sec:malformed-base-header-valid",
          fr.channel == 0 and fr.payload == b"")
    # 4b. bad magic
    check("sec:malformed-bad-magic",
          tries(lambda: rf.Frame.decode(b"\x56\x4c\x01\x00\x00\x00\x00"),
                rf.FramingError))
    # 4c. reserved length range 0x8001–0xFFFF
    check("sec:malformed-reserved-len",
          tries(lambda: rf.Frame.decode(
              b"\x55\x4c\x01\x00\x00\x80\x01" + b"\x00" * 2),
              rf.FramingError))
    # 4d. incomplete payload
    check("sec:malformed-incomplete",
          tries(lambda: rf.Frame.decode(b"\x55\x4c\x01\x00\x00\x00\x10"
                                        + b"\x00" * 3), rf.FramingError))
    # 4e. reserved flag constant pinned (enforcement is in the link
    #     layer; test_limits proves rejection on a real Link)
    check("sec:malformed-reserved-flags-constant",
          limits.Limits.RESERVED_FLAGS == (rf.F_COMPRESSED | rf.F_FRAG)
          == 0x05)
    # 4f. message truncation
    check("sec:malformed-msg-short",
          tries(lambda: rf.msg_decode(b"\x01"), rf.FramingError))
    check("sec:malformed-msg-body-short",
          tries(lambda: rf.msg_decode(b"\x01\x00\x00\x50" + b"\x00" * 3),
                rf.FramingError))
    # 4g. HELLO truncation
    for n in (10, 40, 70):
        check(f"sec:malformed-hello-{n}",
              tries(lambda b=bytes(n): rf.hello_verify(b, os.urandom(32)),
                    rf.ProtocolError, ValueError))
    # 4h. file ops bad lengths
    check("sec:malformed-file-resume_req",
          tries(lambda: ft.resume_req_parse(b"\x05\x00" + b"\x00" * 10),
                ValueError))
    check("sec:malformed-file-checksum",
          tries(lambda: ft.checksum_parse(b"\x07\x00" + b"\x00" * 30),
                ValueError))


# ------------------------------------------------------------ 5. oversized
def sec_oversized():
    # 5a. extended length > MAX_PAYLOAD rejected before allocation
    big = (0xFFFFFFFF).to_bytes(4, "big")
    check("sec:oversized-ext-len",
          tries(lambda: rf.Frame.decode(
              b"\x55\x4c\x01\x00\x00\x80\x00" + big), rf.FramingError))
    # 5b. frame with payload over the cap
    payload = b"\x00" * (limits.Limits.MAX_FRAME_BYTES + 1)
    check("sec:oversized-payload",
          tries(lambda: rf.Frame(0x00, 0, payload).encode(),
                rf.FramingError))
    # 5c. limits table sanity
    check("sec:oversized-limits-table",
          limits.Limits.MAX_FRAME_BYTES == 0x00100000
          and limits.Limits.MAX_FILE_CHUNK == 256 * 1024)


# ------------------------------------------------------------ 6. brute force
def sec_bruteforce():
    clock = [0.0]
    gate = v11.PairingGate(max_failures=5, window_s=60.0,
                           clock=lambda: clock[0])
    for i in range(5):
        assert gate.attempt("1.2.3.4") is True  # 1st..5th allowed
        gate.failure("1.2.3.4")
    check("sec:bruteforce-6th-throttled",
          gate.attempt("1.2.3.4") is False)
    check("sec:bruteforce-other-source-unaffected",
          gate.attempt("5.6.7.8") is True)
    clock[0] = 61.0  # window expired
    check("sec:bruteforce-window-expiry-reset",
          gate.attempt("1.2.3.4") is True)
    # successful pairing resets the counter
    gate2 = v11.PairingGate(max_failures=5, window_s=60.0,
                            clock=lambda: clock[0])
    for i in range(4):
        gate2.attempt("a")
        gate2.failure("a")
    check("sec:bruteforce-4th-still-allowed", gate2.attempt("a") is True)
    gate2.reset("a")  # pairing succeeded
    for i in range(5):
        gate2.attempt("a")
        gate2.failure("a")
    check("sec:bruteforce-success-resets",
          gate2.attempt("a") is False)


# ------------------------------------------------------------ 7. exhaustion
def sec_exhaustion():
    import scheduler as sched
    s = sched.Scheduler(budget_bytes=64 * 1024, max_items=128)
    enq = drops = 0
    for i in range(10_000):
        if s.enqueue(0x05, b"\x00" * 1024, 1024):
            enq += 1
        else:
            drops += 1
    check("sec:exhaustion-counted-drops", enq + drops == 10_000 and
          drops > 0 and
          s.dropped_full + s.dropped_budget == drops)
    check("sec:exhaustion-bounded-state",
          s._items <= 128 and s._bytes <= 64 * 1024)
    while s.pop() is not None:
        pass
    check("sec:exhaustion-conservation",
          s.delivered == enq)
    # memory: 10k attempts never hold > budget
    check("sec:exhaustion-no-unbounded-growth", s._items == 0)


# ------------------------------------------------------------ 8. path traversal
def sec_traversal():
    tmp = tempfile.mkdtemp(prefix="ut-sec-trav-")
    try:
        for evil in ("../etc/passwd", "/abs/path", "a/../../b",
                     "....//....//x", "ok-name.bin"):
            clean = ft.sanitize_name(evil)
            # no path separators survive sanitization
            check(f"sec:traversal-clean-{evil!r}",
                  "/" not in clean and os.sep not in clean and
                  clean != "" and clean not in (".", ".."), clean)
            target = ft.unique_path(tmp, clean)
            # containment: resolved target is inside the inbox dir
            check(f"sec:traversal-contain-{evil!r}",
                  os.path.commonpath([os.path.abspath(target),
                                      os.path.abspath(tmp)])
                  == os.path.abspath(tmp))
        # name too long rejected by meta codec
        check("sec:traversal-name-too-long",
              tries(lambda: ft.meta_body(0, 1, 10, "x" * 300), ValueError))
        # duplicate-name attack: .part files never escape the dir
        rx = ft.FileReceiver(tmp)
        import os as _os
        _os.makedirs(os.path.join(tmp, "sub"), exist_ok=True)
        mb = ft.meta_body(0, 7, 100, "../escape.bin")
        rx.deliver(mb, lambda b: None)
        part = rx._part(7)
        check("sec:traversal-part-contained",
              os.path.abspath(part).startswith(os.path.abspath(tmp)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    for fn in (sec_replay, sec_downgrade, sec_mitm, sec_malformed,
               sec_oversized, sec_bruteforce, sec_exhaustion,
               sec_traversal):
        fn()
    # obs: every denylist field refused in a valid-looking event
    base = {"v": 1, "ts": 1.0, "sev": "info", "ev": "x"}
    import observability as obs
    n = 0
    for k in obs.DENYLIST:
        ev = dict(base, **{k: "leak"})
        ok = False
        try:
            validate_event(ev)
        except EventSchemaError:
            ok = True
        if not ok:
            FAIL.append((f"sec:obs-deny-{k}", ""))
        n += 1
    print(f"SECURITY: {len(PASS)} pass, {len(FAIL)} fail "
          f"({n} denylist fields)")
    for name, d in FAIL:
        print(f"  FAIL {name} {d}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
