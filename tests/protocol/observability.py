"""Structured events + metrics (Phases 32/60) — privacy-first.

Every event is a JSON line with a stable envelope (docs/23 §1). The
hard rule: **no content, ever** — no SMS, clipboard, files, screen
frames, camera frames, or audio. `validate_event` enforces this
mechanically (denylisted field names + string length cap + numeric
types), and the test suite fuzzes the emitter to prove it.
"""
import json
import time

SCHEMA_V = 1
SEVERITIES = ("debug", "info", "warn", "error", "fatal")

# field names that must never appear (content leakage vectors)
DENYLIST = {
    "sms", "sms_body", "sms_text", "clipboard", "clipboard_text",
    "file_data", "file_name", "screen", "screen_frame", "frame_data",
    "camera", "camera_frame", "audio", "audio_bytes", "audio_pcm",
    "secret", "pairing_secret", "key_aead", "key_mac", "password",
    "token", "authorization",
}
MAX_STRING_LEN = 128
MAX_CTX_ENTRIES = 24


class EventSchemaError(ValueError):
    pass


def validate_event(evt: dict) -> None:
    """Raise EventSchemaError on any violation (privacy + shape)."""
    for req in ("v", "ts", "sev", "ev"):
        if req not in evt:
            raise EventSchemaError(f"missing field {req!r}")
    if evt["v"] != SCHEMA_V:
        raise EventSchemaError(f"unsupported schema v{evt['v']}")
    if evt["sev"] not in SEVERITIES:
        raise EventSchemaError(f"bad severity {evt['sev']!r}")
    if not isinstance(evt["ts"], (int, float)):
        raise EventSchemaError("ts must be numeric")
    if not isinstance(evt["ev"], str) or len(evt["ev"]) > 64:
        raise EventSchemaError("ev must be a short identifier")
    for key in evt:
        if key in DENYLIST:
            raise EventSchemaError(f"denied field {key!r}")
    for key, val in evt.items():
        if isinstance(val, str) and len(val) > MAX_STRING_LEN:
            raise EventSchemaError(
                f"string field {key!r} exceeds {MAX_STRING_LEN} chars "
                f"(content leakage?)")
        if isinstance(val, (bytes, bytearray)):
            raise EventSchemaError(f"binary field {key!r} forbidden")
    ctx = evt.get("ctx", {})
    if not isinstance(ctx, dict) or len(ctx) > MAX_CTX_ENTRIES:
        raise EventSchemaError("ctx must be a small dict")
    for key, val in ctx.items():
        if key in DENYLIST:
            raise EventSchemaError(f"denied ctx field {key!r}")
        if isinstance(val, str) and len(val) > MAX_STRING_LEN:
            raise EventSchemaError(f"ctx string {key!r} too long")
        if isinstance(val, (bytes, bytearray)):
            raise EventSchemaError(f"binary ctx {key!r} forbidden")
        if isinstance(val, dict):
            raise EventSchemaError("ctx values must be flat")


class Emitter:
    """JSON-line event emitter with schema enforcement."""

    def __init__(self, sink=None, clock=time.time):
        self.sink = sink  # file-like; default: no-op (in tests we
        # collect)
        self._clock = clock
        self.events = []

    def emit(self, ev: str, sev: str = "info", **fields) -> dict:
        evt = {"v": SCHEMA_V, "ts": self._clock(), "sev": sev, "ev": ev}
        evt.update(fields)
        validate_event(evt)
        self.events.append(evt)
        if self.sink is not None:
            self.sink.write(json.dumps(evt, separators=(",", ":")) + "\n")
        return evt

    # convenience constructors (docs/23 catalog)
    def state(self, state, from_state, session=None, device=None,
              transport=None, ulp="1.0"):
        return self.emit("session.state", state=state,
                         from_state=from_state, session=session,
                         device=device, transport=transport, ulp=ulp)

    def handshake(self, ok, latency_ms, cipher, session=None, ulp="1.0"):
        return self.emit("session.handshake",
                         sev="info" if ok else "error",
                         ok=ok, latency_ms=latency_ms, cipher=cipher,
                         session=session, ulp=ulp)

    def resume(self, ok, attempt, backoff_ms, session=None):
        return self.emit("session.resume",
                         sev="info" if ok else "warn",
                         ok=ok, attempt=attempt, backoff_ms=backoff_ms,
                         session=session)

    def file_op(self, op, file_id, total_bytes, ok=True, **extra):
        ctx = {"total_bytes": total_bytes}
        ctx.update(extra)
        return self.emit(f"file.{op}", sev="info" if ok else "warn",
                         file_id=file_id, ctx=ctx)


class Metrics:
    """Minimal privacy-safe metrics (counters/gauges/histograms)."""

    def __init__(self):
        self._counters = {}
        self._gauges = {}
        self._hist = {}

    def counter(self, name, n=1):
        self._counters[name] = self._counters.get(name, 0) + n

    def gauge(self, name, value):
        self._gauges[name] = value

    def histogram(self, name, value, buckets=(1, 5, 10, 25, 50, 100,
                                              250, 500, 1000)):
        h = self._hist.setdefault(name, {"n": 0, "sum": 0.0,
                                         "buckets": [0] * len(buckets),
                                         "buckets_def": list(buckets)})
        h["n"] += 1
        h["sum"] += value
        for i, b in enumerate(buckets):
            if value <= b:
                h["buckets"][i] += 1
                break
        else:
            h["buckets"][-1] += 1

    def snapshot(self):
        return {"counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {k: dict(v) for k, v in self._hist.items()}}
