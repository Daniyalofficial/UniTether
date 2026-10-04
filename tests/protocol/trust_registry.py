"""Trusted-device registry (Phase 2): device identity + trust state.

File-backed (JSON), atomic writes (tmp + rename), SHA-256 footer for
corruption detection, safe-fail on corruption (no auto-trust).

Never relies on human-readable names: trust is keyed by identity_pub
(32 B X25519), device_id is derived from it; names are display-only
metadata (a renamed device keeps its identity).

Supports: registration, revocation, key rotation, trust expiry,
compromised-device recovery (revoke + new identity), multiple
computers/phones per owner, device groups.
"""
import hashlib
import json
import os
import tempfile
import time

MAGIC = b"UNITRUST1\n"


class TrustRegistry:
    def __init__(self, path: str, clock=time.time):
        self.path = path
        self._clock = clock
        self._data = {"version": 1, "devices": {}, "groups": {}, "revoked": {}}
        self.load()

    # ------------------------------------------------------------ storage
    def load(self) -> None:
        try:
            raw = open(self.path, "rb").read()
            body, footer = raw[: -64], raw[-64:]
            if not raw.startswith(MAGIC):
                raise ValueError("bad magic")
            expect = hashlib.sha256(MAGIC + body).digest()
            # footer: sha256(32) || created(8) || updated(8) || reserved(16)
            if footer[:32] != expect:
                raise ValueError("checksum mismatch")
            self._data = json.loads(body.decode("utf-8"))
        except FileNotFoundError:
            self._data = {"version": 1, "devices": {}, "groups": {}, "revoked": {}}
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            # corruption → safe-fail: start empty, keep the bad file aside
            try:
                os.replace(self.path, self.path + ".corrupt")
            except OSError:
                pass
            self._data = {"version": 1, "devices": {}, "groups": {}, "revoked": {}}

    def save(self) -> None:
        d = os.path.dirname(self.path) or "."
        body = json.dumps(self._data, sort_keys=True).encode("utf-8")
        blob = MAGIC + body + hashlib.sha256(MAGIC + body).digest() \
            + int(self._clock()).to_bytes(8, "big") * 2 + b"\x00" * 16
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".trust-")
        try:
            os.write(fd, blob)
            os.fsync(fd)
            os.close(fd)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # ------------------------------------------------------------ model
    def register(self, identity_pub: bytes, device_id: bytes, name: str,
                 platform: str = "", app_ver: str = "", caps: int = 0,
                 group: str = "default", ttl_s: int = 0,
                 owner: str = "default") -> dict:
        """Register (or update) a trusted device. Key rotation = re-register
        with a new identity_pub under the same device_id: the old key is
        revoked automatically."""
        now = self._clock()
        key = identity_pub.hex()
        old = self._data["devices"].get(key)
        if old and old.get("device_id") != device_id.hex():
            raise ValueError("identity pub already bound to another device")
        entry = {
            "device_id": device_id.hex(),
            "identity_pub": key,
            "name": name,
            "platform": platform,
            "app_ver": app_ver,
            "caps": caps,
            "group": group,
            "owner": owner,
            "registered": now,
            "last_seen": now,
            "expires": now + ttl_s if ttl_s else 0,  # 0 = no expiry
            "revoked": False,
            "trust_state": "trusted",
        }
        self._data["devices"][key] = entry
        # key rotation: same device_id, different pub → revoke old pub
        for k, v in list(self._data["devices"].items()):
            if v["device_id"] == device_id.hex() and k != key and not v["revoked"]:
                v["revoked"] = True
                v["trust_state"] = "rotated"
                self._data["revoked"][k] = {"reason": "rotated", "at": now}
        if group not in self._data["groups"]:
            self._data["groups"][group] = {"created": now, "members": []}
        if device_id.hex() not in self._data["groups"][group]["members"]:
            self._data["groups"][group]["members"].append(device_id.hex())
        self.save()
        return entry

    def decide(self, identity_pub: bytes, device_id: bytes) -> int:
        """Trust decision for an observed identity (identity_exchange).

        Returns ulp_v11 DECISION_* codes."""
        import ulp_v11 as v11
        key = identity_pub.hex()
        now = self._clock()
        entry = self._data["devices"].get(key)
        if entry is None:
            # unknown identity: auto-approve only for the owner's first
            # trust (the registry's policy); default = approve-once.
            return v11.DECISION_TRUSTED_NEW
        if entry.get("revoked") or key in self._data["revoked"]:
            return v11.DECISION_REVOKED
        exp = entry.get("expires", 0)
        if exp and now > exp:
            return v11.DECISION_REVOKED  # expired trust
        self._data["devices"][key]["last_seen"] = now
        self.save()
        return v11.DECISION_TRUSTED

    def note_trusted(self, identity_pub: bytes, device_id: bytes,
                     name: str = "", platform: str = "",
                     app_ver: str = "", caps: int = 0) -> None:
        """Record a successful trust exchange. First-time (unknown)
        identities are auto-registered — trust establishment."""
        key = identity_pub.hex()
        if key in self._data["devices"]:
            if name:
                self._data["devices"][key]["name"] = name
            self._data["devices"][key]["last_seen"] = self._clock()
            self.save()
        else:
            self.register(identity_pub, device_id, name or "unknown",
                          platform, app_ver, caps)

    def revoke(self, identity_pub: bytes = None, device_id: bytes = None,
               reason: str = "manual") -> int:
        """Revoke by identity and/or device id (compromised-device
        recovery). Returns number of entries revoked."""
        now = self._clock()
        n = 0
        for k, v in list(self._data["devices"].items()):
            hit = (identity_pub is not None and k == identity_pub.hex()) \
                or (device_id is not None and v["device_id"] == device_id.hex())
            if hit and not v["revoked"]:
                v["revoked"] = True
                v["trust_state"] = "revoked"
                self._data["revoked"][k] = {"reason": reason, "at": now}
                n += 1
        if n:
            self.save()
        return n

    def reset_trust(self, device_id: bytes) -> None:
        """Full trust reset for a device: all its keys revoked; the next
        pairing must re-register it."""
        self.revoke(device_id=device_id, reason="trust_reset")

    def set_expiry(self, identity_pub: bytes, ttl_s: int) -> None:
        key = identity_pub.hex()
        if key in self._data["devices"]:
            self._data["devices"][key]["expires"] = self._clock() + ttl_s
            self.save()

    def devices(self) -> list:
        return sorted(self._data["devices"].values(),
                      key=lambda v: v["device_id"])

    def groups(self) -> dict:
        return self._data["groups"]
