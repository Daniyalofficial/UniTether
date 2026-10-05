"""Resource limits (Phase 8): every network-controlled value bounded.

These limits apply to the reference session manager and are mirrored
in the Rust host (`unilink-protocol::limits`) and the Android session.
Rejecting, not clamping, is the policy for protocol-level limits.
"""
import threading
from collections import deque


class Limits:
    # protocol
    MAX_FRAME_BYTES = 0x0010_0000        # 1 MiB (v1 MAX_PAYLOAD)
    MAX_EXTENDED_FRAME_BYTES = 0x0010_0000
    MAX_CONTROL_QUEUE = 128              # pending control msgs per session
    MAX_PENDING_FRAMES = 4096            # buffered inbound frames
    # identity / pairing
    MAX_NAME_LEN = 64
    MAX_PLATFORM_LEN = 16
    MAX_ERROR_MSG_LEN = 120
    MAX_RECONNECT_ATTEMPTS = 20
    # file transfer
    MAX_FILE_SIZE = 64 * 1024 ** 3       # 64 GiB
    MAX_CONCURRENT_FILES = 16
    MAX_FILE_CHUNK = 256 * 1024          # 256 KiB per data frame chunk
    # proxy
    MAX_PROXY_CONNECTIONS = 64
    MAX_PROXY_CONNECT_TIMEOUT_S = 10
    # session memory
    MAX_SESSION_BUFFER_BYTES = 8 * 1024 ** 2   # per-session queue budget
    # transport
    MAX_HANDSHAKE_TIMEOUT_S = 15
    MAX_TRANSPORT_RESELECTS = 5

    # flags that are RESERVED (never set by a conformant sender):
    # rejecting them on receive prevents future codec ambiguity and
    # compression-bomb vectors (docs/18 T9).
    RESERVED_FLAGS = 0x05                # F_COMPRESSED | F_FRAG


class BoundedControlQueue:
    """Bounded pending-control queue: full ⇒ oldest dropped + counter."""

    def __init__(self, limit: int = Limits.MAX_CONTROL_QUEUE):
        self._q = deque()
        self.limit = limit
        self.dropped = 0
        self._lock = threading.Lock()

    def push(self, item) -> bool:
        with self._lock:
            if len(self._q) >= self.limit:
                self._q.popleft()
                self.dropped += 1
            self._q.append(item)
            return True

    def pop(self):
        with self._lock:
            if self._q:
                return self._q.popleft()
            return None

    def __len__(self):
        with self._lock:
            return len(self._q)


class FileTransferGovernor:
    """Concurrent/size governor for file transfers (Phase 12)."""

    def __init__(self):
        self._active = {}
        self._lock = threading.Lock()

    def begin(self, file_id: int, total_bytes: int) -> None:
        if total_bytes > Limits.MAX_FILE_SIZE:
            raise ValueError(f"file too large: {total_bytes}")
        with self._lock:
            if len(self._active) >= Limits.MAX_CONCURRENT_FILES:
                raise ValueError("too many concurrent transfers")
            self._active[file_id] = {"total": total_bytes, "done": 0}

    def progress(self, file_id: int, n: int) -> bool:
        """Returns False when the transfer exceeds its declared total."""
        with self._lock:
            t = self._active.get(file_id)
            if t is None:
                raise ValueError(f"unknown transfer {file_id}")
            t["done"] += n
            if t["done"] > t["total"]:
                return False
            return t["done"] < t["total"]

    def end(self, file_id: int) -> bool:
        with self._lock:
            t = self._active.pop(file_id, None)
            return bool(t and t["done"] == t["total"])
