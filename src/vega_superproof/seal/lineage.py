"""lineage.py - dual lineage: one hash chain for WHAT was sealed (content), one for WHICH KEYS sealed it (key
events, by key id - never key material). The top root binds both, so a record cannot be re-attributed to other
keys or other content without breaking the root."""
import hashlib

ZERO = "0" * 64


def key_id(key: bytes) -> str:
    """Non-secret identifier of a random 256-bit key."""
    return hashlib.sha256(b"vega-keyid-v1" + bytes(key)).hexdigest()


def _link(prev: str, item: str) -> str:
    return hashlib.sha256(bytes.fromhex(prev) + item.encode("utf-8")).hexdigest()


class Lineage:
    def __init__(self):
        self.content_head = ZERO
        self.key_head = ZERO
        self.content, self.keys = [], []

    def add_content(self, digest: str) -> str:
        self.content_head = _link(self.content_head, digest)
        self.content.append(digest)
        return self.content_head

    def add_key_event(self, kid: str, event: str) -> str:
        self.key_head = _link(self.key_head, f"{event}:{kid}")
        self.keys.append((event, kid))
        return self.key_head

    def root(self) -> str:
        return hashlib.sha256(bytes.fromhex(self.content_head) + bytes.fromhex(self.key_head)).hexdigest()
