"""disclosure.py - selective disclosure that survives a quantum computer: commit to a whole record, later show only the fields you choose.

commit_record(fields) -> (root, secret openings). The root is a Merkle root over salted leaves, one per field, padded with random leaves to a power of two, so
it reveals neither a field's value nor its name nor the exact number of fields (only a size bucket). disclose(openings, names) -> a proof showing those fields,
each with its salt and path. verify_disclosure(root, proof) -> the fields shown, or None if anything is wrong.
Only SHA-256 is used, so this holds against a quantum computer as the hash does (about 128 bits). It proves the revealed fields are the ones committed to; it
does not prove the committed numbers are true (that is the issuer's signature on the root) and it does not prove things about hidden fields (use zk.py for that)."""
import hashlib
import json
import secrets

MAX_FIELDS = 1024


class DisclosureRefused(ValueError):
    pass


def _canon(o) -> bytes:
    try:
        return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DisclosureRefused("field values must be plain JSON data: %s" % exc) from exc


def _leaf(salt: bytes, name: str, value) -> bytes:
    return hashlib.sha256(b"DISC-LEAF\x00" + salt + len(name.encode()).to_bytes(2, "big") + name.encode() + _canon(value)).digest()


def _dummy(salt: bytes) -> bytes:
    return hashlib.sha256(b"DISC-PAD\x00" + salt).digest()


def _node(level: int, pos: int, left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"DISC-NODE\x00" + level.to_bytes(1, "big") + pos.to_bytes(4, "big") + left + right).digest()


def _levels(leaves):
    lv = [leaves]
    while len(lv[-1]) > 1:
        cur = lv[-1]
        lv.append([_node(len(lv), k, cur[2 * k], cur[2 * k + 1]) for k in range(len(cur) // 2)])
    return lv


def commit_record(fields: dict):
    if not isinstance(fields, dict) or not 1 <= len(fields) <= MAX_FIELDS:
        raise DisclosureRefused("fields is a non-empty object of at most %d entries" % MAX_FIELDS)
    for k in fields:
        if not isinstance(k, str) or not k or len(k.encode()) > 200:
            raise DisclosureRefused("field names are short non-empty text")
    names = sorted(fields)
    size = 1
    while size < len(names):
        size *= 2
    salts = {n: secrets.token_bytes(32) for n in names}
    pads = [secrets.token_bytes(32) for _ in range(size - len(names))]
    leaves = [_leaf(salts[n], n, fields[n]) for n in names] + [_dummy(p) for p in pads]
    # the order of the real leaves is shuffled by a secret permutation so a leaf's position says nothing about its name
    perm = list(range(size))
    for i in range(size - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    placed = [None] * size
    for src, dst in enumerate(perm):
        placed[dst] = leaves[src]
    levels = _levels(placed)
    openings = {"levels": levels, "fields": {n: {"value": fields[n], "salt": salts[n].hex(), "pos": perm[i]} for i, n in enumerate(names)}}
    return levels[-1][0].hex(), openings


def disclose(openings: dict, names) -> dict:
    out = []
    levels = openings["levels"]
    for n in names:
        f = openings["fields"].get(n)
        if f is None:
            raise DisclosureRefused("no such field: %r" % (n,))
        pos, path = f["pos"], []
        for lv in range(len(levels) - 1):
            path.append(levels[lv][pos ^ 1].hex())
            pos >>= 1
        out.append({"name": n, "value": f["value"], "salt": f["salt"], "pos": f["pos"], "path": path})
    return {"size": len(levels[0]), "fields": out}


def verify_disclosure(root_hex: str, proof) -> dict:
    """-> {name: value} for every field shown, or None if any part fails."""
    try:
        size = proof["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size & (size - 1) or size > 2 * MAX_FIELDS:
            return None
        depth = size.bit_length() - 1
        shown, seen_pos = {}, set()
        for f in proof["fields"]:
            name, pos = f["name"], f["pos"]
            if not isinstance(name, str) or not isinstance(pos, int) or isinstance(pos, bool) or not 0 <= pos < size or len(f["path"]) != depth:
                return None
            if name in shown or pos in seen_pos:
                return None
            node = _leaf(bytes.fromhex(f["salt"]), name, f["value"])
            p = pos
            for lv, sib_hex in enumerate(f["path"]):
                sib = bytes.fromhex(sib_hex)
                node = _node(lv + 1, p >> 1, node, sib) if p % 2 == 0 else _node(lv + 1, p >> 1, sib, node)
                p >>= 1
            if node.hex() != root_hex:
                return None
            shown[name] = f["value"]
            seen_pos.add(pos)
        return shown
    except (KeyError, TypeError, ValueError, DisclosureRefused):
        return None
