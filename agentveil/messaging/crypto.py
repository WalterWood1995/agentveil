"""End-to-end encryption for agent-to-agent messages (PyNaCl / libsodium).

Identity   : Ed25519 signing key + X25519 encryption key.
Agent ID   : base32(BLAKE2b-160(sign_pk || enc_pk)) — what you verify out-of-band.
Message    : inner JSON {from, to, ts, id, body} signed with Ed25519 (domain-separated),
             length-padded to fixed buckets, then sealed with crypto_box_seal to the
             recipient's X25519 key. The relay sees only: recipient mailbox id, a padded
             ciphertext, and timing. It never learns the sender.
Limitation : static keys — no forward secrecy. Rotate identities for long-lived secrets.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path

import nacl.exceptions
import nacl.pwhash
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

VERSION = 1
PAD_BUCKETS = (2048, 8192, 32768, 131072)  # envelope overhead is ~450 bytes; short chats share one size
MAX_BODY_CHARS = 60_000
MSG_CTX = b"agentveil/msg/v1\x00"
CARD_CTX = b"agentveil/card/v1\x00"
FETCH_CTX = b"agentveil/fetch/v1\x00"
MAX_AGE = 14 * 86400
MAX_SKEW = 600


class CryptoError(Exception):
    pass


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def agent_id(sign_pk: bytes, enc_pk: bytes) -> str:
    digest = hashlib.blake2b(sign_pk + enc_pk, digest_size=20).digest()
    return base64.b32encode(digest).decode().lower()


def mailbox_id(sign_pk: bytes) -> str:
    return hashlib.blake2b(b"agentveil/mailbox/v1" + sign_pk, digest_size=20).hexdigest()


def fingerprint(aid: str) -> str:
    return " ".join(aid[i:i + 4] for i in range(0, len(aid), 4))


def pad(data: bytes) -> bytes:
    framed = struct.pack(">I", len(data)) + data
    for size in PAD_BUCKETS:
        if len(framed) <= size:
            return framed + nacl.utils.random(size - len(framed))
    raise CryptoError(f"message too large ({len(data)} bytes)")


def unpad(data: bytes) -> bytes:
    if len(data) < 4:
        raise CryptoError("truncated message")
    (n,) = struct.unpack(">I", data[:4])
    if n > len(data) - 4:
        raise CryptoError("bad padding")
    return data[4:4 + n]


@dataclass(frozen=True)
class Contact:
    name: str
    sign_pk: bytes
    enc_pk: bytes
    relay: str

    @property
    def id(self) -> str:
        return agent_id(self.sign_pk, self.enc_pk)

    @property
    def mailbox(self) -> str:
        return mailbox_id(self.sign_pk)

    def to_json(self) -> dict:
        return {"name": self.name, "sign": b64e(self.sign_pk), "enc": b64e(self.enc_pk), "relay": self.relay}

    @classmethod
    def from_json(cls, d: dict) -> "Contact":
        return cls(d["name"], b64d(d["sign"]), b64d(d["enc"]), d.get("relay", ""))


def parse_card(card: str) -> Contact:
    """Parse and verify a self-signed contact card ('avc1.<base64>')."""
    card = "".join(card.split())
    if not card.startswith("avc1."):
        raise CryptoError("not an AgentVeil contact card (expected 'avc1.' prefix)")
    try:
        obj = json.loads(b64d(card[5:]))
        body, sig = obj["c"], b64d(obj["s"])
        VerifyKey(b64d(body["sign"])).verify(CARD_CTX + canonical(body), sig)
        if len(b64d(body["enc"])) != 32:
            raise CryptoError("bad encryption key")
        return Contact(str(body.get("name", ""))[:64], b64d(body["sign"]), b64d(body["enc"]), str(body.get("relay", "")))
    except (KeyError, ValueError, TypeError, nacl.exceptions.BadSignatureError, nacl.exceptions.CryptoError) as e:
        raise CryptoError(f"invalid contact card: {e.__class__.__name__}") from None


@dataclass
class InboundMessage:
    sender_id: str
    sender_name: str
    sender_sign_pk: bytes
    sender_enc_pk: bytes
    sender_relay: str
    ts: int
    msg_id: str
    body: str


class LocalIdentity:
    def __init__(self, sign_sk: SigningKey, enc_sk: PrivateKey, name: str):
        self.sign_sk, self.enc_sk, self.name = sign_sk, enc_sk, name

    @classmethod
    def generate(cls, name: str = "") -> "LocalIdentity":
        ident = cls(SigningKey.generate(), PrivateKey.generate(), name)
        if not name:
            ident.name = "agent-" + ident.id[:6]
        return ident

    @property
    def sign_pk(self) -> bytes:
        return bytes(self.sign_sk.verify_key)

    @property
    def enc_pk(self) -> bytes:
        return bytes(self.enc_sk.public_key)

    @property
    def id(self) -> str:
        return agent_id(self.sign_pk, self.enc_pk)

    @property
    def mailbox(self) -> str:
        return mailbox_id(self.sign_pk)

    # ---- persistence -------------------------------------------------------------------
    def save(self, path: Path, passphrase: str | None) -> None:
        secret = bytes(self.sign_sk) + bytes(self.enc_sk)
        if passphrase:
            salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
            ops, mem = nacl.pwhash.argon2id.OPSLIMIT_MODERATE, nacl.pwhash.argon2id.MEMLIMIT_MODERATE
            key = nacl.pwhash.argon2id.kdf(32, passphrase.encode(), salt, opslimit=ops, memlimit=mem)
            sec = {"kdf": "argon2id", "salt": b64e(salt), "ops": ops, "mem": mem,
                   "data": b64e(nacl.secret.SecretBox(key).encrypt(secret))}
        else:
            sec = {"kdf": "none", "data": b64e(secret)}
        doc = {"v": VERSION, "name": self.name, "id": self.id, "secret": sec}
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=1), encoding="utf-8")
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path, passphrase: str | None) -> "LocalIdentity":
        doc = json.loads(path.read_text(encoding="utf-8"))
        sec = doc["secret"]
        if sec["kdf"] == "argon2id":
            if not passphrase:
                raise CryptoError("identity is passphrase-protected; set AGENTVEIL_PASSPHRASE")
            key = nacl.pwhash.argon2id.kdf(32, passphrase.encode(), b64d(sec["salt"]),
                                           opslimit=sec["ops"], memlimit=sec["mem"])
            try:
                secret = nacl.secret.SecretBox(key).decrypt(b64d(sec["data"]))
            except nacl.exceptions.CryptoError:
                raise CryptoError("wrong passphrase for identity") from None
        else:
            secret = b64d(sec["data"])
        return cls(SigningKey(secret[:32]), PrivateKey(secret[32:64]), doc.get("name", ""))

    # ---- contact card --------------------------------------------------------------------
    def card(self, relay: str) -> str:
        body = {"v": VERSION, "name": self.name, "sign": b64e(self.sign_pk), "enc": b64e(self.enc_pk), "relay": relay}
        sig = self.sign_sk.sign(CARD_CTX + canonical(body)).signature
        return "avc1." + b64e(canonical({"c": body, "s": b64e(sig)}))

    # ---- messages ------------------------------------------------------------------------
    def seal(self, to: Contact, body: str, *, my_relay: str = "") -> bytes:
        if len(body) > MAX_BODY_CHARS:
            raise CryptoError(f"message longer than {MAX_BODY_CHARS} characters")
        inner = {
            "v": VERSION,
            "from": {"name": self.name, "sign": b64e(self.sign_pk), "enc": b64e(self.enc_pk), "relay": my_relay},
            "to": to.id,
            "ts": int(time.time()),
            "id": secrets.token_hex(16),
            "body": body,
        }
        m = canonical(inner)
        sig = self.sign_sk.sign(MSG_CTX + m).signature
        payload = canonical({"m": b64e(m), "s": b64e(sig)})
        return SealedBox(PublicKey(to.enc_pk)).encrypt(pad(payload))

    def open(self, blob: bytes, *, now: float | None = None) -> InboundMessage:
        try:
            payload = unpad(SealedBox(self.enc_sk).decrypt(blob))
            outer = json.loads(payload)
            m, sig = b64d(outer["m"]), b64d(outer["s"])
            inner = json.loads(m)
            frm = inner["from"]
            sign_pk, enc_pk = b64d(frm["sign"]), b64d(frm["enc"])
            VerifyKey(sign_pk).verify(MSG_CTX + m, sig)
        except (KeyError, ValueError, TypeError, nacl.exceptions.CryptoError, nacl.exceptions.BadSignatureError) as e:
            raise CryptoError(f"undecryptable or forged message ({e.__class__.__name__})") from None
        if inner.get("to") != self.id:
            raise CryptoError("message was signed for a different recipient (possible re-forwarding)")
        now = time.time() if now is None else now
        ts = int(inner.get("ts", 0))
        if ts < now - MAX_AGE or ts > now + MAX_SKEW:
            raise CryptoError("message timestamp outside the accepted window (possible replay)")
        return InboundMessage(
            sender_id=agent_id(sign_pk, enc_pk), sender_name=str(frm.get("name", ""))[:64],
            sender_sign_pk=sign_pk, sender_enc_pk=enc_pk, sender_relay=str(frm.get("relay", "")),
            ts=ts, msg_id=str(inner.get("id", "")), body=str(inner.get("body", "")),
        )

    def fetch_request(self, ack: list[str]) -> dict:
        req = {"mailbox": self.mailbox, "sign_pk": b64e(self.sign_pk), "ts": int(time.time()),
               "nonce": secrets.token_hex(16), "ack": list(ack)}
        sig = self.sign_sk.sign(FETCH_CTX + canonical(req)).signature
        return {"req": req, "sig": b64e(sig)}


def verify_fetch_request(doc: dict, *, now: float | None = None) -> dict:
    """Relay-side check: signer owns the mailbox, signature valid, fresh. Returns req."""
    try:
        req, sig = doc["req"], b64d(doc["sig"])
        sign_pk = b64d(req["sign_pk"])
        if mailbox_id(sign_pk) != req["mailbox"]:
            raise CryptoError("mailbox does not belong to this key")
        VerifyKey(sign_pk).verify(FETCH_CTX + canonical(req), sig)
    except (KeyError, ValueError, TypeError, nacl.exceptions.BadSignatureError, nacl.exceptions.CryptoError) as e:
        raise CryptoError(f"bad fetch request ({e.__class__.__name__})") from None
    now = time.time() if now is None else now
    if abs(now - int(req["ts"])) > 300:
        raise CryptoError("stale fetch request")
    if not isinstance(req.get("ack"), list) or len(req["ack"]) > 1000:
        raise CryptoError("bad ack list")
    return req
