"""Agent-side messaging: identity, contacts, send/receive through the tunnel."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ..config import Config
from ..egress import EgressBlocked, EgressPolicy, Identity, check_upstream, make_client, make_loopback_client
from .crypto import Contact, CryptoError, InboundMessage, LocalIdentity, b64d, b64e, fingerprint, parse_card

MAX_SEEN = 5000


class MessagingError(Exception):
    pass


class Messenger:
    def __init__(self, cfg: Config, policy: EgressPolicy):
        self.cfg = cfg
        self.policy = policy
        self.net = Identity(cfg)  # own circuit, separate from browsing
        self.dir = Path(cfg.data_dir)
        self._ident: LocalIdentity | None = None

    # ---- local state -------------------------------------------------------------------
    @property
    def relay(self) -> str:
        return self.cfg.messaging.relay_url.rstrip("/")

    def identity(self) -> LocalIdentity:
        if self._ident is None:
            path = self.dir / "identity.json"
            passphrase = os.environ.get("AGENTVEIL_PASSPHRASE") or None
            if path.exists():
                self._ident = LocalIdentity.load(path, passphrase)
            else:
                self._ident = LocalIdentity.generate()
                self._ident.save(path, passphrase)
        return self._ident

    @property
    def identity_encrypted(self) -> bool:
        path = self.dir / "identity.json"
        return path.exists() and json.loads(path.read_text(encoding="utf-8"))["secret"]["kdf"] != "none"

    def _load(self, name: str, default):
        p = self.dir / name
        if not p.exists():
            return default
        return json.loads(p.read_text(encoding="utf-8"))

    def _save(self, name: str, data) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        p = self.dir / name
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
        tmp.replace(p)

    def contacts(self) -> dict[str, Contact]:
        return {alias: Contact.from_json(d) for alias, d in self._load("contacts.json", {}).items()}

    def add_contact(self, card: str, alias: str = "") -> tuple[str, Contact, bool]:
        """Returns (alias, contact, replaced_existing_key)."""
        c = parse_card(card)
        if c.id == self.identity().id:
            raise MessagingError("that is your own card")
        alias = (alias or c.name or c.id[:8]).strip()[:40]
        data = self._load("contacts.json", {})
        replaced = alias in data and Contact.from_json(data[alias]).id != c.id
        data[alias] = c.to_json()
        self._save("contacts.json", data)
        return alias, c, replaced

    def remove_contact(self, alias: str) -> bool:
        data = self._load("contacts.json", {})
        if data.pop(alias, None) is None:
            return False
        self._save("contacts.json", data)
        return True

    def lookup_sender(self, msg: InboundMessage) -> str | None:
        for alias, c in self.contacts().items():
            if c.sign_pk == msg.sender_sign_pk and c.enc_pk == msg.sender_enc_pk:
                return alias
        return None

    def card(self) -> str:
        if not self.relay:
            raise MessagingError("messaging.relay_url is not configured")
        return self.identity().card(self.relay)

    # ---- network -----------------------------------------------------------------------
    async def _client_for(self, url: str) -> tuple[httpx.AsyncClient, str]:
        host = (urlsplit(url).hostname or "").strip("[]")
        if self.cfg.messaging.allow_direct_loopback_relay and host in ("127.0.0.1", "::1"):
            return make_loopback_client(url), url
        url = self.policy.check_url(url, allow_http=False)
        await check_upstream(self.cfg)
        return make_client(self.cfg, self.net), url

    async def _post(self, url: str, payload: dict) -> dict:
        client, url = await self._client_for(url)
        async with client:
            resp = await client.post(url, json=payload)
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if resp.status_code >= 400:
            raise MessagingError(f"relay answered HTTP {resp.status_code}: {data.get('error', resp.text[:200])}")
        return data

    async def send(self, to: str, text: str) -> Contact:
        contacts = self.contacts()
        contact = contacts.get(to) or next((c for c in contacts.values() if c.id == to), None)
        if contact is None:
            raise MessagingError(f"unknown contact '{to}'. Add their card with msg_add_contact first.")
        if not contact.relay:
            raise MessagingError("contact card has no relay address")
        blob = self.identity().seal(contact, text, my_relay=self.relay)
        await self._post(f"{contact.relay.rstrip('/')}/v1/send", {"to": contact.mailbox, "blob": b64e(blob)})
        return contact

    async def receive(self) -> tuple[list[tuple[InboundMessage, str | None]], list[str]]:
        """Returns ([(message, contact_alias_or_None)], [rejection notes])."""
        if not self.relay:
            raise MessagingError("messaging.relay_url is not configured")
        state = self._load("msgstate.json", {"seen": [], "ack": []})
        ident = self.identity()
        data = await self._post(f"{self.relay}/v1/fetch", ident.fetch_request(state.get("ack", [])))
        seen = list(state.get("seen", []))
        seen_set = set(seen)
        out, notes, ack = [], [], []
        for item in data.get("messages", []):
            ack.append(str(item.get("rid", "")))
            try:
                msg = ident.open(b64d(item["blob"]))
            except (CryptoError, KeyError, ValueError) as e:
                notes.append(f"dropped a message: {e}")
                continue
            if msg.msg_id in seen_set:
                continue
            seen.append(msg.msg_id)
            seen_set.add(msg.msg_id)
            out.append((msg, self.lookup_sender(msg)))
        self._save("msgstate.json", {"seen": seen[-MAX_SEEN:], "ack": ack})
        return out, notes


def describe_identity(m: Messenger) -> str:
    ident = m.identity()
    lines = [
        f"name: {ident.name}",
        f"agent id: {ident.id}",
        f"fingerprint: {fingerprint(ident.id)}",
        f"relay: {m.relay or '(not configured)'}",
        f"identity key file encrypted: {'yes' if m.identity_encrypted else 'NO — set AGENTVEIL_PASSPHRASE before first use to encrypt it'}",
    ]
    try:
        lines.append(f"contact card (share it; peers must verify the fingerprint out-of-band):\n{m.card()}")
    except MessagingError as e:
        lines.append(f"contact card unavailable: {e}")
    return "\n".join(lines)


__all__ = ["Messenger", "MessagingError", "describe_identity", "EgressBlocked"]
