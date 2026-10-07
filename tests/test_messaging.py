import threading

import pytest

from agentveil.egress import EgressPolicy
from agentveil.messaging.client import Messenger, MessagingError
from agentveil.messaging.crypto import CryptoError, LocalIdentity, b64d, b64e, parse_card
from agentveil.messaging.relay import make_server


def test_seal_open_roundtrip_and_tamper():
    alice, bob = LocalIdentity.generate("alice"), LocalIdentity.generate("bob")
    bob_contact = parse_card(bob.card("http://relay.example"))
    blob = alice.seal(bob_contact, "你好 bob", my_relay="http://relay.example")
    msg = bob.open(blob)
    assert msg.body == "你好 bob" and msg.sender_id == alice.id and msg.sender_name == "alice"

    tampered = bytearray(blob)
    tampered[60] ^= 1
    with pytest.raises(CryptoError):
        bob.open(bytes(tampered))
    with pytest.raises(CryptoError):  # not addressed to carol
        LocalIdentity.generate("carol").open(blob)


def test_forwarded_message_rejected():
    """Bob re-encrypting Alice's signed message to Carol must not look like Alice wrote to Carol."""
    import nacl.public
    alice, bob, carol = (LocalIdentity.generate(n) for n in ("alice", "bob", "carol"))
    blob = alice.seal(parse_card(bob.card("r")), "for bob only")
    inner = nacl.public.SealedBox(bob.enc_sk).decrypt(blob)
    forwarded = nacl.public.SealedBox(nacl.public.PublicKey(carol.enc_pk)).encrypt(inner)
    with pytest.raises(CryptoError, match="different recipient"):
        carol.open(forwarded)


def test_padding_hides_length():
    a, b = LocalIdentity.generate(), LocalIdentity.generate()
    c = parse_card(b.card("r"))
    assert len(a.seal(c, "hi")) == len(a.seal(c, "x" * 300))


def test_card_tamper_detected():
    card = LocalIdentity.generate("bob").card("http://relay.example")
    raw = b64d(card[5:]).replace(b"relay.example", b"evil.example!")
    with pytest.raises(CryptoError):
        parse_card("avc1." + b64e(raw))


def test_identity_passphrase(tmp_path):
    ident = LocalIdentity.generate("x")
    ident.save(tmp_path / "id.json", "correct horse")
    assert LocalIdentity.load(tmp_path / "id.json", "correct horse").id == ident.id
    with pytest.raises(CryptoError):
        LocalIdentity.load(tmp_path / "id.json", "wrong")
    assert "secret" in (tmp_path / "id.json").read_text() and b64e(bytes(ident.sign_sk)) not in (tmp_path / "id.json").read_text()


@pytest.fixture
def relay():
    srv = make_server("127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _messenger(make_cfg, tmp_path, name, relay_url, port, **messaging):
    cfg = make_cfg(port, messaging={"relay_url": relay_url, **messaging})
    cfg.data_dir = tmp_path / name
    return Messenger(cfg, EgressPolicy(cfg))


async def test_relay_end_to_end_loopback(relay, make_cfg, tmp_path, dead_port):
    url = f"http://127.0.0.1:{relay.server_address[1]}"
    alice = _messenger(make_cfg, tmp_path, "alice", url, dead_port, allow_direct_loopback_relay=True)
    bob = _messenger(make_cfg, tmp_path, "bob", url, dead_port, allow_direct_loopback_relay=True)
    alice.add_contact(bob.card(), "bob")
    bob.add_contact(alice.card(), "alice")
    await alice.send("bob", "meet at the usual place")
    msgs, notes = await bob.receive()
    assert [(m.body, alias) for m, alias in msgs] == [("meet at the usual place", "alice")] and not notes
    assert (await bob.receive())[0] == []  # acked + deduplicated

    # someone else cannot drain bob's mailbox
    mallory = LocalIdentity.generate("mallory")
    req = mallory.fetch_request([])
    req["req"]["mailbox"] = bob.identity().mailbox
    import httpx
    async with httpx.AsyncClient(trust_env=False) as c:
        r = await c.post(f"{url}/v1/fetch", json=req)
    assert r.status_code == 403

    # unknown contact
    with pytest.raises(MessagingError):
        await alice.send("nobody", "x")


async def test_replayed_message_ignored(relay, make_cfg, tmp_path, dead_port):
    import httpx
    url = f"http://127.0.0.1:{relay.server_address[1]}"
    alice = _messenger(make_cfg, tmp_path, "alice", url, dead_port, allow_direct_loopback_relay=True)
    bob = _messenger(make_cfg, tmp_path, "bob", url, dead_port, allow_direct_loopback_relay=True)
    blob = b64e(alice.identity().seal(parse_card(bob.card()), "once"))
    async with httpx.AsyncClient(trust_env=False) as c:
        for _ in range(2):  # an attacker re-injects a captured ciphertext
            assert (await c.post(f"{url}/v1/send", json={"to": bob.identity().mailbox, "blob": blob})).status_code == 202
    msgs, _ = await bob.receive()
    assert [m.body for m, _ in msgs] == ["once"]
    async with httpx.AsyncClient(trust_env=False) as c:
        await c.post(f"{url}/v1/send", json={"to": bob.identity().mailbox, "blob": blob})
    assert (await bob.receive())[0] == []


async def test_relay_traffic_goes_through_tunnel(relay, socks, make_cfg, tmp_path):
    socks.mapping["relay.test"] = ("127.0.0.1", relay.server_address[1])
    port = socks.server_address[1]
    alice = _messenger(make_cfg, tmp_path, "alice", "http://relay.test", port)
    bob = _messenger(make_cfg, tmp_path, "bob", "http://relay.test", port)
    alice.add_contact(bob.card(), "bob")
    await alice.send("bob", "via tunnel")
    msgs, _ = await bob.receive()
    assert msgs[0][0].body == "via tunnel" and msgs[0][1] is None  # bob hasn't added alice: unknown sender
    assert {e["host"] for e in socks.log} == {"relay.test"}


async def test_loopback_relay_requires_opt_in(relay, make_cfg, tmp_path, dead_port):
    url = f"http://127.0.0.1:{relay.server_address[1]}"
    m = _messenger(make_cfg, tmp_path, "m", url, dead_port)
    with pytest.raises(Exception):  # private address through the tunnel is refused by policy
        await m.receive()
