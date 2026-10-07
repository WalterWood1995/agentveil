import pytest

from agentveil.config import ConfigError, config_from_dict, validate
from agentveil.egress import EgressBlocked, EgressPolicy, Identity, UpstreamUnavailable
from agentveil.fetcher import Fetcher
from agentveil.runtime import Runtime

BLOCKED = [
    "http://127.0.0.1/", "http://localhost:8080/", "http://LOCALHOST./", "http://10.0.0.5/",
    "http://192.168.1.1/admin", "http://172.16.3.4/", "http://169.254.169.254/latest/meta-data",
    "http://100.64.0.1/", "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fe80::1]/",
    "http://2130706433/", "http://0x7f000001/", "http://127.1/", "http://0177.0.0.1/", "http://0/",
    "http://router/", "http://printer.local/", "http://nas.lan/", "http://db.internal/",
    "http://x.localhost/", "file:///etc/passwd", "ftp://example.com/", "javascript:alert(1)",
    "data:text/html,hi", "http://user:pw@example.com/", "https://", "http://[::1",
]


@pytest.mark.parametrize("url", BLOCKED)
def test_policy_blocks(url):
    pol = EgressPolicy(validate(config_from_dict({})))
    with pytest.raises(EgressBlocked):
        pol.check_url(url)


def test_policy_allows_and_upgrades():
    pol = EgressPolicy(validate(config_from_dict({})))
    assert pol.check_url("https://example.com/a?b=1") == "https://example.com/a?b=1"
    assert pol.check_url("http://example.com/a?b=1") == "https://example.com/a?b=1"
    assert pol.check_url("http://example.com:80/x") == "https://example.com/x"
    assert pol.check_url("https://8.8.8.8/") == "https://8.8.8.8/"
    onion = "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
    assert pol.check_url(onion) == onion  # onion: Tor already encrypts end-to-end
    assert pol.check_url("http://example.com/", allow_http=True) == "http://example.com/"


def test_onion_blocked_without_tor():
    pol = EgressPolicy(validate(config_from_dict({"upstream": {"kind": "socks", "port": 1080}})))
    with pytest.raises(EgressBlocked):
        pol.check_url("http://abc.onion/")


@pytest.mark.parametrize("upstream", [
    {"host": "8.8.8.8"},            # a cleartext SOCKS server on the internet
    {"host": "proxy.example.com"},  # would need a local DNS lookup
    {"kind": "http"},
    {"control_host": "10.0.0.2"},
])
def test_upstream_validation(upstream):
    with pytest.raises(ConfigError):
        validate(config_from_dict({"upstream": upstream}))


def test_unknown_config_keys_rejected():
    with pytest.raises(ConfigError):
        config_from_dict({"policy": {"https_onyl": True}})


async def test_fetch_sends_hostname_to_tunnel(socks, make_cfg):
    cfg = make_cfg(socks.server_address[1])
    pol = EgressPolicy(cfg)
    ident = Identity(cfg)
    res, cs = await Fetcher(cfg, pol).fetch(ident, "http://site.test/")
    assert res.status == 200 and "Hello agent" in res.text(cs)
    entry = socks.log[-1]
    assert entry["atyp"] == 3 and entry["host"] == "site.test"  # DOMAIN => resolved by the tunnel
    assert entry["user"] == ident.username and entry["user"].startswith("av-")


async def test_identity_rotation_changes_circuit(socks, make_cfg):
    cfg = make_cfg(socks.server_address[1])
    pol, ident = EgressPolicy(cfg), Identity(cfg)
    f = Fetcher(cfg, pol)
    await f.fetch(ident, "http://site.test/")
    first = socks.log[-1]["user"]
    ident.rotate()
    await f.fetch(ident, "http://site.test/")
    assert socks.log[-1]["user"] != first


async def test_fail_closed_when_tunnel_down(web, dead_port, make_cfg):
    # Policy would allow this local target; only the dead tunnel stands in the way.
    cfg = make_cfg(dead_port, policy={"allow_hosts": ["127.0.0.1"]})
    f = Fetcher(cfg, EgressPolicy(cfg))
    with pytest.raises(UpstreamUnavailable):
        await f.fetch(Identity(cfg), f"http://127.0.0.1:{web.server_address[1]}/")
    assert web.hits == []  # nothing reached the site directly


async def test_env_proxy_variables_ignored(socks, make_cfg, monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "all_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "*")
    cfg = make_cfg(socks.server_address[1])
    res, _ = await Fetcher(cfg, EgressPolicy(cfg)).fetch(Identity(cfg), "http://site.test/")
    assert res.status == 200 and socks.log[-1]["host"] == "site.test"


async def test_redirect_into_private_network_blocked(socks, web, make_cfg):
    cfg = make_cfg(socks.server_address[1])
    f = Fetcher(cfg, EgressPolicy(cfg))
    with pytest.raises(EgressBlocked):
        await f.fetch(Identity(cfg), "http://site.test/redir-private")
    assert "/secret" not in web.hits
    res, cs = await f.fetch(Identity(cfg), "http://site.test/redir-ok")
    assert "Second page reached" in res.text(cs) and res.redirects


async def test_runtime_fetch_renders_sanitized_text(socks, make_cfg):
    rt = Runtime(make_cfg(socks.server_address[1]))
    out = await rt.fetch("http://site.test/")
    assert "Hello agent" in out and "Visible paragraph" in out
    assert "IGNORE ALL PREVIOUS" not in out and "zerowidth" in out
    assert "hidden elements removed" in out and "<<<UNTRUSTED" in out
    assert "http://site.test/page2" in out
    out = await rt.fetch("http://site.test/json")
    assert '"ok": true' in out


async def test_runtime_reports_fail_closed(dead_port, make_cfg):
    rt = Runtime(make_cfg(dead_port))
    status = await rt.status()
    assert "FAIL-CLOSED" in status
    with pytest.raises(Exception, match="FAIL-CLOSED"):
        await rt.fetch("https://example.com/")
