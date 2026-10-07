import json

import pytest

from agentveil.torconfig import TorConfigError, build_torrc


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path / "torbundle"
    pt = root / "tor" / "pluggable_transports"
    pt.mkdir(parents=True)
    (root / "data").mkdir()
    for f in ("lyrebird.exe", "snowflake-client.exe", "conjure-client.exe"):
        (pt / f).write_bytes(b"")
    (root / "tor" / "tor.exe").write_bytes(b"")
    (root / "data" / "geoip").write_text("x")
    (pt / "pt_config.json").write_text(json.dumps({
        "recommendedDefault": "obfs4",
        "pluggableTransports": {
            "lyrebird": "ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec ${pt_path}lyrebird${pt_extension}",
            "snowflake": "ClientTransportPlugin snowflake exec ${pt_path}snowflake-client${pt_extension}",
            "conjure": "ClientTransportPlugin conjure exec ${pt_path}conjure-client${pt_extension} -registerURL https://r.example/api",
        },
        "bridges": {
            "obfs4": ["obfs4 192.0.2.1:443 AAAA cert=x iat-mode=0"],
            "snowflake": ["snowflake 192.0.2.3:80 BBBB fingerprint=BBBB url=https://cdn.example/"],
        },
    }))
    return root


def test_builtin_snowflake(bundle, tmp_path):
    torrc = build_torrc(bundle, tmp_path / "data")
    assert "SocksPort 127.0.0.1:9050 IsolateSOCKSAuth" in torrc
    assert "UseBridges 1" in torrc and "Bridge snowflake 192.0.2.3:80" in torrc
    assert "snowflake-client.exe" in torrc and "lyrebird" not in torrc
    assert "${" not in torrc and "GeoIPFile" in torrc


def test_custom_webtunnel_lines(bundle, tmp_path):
    torrc = build_torrc(bundle, tmp_path / "data",
                        bridge_lines=["Bridge webtunnel 192.0.2.9:443 CCCC url=https://w.example/x ver=0.0.1", "# comment"])
    assert "Bridge webtunnel 192.0.2.9:443" in torrc and "lyrebird.exe" in torrc and "snowflake" not in torrc


def test_tor_over_own_tunnel(bundle, tmp_path):
    torrc = build_torrc(bundle, tmp_path / "data", bridges="none", via_socks="127.0.0.1:1080")
    assert "Socks5Proxy 127.0.0.1:1080" in torrc and "UseBridges" not in torrc
    with pytest.raises(TorConfigError):
        build_torrc(bundle, tmp_path / "data", via_socks="127.0.0.1:1080")  # snowflake can't ride a SOCKS proxy


def test_paths_with_spaces_rejected(bundle, tmp_path):
    with pytest.raises(TorConfigError):
        build_torrc(bundle, tmp_path / "my data")
