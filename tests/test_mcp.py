"""End-to-end: spawn the MCP server over stdio like an agent host would."""

import sys

from mcp import ClientSession, StdioServerParameters, stdio_client


async def test_mcp_server_tools_and_fail_closed(tmp_path, dead_port, socks):
    cfg = tmp_path / "agentveil.toml"
    data_dir = (tmp_path / "data").as_posix()
    cfg.write_text(f'data_dir = "{data_dir}"\n[upstream]\nkind = "tor"\nport = {dead_port}\ncontrol_port = 9\n',
                   encoding="utf-8")
    params = StdioServerParameters(command=sys.executable, args=["-m", "agentveil", "-c", str(cfg), "mcp"])
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        names = {t.name for t in (await session.list_tools()).tools}
        assert {"web_search", "web_fetch", "browser_open", "browser_act", "new_identity",
                "security_status", "msg_send", "msg_receive"} <= names

        res = await session.call_tool("web_fetch", {"url": "https://example.com/"})
        assert res.is_error and "FAIL-CLOSED" in res.content[0].text

        res = await session.call_tool("web_fetch", {"url": "http://192.168.1.1/"})
        assert res.is_error and "BLOCKED" in res.content[0].text

        res = await session.call_tool("security_status", {})
        assert "FAIL-CLOSED" in res.content[0].text

        res = await session.call_tool("msg_whoami", {})
        assert "fingerprint" in res.content[0].text
