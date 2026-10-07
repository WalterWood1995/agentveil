"""Command line: `agentveil status | search | fetch | open | mcp | relay | msg | tor-config`."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .config import ConfigError, load_config
from .runtime import AgentVeilError, Runtime


def _run(coro_factory, cfg_path):
    async def go():
        rt = Runtime(load_config(cfg_path))
        try:
            return await coro_factory(rt)
        finally:
            await rt.close()

    return asyncio.run(go())


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(prog="agentveil", description="Fail-closed, tunnel-only browser for AI agents")
    ap.add_argument("-c", "--config", help="path to agentveil.toml")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status", help="check tunnel, exit IP and policy")
    p.add_argument("--deep", action="store_true", help="also self-test the hardened browser")
    p = sub.add_parser("search", help="anonymous web search")
    p.add_argument("query", nargs="+")
    p.add_argument("-n", type=int, default=8)
    p = sub.add_parser("fetch", help="fetch a URL as clean text")
    p.add_argument("url")
    p.add_argument("--max-chars", type=int, default=20000)
    p.add_argument("--allow-http", action="store_true")
    p = sub.add_parser("open", help="render a URL in the hardened browser and print its text")
    p.add_argument("url")
    p.add_argument("--no-js", action="store_true")
    p.add_argument("--screenshot", help="save a PNG screenshot here")
    sub.add_parser("new-identity", help="rotate circuit (Tor NEWNYM)")
    sub.add_parser("mcp", help="run the MCP stdio server")
    p = sub.add_parser("relay", help="run a blind message relay (in-memory, no logs)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)

    p = sub.add_parser("msg", help="end-to-end encrypted agent messaging")
    msub = p.add_subparsers(dest="mcmd", required=True)
    msub.add_parser("whoami")
    msub.add_parser("contacts")
    q = msub.add_parser("add")
    q.add_argument("card")
    q.add_argument("--alias", default="")
    q = msub.add_parser("send")
    q.add_argument("to")
    q.add_argument("text", nargs="+")
    msub.add_parser("recv")

    p = sub.add_parser("tor-config", help="write a torrc from an unpacked Tor Expert Bundle")
    p.add_argument("--bundle", required=True, help="folder where tor-expert-bundle was extracted")
    p.add_argument("--bridges", default="snowflake", help="snowflake | obfs4 | meek | none (built-in bridge set)")
    p.add_argument("--bridge-line", action="append", default=[], help="custom bridge line (repeatable)")
    p.add_argument("--bridge-file", help="file with one bridge line per line (e.g. from bridges.torproject.org)")
    p.add_argument("--via-socks", help="run Tor through your own tunnel, e.g. 127.0.0.1:1080 (sing-box/Xray)")
    p.add_argument("--out", help="torrc path (default: <data_dir>/torrc)")

    args = ap.parse_args(argv)
    try:
        return _dispatch(args)
    except (AgentVeilError, ConfigError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


def _dispatch(args) -> int:
    c = args.config
    if args.cmd == "status":
        print(_run(lambda rt: rt.status(deep=args.deep), c))
    elif args.cmd == "search":
        print(_run(lambda rt: rt.search(" ".join(args.query), args.n), c))
    elif args.cmd == "fetch":
        print(_run(lambda rt: rt.fetch(args.url, max_chars=args.max_chars, allow_insecure_http=args.allow_http), c))
    elif args.cmd == "open":
        async def go(rt):
            text = await rt.browser_open(args.url, javascript=not args.no_js)
            if args.screenshot:
                pid = next(iter(rt.browser.pages))
                data, _ = await rt.browser_screenshot(pid)
                Path(args.screenshot).write_bytes(data)
                text += f"\n[screenshot saved to {args.screenshot}]"
            return text
        print(_run(go, c))
    elif args.cmd == "new-identity":
        print(_run(lambda rt: rt.new_identity(), c))
    elif args.cmd == "mcp":
        from .mcp_server import main as mcp_main
        mcp_main(c)
    elif args.cmd == "relay":
        from .messaging.relay import serve
        serve(args.host, args.port)
    elif args.cmd == "msg":
        if args.mcmd == "whoami":
            print(_run(lambda rt: _aw(rt.msg_whoami()), c))
        elif args.mcmd == "contacts":
            print(_run(lambda rt: _aw(rt.msg_contacts()), c))
        elif args.mcmd == "add":
            print(_run(lambda rt: _aw(rt.msg_add_contact(args.card, args.alias)), c))
        elif args.mcmd == "send":
            print(_run(lambda rt: rt.msg_send(args.to, " ".join(args.text)), c))
        elif args.mcmd == "recv":
            print(_run(lambda rt: rt.msg_receive(), c))
    elif args.cmd == "tor-config":
        from .torconfig import TorConfigError, build_torrc, tor_executable
        cfg = load_config(c)
        cfg.data_dir.mkdir(parents=True, exist_ok=True)  # Tor creates only the last path component
        lines = list(args.bridge_line)
        if args.bridge_file:
            lines += Path(args.bridge_file).read_text(encoding="utf-8").splitlines()
        try:
            torrc = build_torrc(Path(args.bundle), cfg.data_dir / "tor-data", bridges=args.bridges,
                                bridge_lines=lines, via_socks=args.via_socks,
                                socks_port=cfg.upstream.port, control_port=cfg.upstream.control_port or 9051)
        except TorConfigError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        out = Path(args.out) if args.out else cfg.data_dir / "torrc"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(torrc, encoding="utf-8")
        exe = tor_executable(Path(args.bundle))
        print(f"wrote {out}\nstart Tor with:\n  \"{exe or 'tor'}\" -f \"{out}\"")
    return 0


async def _aw(value):
    return value


if __name__ == "__main__":
    sys.exit(main())
