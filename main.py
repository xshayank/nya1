#!/usr/bin/env python3
"""
HTTP Port Forwarder — Forward a fixed HTTP target endpoint via Google Apps Script
(domain-fronted through www.google.com for DPI bypass).

Client → localhost:<listen_port> (plain TCP) → GAS relay → http://target:port
"""

import argparse
import asyncio
import json
import logging
import os
import sys

# Project modules live under ./src — put that folder on sys.path.
_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from forwarder import HTTPForwarder
from constants import __version__
from logging_utils import configure as configure_logging, print_banner


_PLACEHOLDER_AUTH_KEYS = {
    "",
    "CHANGE_ME_TO_A_STRONG_SECRET",
    "your-secret-password-here",
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="http-forwarder",
        description="Forward a fixed HTTP target via Google Apps Script relay.",
    )
    parser.add_argument(
        "-c", "--config",
        default=os.environ.get("DFT_CONFIG", "config.json"),
        help="Path to config file (default: config.json, env: DFT_CONFIG)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help="Override listen port (env: DFT_PORT)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level (env: DFT_LOG_LEVEL)",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    config_path = args.config

    try:
        with open(config_path) as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Config not found: {config_path}")
        wizard = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setup.py")
        if os.path.exists(wizard) and sys.stdin.isatty():
            try:
                answer = input("Run the interactive setup wizard now? [Y/n]: ").strip().lower()
            except EOFError:
                answer = "n"
            if answer in ("", "y", "yes"):
                import subprocess
                rc = subprocess.call([sys.executable, wizard])
                if rc != 0:
                    sys.exit(rc)
                try:
                    with open(config_path) as f:
                        config = json.load(f)
                except Exception as e:
                    print(f"Could not load config after setup: {e}")
                    sys.exit(1)
            else:
                print("Copy config.example.json to config.json and fill in your values,")
                print("or run: python setup.py")
                sys.exit(1)
        else:
            print("Run: python setup.py   (or copy config.example.json to config.json)")
            sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config: {e}")
        sys.exit(1)

    # Environment variable overrides
    if os.environ.get("DFT_AUTH_KEY"):
        config["auth_key"] = os.environ["DFT_AUTH_KEY"]
    if os.environ.get("DFT_SCRIPT_ID"):
        config["script_id"] = os.environ["DFT_SCRIPT_ID"]

    # CLI argument overrides
    if args.port is not None:
        config["listen_port"] = args.port
    elif os.environ.get("DFT_PORT"):
        config["listen_port"] = int(os.environ["DFT_PORT"])

    if args.log_level is not None:
        config["log_level"] = args.log_level
    elif os.environ.get("DFT_LOG_LEVEL"):
        config["log_level"] = os.environ["DFT_LOG_LEVEL"]

    # Validate required fields
    for key in ("auth_key", "target_url"):
        if key not in config:
            print(f"Missing required config key: '{key}'")
            sys.exit(1)

    if config.get("auth_key", "") in _PLACEHOLDER_AUTH_KEYS:
        print(
            "Refusing to start: 'auth_key' is unset or uses a known placeholder.\n"
            "Pick a long random secret and set it in both config.json AND "
            "the AUTH_KEY constant inside Code.gs (they must match)."
        )
        sys.exit(1)

    sid = config.get("script_ids") or config.get("script_id")
    if not sid or (isinstance(sid, str) and sid == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"):
        print("Missing 'script_id' in config.")
        print("Deploy the Apps Script from Code.gs and paste the Deployment ID.")
        sys.exit(1)

    configure_logging(config.get("log_level", "INFO"))
    log = logging.getLogger("Main")

    print_banner(__version__)
    log.info("HTTP Port Forwarder starting")
    log.info("Target URL        : %s", config["target_url"])
    log.info("GAS relay         : SNI=%s → script.google.com",
             config.get("front_domain", "www.google.com"))

    script_ids = config.get("script_ids") or config.get("script_id")
    if isinstance(script_ids, list):
        log.info("Script IDs        : %d scripts (round-robin)", len(script_ids))
        for i, s in enumerate(script_ids):
            log.info("  [%d] %s", i + 1, s)
    else:
        log.info("Script ID         : %s", script_ids)

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        log.info("Stopped")


def _make_exception_handler(log):
    """Suppress harmless Windows WinError 10054 noise from connection cleanup."""
    def handler(loop, context):
        exc = context.get("exception")
        cb  = context.get("handle") or context.get("source_traceback", "")
        if (
            isinstance(exc, ConnectionResetError)
            and "_call_connection_lost" in str(cb)
        ):
            return
        log.error("[asyncio]  %s", context.get("message", context))
        if exc:
            loop.default_exception_handler(context)
    return handler


async def _run(config):
    loop = asyncio.get_running_loop()
    _log = logging.getLogger("asyncio")
    loop.set_exception_handler(_make_exception_handler(_log))
    server = HTTPForwarder(config)
    try:
        await server.start()
    finally:
        await server.stop()


if __name__ == "__main__":
    main()