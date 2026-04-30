#!/usr/bin/env python3
"""Interactive setup wizard.

Writes a ready-to-use config.json by prompting only for the values
the user really has to choose. Everything else gets a sane default.

Run:
    python setup.py
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import string
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.json"
EXAMPLE_PATH = HERE / "config.example.json"


def _c(code: str, text: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(t: str) -> str: return _c("1", t)
def cyan(t: str) -> str: return _c("36", t)
def green(t: str) -> str: return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def red(t: str) -> str: return _c("31", t)
def dim(t: str) -> str: return _c("2", t)


def prompt(question: str, default: str | None = None) -> str:
    suffix = f" [{dim(default)}]" if default else ""
    while True:
        try:
            raw = input(f"{cyan('?')} {question}{suffix}: ").strip()
        except EOFError:
            print()
            sys.exit(1)
        if not raw and default is not None:
            return default
        if raw:
            return raw
        print(red("  value required"))


def prompt_yes_no(question: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{cyan('?')} {question} [{hint}]: ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False


def random_auth_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def load_base_config() -> dict:
    if EXAMPLE_PATH.exists():
        try:
            with EXAMPLE_PATH.open() as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID",
        "auth_key": "CHANGE_ME_TO_A_STRONG_SECRET",
        "target_url": "http://test.com:80",
        "listen_host": "127.0.0.1",
        "listen_port": 1080,
        "front_domain": "www.google.com",
        "google_ip": "216.239.38.120",
        "relay_timeout": 25,
        "log_level": "INFO",
    }


def write_config(cfg: dict) -> None:
    if CONFIG_PATH.exists():
        backup = CONFIG_PATH.with_suffix(".json.bak")
        shutil.copy2(CONFIG_PATH, backup)
        print(yellow(f"  existing config.json backed up to {backup.name}"))
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")


def main() -> int:
    print()
    print(bold("HTTP Port Forwarder — setup wizard"))
    print(dim("Answer a few questions and we'll write config.json for you."))

    if CONFIG_PATH.exists():
        if not prompt_yes_no("config.json already exists. Overwrite?", default=False):
            print(dim("Nothing changed."))
            return 0

    cfg = load_base_config()

    suggested_key = random_auth_key()
    print()
    print(bold("Shared password (auth_key)"))
    print(dim("  Must match AUTH_KEY inside script/Code.gs."))
    cfg["auth_key"] = prompt("auth_key", default=suggested_key)

    print()
    print(bold("Google Apps Script setup"))
    print(dim("  1. Open https://script.google.com -> New project"))
    print(dim("  2. Paste script/Code.gs from this repo into the editor"))
    print(dim("  3. Set AUTH_KEY in Code.gs to the password above"))
    print(dim("  4. Deploy -> New deployment -> Web app"))
    print(dim("     Execute as: Me   |   Who has access: Anyone"))
    print(dim("  5. Copy the Deployment ID and paste it here"))
    print()

    ids_raw = prompt(
        "Deployment ID(s) - comma-separated for load balancing",
        default=None,
    )
    ids = [x.strip() for x in ids_raw.split(",") if x.strip()]
    if len(ids) == 1:
        cfg["script_id"] = ids[0]
        cfg.pop("script_ids", None)
    else:
        cfg["script_ids"] = ids
        cfg.pop("script_id", None)

    print()
    print(bold("Target HTTP endpoint"))
    print(dim("  The fixed HTTP endpoint GAS will forward requests to."))
    cfg["target_url"] = prompt("target_url", default=str(cfg.get("target_url", "http://test.com:80")))

    print()
    print(bold("Network settings") + dim("  (press enter to accept defaults)"))

    port = prompt("Local listen port", default=str(cfg.get("listen_port", 1080)))
    try:
        cfg["listen_port"] = int(port)
    except ValueError:
        cfg["listen_port"] = 1080

    cfg["front_domain"] = prompt("Front domain (SNI)", default=str(cfg.get("front_domain", "www.google.com")))
    cfg["google_ip"] = prompt("Google IP (optional, leave blank for DNS)", default=str(cfg.get("google_ip", "")))

    write_config(cfg)

    print()
    print(green(f"[OK] wrote {CONFIG_PATH.name}"))
    print()
    print(bold("Next step:"))
    print(f"  python main.py")
    print()
    print(yellow("Reminder: the AUTH_KEY inside script/Code.gs must match the auth_key"))
    print(yellow("you just entered - otherwise the relay will return 'unauthorized'."))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print(dim("Cancelled."))
        sys.exit(130)