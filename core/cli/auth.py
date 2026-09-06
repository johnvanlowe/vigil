"""CLI commands for authentication bootstrapping and credential management."""

import argparse
import secrets
import sys
from typing import Optional


def bootstrap_auth(admin_user: str = "admin") -> dict:
    """Bootstrap administrative credentials for new or upgraded installs."""
    new_token = secrets.token_urlsafe(24)
    print("==========================================")
    print("Vigil Authentication Bootstrap")
    print("==========================================")
    print(f"Admin User:    {admin_user}")
    print(f"One-Time Key:  {new_token}")
    print("Use this key for initial login or API access.")
    print("Please rotate to your production credentials immediately.")
    print("==========================================")
    return {"user": admin_user, "bootstrap_key": new_token}


def main():
    parser = argparse.ArgumentParser(prog="vigil auth")
    sub = parser.add_subparsers(dest="subcommand")

    boot_parser = sub.add_parser("bootstrap", help="Bootstrap initial admin credentials")
    boot_parser.add_argument("--user", default="admin", help="Admin username")

    args = parser.parse_args()
    if args.subcommand == "bootstrap":
        bootstrap_auth(args.user)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
