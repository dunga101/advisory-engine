#!/usr/bin/env python3
"""Decrypt ansible/vault/secrets.yml and write a gitignored .env for docker-compose / local use."""
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
VAULT_FILE = REPO_ROOT / "ansible" / "vault" / "secrets.yml"
VAULT_PASS_FILE = REPO_ROOT / "ansible" / ".vault_pass.txt"
ENV_FILE = REPO_ROOT / ".env"
LOCAL_ANSIBLE_VAULT = REPO_ROOT / ".venv-ansible" / "bin" / "ansible-vault"


def main() -> None:
    if not VAULT_PASS_FILE.exists():
        sys.exit(f"missing vault password file: {VAULT_PASS_FILE}")

    ansible_vault_bin = str(LOCAL_ANSIBLE_VAULT) if LOCAL_ANSIBLE_VAULT.exists() else "ansible-vault"
    result = subprocess.run(
        [
            ansible_vault_bin,
            "view",
            "--vault-password-file",
            str(VAULT_PASS_FILE),
            str(VAULT_FILE),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    secrets = yaml.safe_load(result.stdout) or {}

    lines = [f"{key.upper()}={value}" for key, value in secrets.items()]
    ENV_FILE.write_text("\n".join(lines) + "\n")
    ENV_FILE.chmod(0o600)
    print(f"wrote {ENV_FILE} ({len(lines)} vars)")


if __name__ == "__main__":
    main()
