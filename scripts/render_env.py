#!/usr/bin/env python3
"""Decrypt ansible/vault/secrets.yml and write gitignored per-service .env
files for docker-compose / local use.

Each service gets only the secrets it actually needs — collectors holds
the Cisco credentials, publisher holds the GitHub push token, review-app
holds neither. The build brief already said "collectors has no reason to
hold GITHUB_PUSH_TOKEN"; the reverse (review-app holding the push token
and Cisco credentials) is just as true and matters more once review-app
is web-facing (Phase 7/11). GEMINI_API_KEY belongs to the separate
ai-node host (build brief Section 3), not any of these three containers,
so it's intentionally unmapped here rather than handed to a service that
doesn't call it.

Architecture review item 2 (secret isolation): DATABASE_URL used to be
byte-identical across all three services, so review-app — the one
LAN-exposed service, :8080 — held the same full-privilege DB role
collectors does. Each service now gets a distinct vault key mapped onto
the same DATABASE_URL env var the app code reads (common/db.py just does
os.environ["DATABASE_URL"]) — collectors keeps the broad `advisory_engine`
role (it's the only writer of CVE/product/advisory facts), publisher gets
a read-only `advisory_publisher` role (publisher/data.py never writes),
and review gets `advisory_review`, scoped to only the tables a human
reviewer approves/rejects through. See db/sql/001_create_service_roles.sql
for the actual GRANTs — that has to be run manually against db-01, this
script has no DB access of its own."""
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
VAULT_FILE = REPO_ROOT / "ansible" / "vault" / "secrets.yml"
VAULT_PASS_FILE = REPO_ROOT / "ansible" / ".vault_pass.txt"
LOCAL_ANSIBLE_VAULT = REPO_ROOT / ".venv-ansible" / "bin" / "ansible-vault"

# Per-service secret allowlists, as {env_var_name: vault_key} pairs. Vault
# is still the single source of truth for values — this controls both
# which service's .env file a given key is rendered into, and (for
# DATABASE_URL specifically) which distinctly-privileged vault key backs
# it per service, so the env var name the app reads can stay the same
# (DATABASE_URL) while the underlying role differs.
SERVICE_KEYS = {
    "collectors": {
        "DATABASE_URL": "DATABASE_URL",
        "CISCO_CLIENT_ID": "CISCO_CLIENT_ID",
        "CISCO_CLIENT_SECRET": "CISCO_CLIENT_SECRET",
    },
    "publisher": {
        "DATABASE_URL": "DATABASE_URL_PUBLISHER",
        "GITHUB_PUSH_TOKEN": "GITHUB_PUSH_TOKEN",
    },
    "review": {
        "DATABASE_URL": "DATABASE_URL_REVIEW",
    },
}


def _decrypt_secrets() -> dict[str, str]:
    if not VAULT_PASS_FILE.exists():
        sys.exit(f"missing vault password file: {VAULT_PASS_FILE}")

    ansible_vault_bin = (
        str(LOCAL_ANSIBLE_VAULT) if LOCAL_ANSIBLE_VAULT.exists() else "ansible-vault"
    )
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
    raw = yaml.safe_load(result.stdout) or {}
    return {key.upper(): value for key, value in raw.items()}


def main() -> None:
    secrets = _decrypt_secrets()

    known_vault_keys = {
        vault_key for mapping in SERVICE_KEYS.values() for vault_key in mapping.values()
    }
    unmapped = sorted(set(secrets) - known_vault_keys)
    if unmapped:
        print(
            f"note: vault keys not assigned to any service .env (expected for "
            f"secrets belonging to other hosts, e.g. GEMINI_API_KEY -> ai-node): "
            f"{unmapped}",
            file=sys.stderr,
        )

    for service, mapping in SERVICE_KEYS.items():
        env_file = REPO_ROOT / f".env.{service}"
        lines = [
            f"{env_var}={secrets[vault_key]}"
            for env_var, vault_key in mapping.items()
            if vault_key in secrets
        ]
        missing = [vault_key for vault_key in mapping.values() if vault_key not in secrets]
        if missing:
            print(f"warning: {env_file.name} missing vault keys: {missing}", file=sys.stderr)

        env_file.write_text("\n".join(lines) + "\n")
        env_file.chmod(0o600)
        print(f"wrote {env_file} ({len(lines)} vars)")


if __name__ == "__main__":
    main()
