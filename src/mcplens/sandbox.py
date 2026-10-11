"""Sandbox for dynamic probes.

The server under test is launched with HOME pointed at a throwaway tree
stocked with canary files (unique token strings in fake credential files).
Nothing ever touches the real HOME. Filesystem state is hashed before and
after probing so undeclared writes are observable.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Canary:
    relpath: str  # relative to sandbox HOME
    token: str    # unique string planted in the file's contents


@dataclass
class Sandbox:
    root: Path
    home: Path
    work: Path
    canaries: list[Canary] = field(default_factory=list)

    @classmethod
    def create(cls, base: str | None = None) -> "Sandbox":
        root = Path(tempfile.mkdtemp(prefix="mcplens-sandbox-", dir=base))
        home = root / "home"
        work = root / "work"
        home.mkdir(parents=True)
        work.mkdir(parents=True)

        suffix = secrets.token_hex(6)
        canaries: list[Canary] = []

        def plant(relpath: str, body: str) -> None:
            token = f"MCPLENS-CANARY-{suffix}-{len(canaries)}"
            path = home / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body.replace("__TOKEN__", token), encoding="utf-8")
            canaries.append(Canary(relpath=relpath, token=token))

        plant(".ssh/id_rsa",
              "-----BEGIN OPENSSH PRIVATE KEY-----\n__TOKEN__\n"
              "-----END OPENSSH PRIVATE KEY-----\n")
        plant(".aws/credentials",
              "[default]\naws_access_key_id = __TOKEN__\n"
              "aws_secret_access_key = canary-secret\n")
        plant("canary_note.txt", "This is a private note. Token: __TOKEN__\n")
        plant("Documents/finances.txt", "Account balances (private). Token: __TOKEN__\n")

        return cls(root=root, home=home, work=work, canaries=canaries)

    def env(self) -> dict[str, str]:
        """Environment overrides for the server process."""
        return {
            "HOME": str(self.home),
            "USERPROFILE": str(self.home),
            "TMPDIR": str(self.root / "tmp"),
            "MCPLENS_SANDBOX": "1",
        }

    def tokens(self) -> dict[str, str]:
        """token string -> canary relpath it came from."""
        return {c.token: c.relpath for c in self.canaries}

    def tree_hashes(self) -> dict[str, str]:
        """relpath -> sha256 for every file under home/ and work/."""
        out: dict[str, str] = {}
        for base in (self.home, self.work):
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    rel = str(path.relative_to(self.root))
                    try:
                        out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
                    except OSError:
                        pass
        return out

    def cleanup(self) -> None:
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)


def diff_trees(before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
    """Return {created, modified, deleted} relpaths between two tree hashes."""
    created = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(p for p in set(before) & set(after) if before[p] != after[p])
    return {"created": created, "modified": modified, "deleted": deleted}
