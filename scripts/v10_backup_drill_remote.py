#!/usr/bin/env python3
"""Back up every V10 Relay SQLite store online and prove the backup restores.

For each Relay this takes a consistent online copy of every durable store with
SQLite's backup API into a dated directory under the node root, then restores
each copy into a scratch directory and checks ``PRAGMA integrity_check``,
schema and per-table row counts against the backup.  Production files are
only read; nothing is restored over them.  The report is JSON evidence.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".codex-run/mesh"))

import remote  # type: ignore  # noqa: E402


REMOTE_ROOT = "/opt/mycomesh-v10-dynamic-20260926"
PYTHON = "/opt/mycomesh-mesh/venv/bin/python"
DRILL = r'''
import hashlib, json, os, shutil, sqlite3, sys, tempfile, time
data, target = sys.argv[1], sys.argv[2]
os.makedirs(target, mode=0o700, exist_ok=False)

def describe(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        schema = sorted(row[0] for row in db.execute(
            "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"))
        tables = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        counts = {name: db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0] for name in tables}
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        db.close()
    return {"schema_sha256": hashlib.sha256(json.dumps(schema).encode()).hexdigest(),
            "rows": counts, "integrity": integrity}

report = {"backup_dir": target, "stores": {}}
for name in sorted(os.listdir(data)):
    if not name.endswith(".sqlite3"):
        continue
    source = os.path.join(data, name)
    backup = os.path.join(target, name)
    started = time.monotonic()
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=30)
    dst = sqlite3.connect(backup)
    try:
        src.backup(dst)
    finally:
        dst.close(); src.close()
    os.chmod(backup, 0o600)
    backup_seconds = round(time.monotonic() - started, 3)
    backed_up = describe(backup)
    scratch = tempfile.mkdtemp(prefix="mycomesh-restore-")
    try:
        restored_path = os.path.join(scratch, name)
        started = time.monotonic()
        shutil.copy2(backup, restored_path)
        restored = describe(restored_path)
        restore_seconds = round(time.monotonic() - started, 3)
    finally:
        shutil.rmtree(scratch)
    with open(backup, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    report["stores"][name] = {
        "bytes": os.path.getsize(backup), "sha256": digest,
        "backup_seconds": backup_seconds, "restore_verify_seconds": restore_seconds,
        "integrity": restored["integrity"], "rows": restored["rows"],
        "restore_matches_backup": restored == backed_up and restored["integrity"] == "ok",
    }
report["ok"] = bool(report["stores"]) and all(s["restore_matches_backup"] for s in report["stores"].values())
print(json.dumps(report, sort_keys=True))
'''


def drill(node: str) -> dict[str, Any]:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    target = f"{REMOTE_ROOT}/backups/{stamp}"
    script = f"/tmp/mycomesh-backup-drill-{stamp}.py"
    client = remote.connect(node)
    try:
        with client.open_sftp() as sftp:
            with sftp.file(script, "wb") as handle:
                handle.write(DRILL.encode())
            sftp.chmod(script, 0o600)
        rc, out, err = remote.execute(
            client,
            f"mkdir -m 0700 -p {shlex.quote(REMOTE_ROOT + '/backups')} && "
            f"{PYTHON} {shlex.quote(script)} {shlex.quote(REMOTE_ROOT + '/data')} {shlex.quote(target)}; "
            f"status=$?; rm -f -- {shlex.quote(script)}; exit $status",
            timeout=300,
        )
        if rc:
            raise RuntimeError(remote.scrub(err or out).strip()[-1200:])
        return {"node": node, **json.loads(out)}
    finally:
        client.close()
        if getattr(client, "_mesh_jump", None):
            client._mesh_jump.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", action="append", choices=("relay1", "relay3"))
    args = parser.parse_args()
    ok = True
    for node in args.node or ["relay1", "relay3"]:
        try:
            result = drill(node)
        except Exception as exc:
            result = {"node": node, "ok": False, "error": remote.scrub(str(exc))}
        ok = ok and result.get("ok") is True
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
