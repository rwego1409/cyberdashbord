import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from django.conf import settings


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sign_hash(content_hash: str) -> str:
    signing_key = os.getenv("REPORT_SIGNING_KEY", settings.SECRET_KEY)
    return hmac.new(signing_key.encode("utf-8"), content_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def export_root_dir() -> Path:
    default_path = Path(settings.BASE_DIR) / "report_exports"
    return Path(os.getenv("REPORT_EXPORT_DIR", str(default_path)))


def _ledger_path() -> Path:
    return export_root_dir() / "ledger.jsonl"


def _read_last_entry() -> dict | None:
    ledger = _ledger_path()
    if not ledger.exists():
        return None

    with ledger.open("r", encoding="utf-8") as handle:
        lines = [line.strip() for line in handle.readlines() if line.strip()]
    if not lines:
        return None
    return json.loads(lines[-1])


def append_immutable_export_record(
    report_type: str,
    export_format: str,
    artifact_bytes: bytes,
    artifact_extension: str,
    artifact_hash: str,
    signature: str,
) -> dict:
    now = datetime.now(timezone.utc)
    root = export_root_dir()
    root.mkdir(parents=True, exist_ok=True)

    export_id = uuid4().hex
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    file_name = f"{timestamp}_{export_id}.{artifact_extension}"
    file_path = root / file_name

    with file_path.open("xb") as artifact:
        artifact.write(artifact_bytes)

    previous = _read_last_entry()
    previous_chain_hash = previous.get("chain_hash", "") if previous else ""

    entry = {
        "id": export_id,
        "created_at": now.isoformat(),
        "report_type": report_type,
        "format": export_format,
        "sha256": artifact_hash,
        "signature": signature,
        "artifact_path": str(file_path),
        "previous_chain_hash": previous_chain_hash,
    }
    entry["chain_hash"] = sha256_hex(canonical_json_bytes(entry))

    with _ledger_path().open("a", encoding="utf-8") as ledger:
        ledger.write(json.dumps(entry, separators=(",", ":")))
        ledger.write("\n")

    return entry


def list_export_ledger(limit: int = 50) -> list[dict]:
    ledger = _ledger_path()
    if not ledger.exists():
        return []

    with ledger.open("r", encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    return list(reversed(rows[-limit:]))


def verify_export_ledger(limit: int = 200) -> dict:
    ledger = list(reversed(list_export_ledger(limit=limit)))
    if not ledger:
        return {"ok": True, "checked": 0, "issues": []}

    issues: list[str] = []
    previous_chain_hash = ""
    checked = 0
    for row in ledger:
        local = dict(row)
        chain_hash = local.pop("chain_hash", "")
        expected_chain_hash = sha256_hex(canonical_json_bytes(local))
        if chain_hash != expected_chain_hash:
            issues.append(f"chain hash mismatch for id={row.get('id')}")
        if local.get("previous_chain_hash", "") != previous_chain_hash:
            issues.append(f"previous chain mismatch for id={row.get('id')}")
        previous_chain_hash = chain_hash
        checked += 1

    return {"ok": not issues, "checked": checked, "issues": issues}
