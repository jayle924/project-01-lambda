import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from typing import Any
from urllib.parse import unquote_plus

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client("s3")


def _sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _safe_extract_zip(zip_path: str, dest_dir: str) -> None:
    abs_dest = os.path.abspath(dest_dir)
    os.makedirs(abs_dest, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            out_path = os.path.join(abs_dest, info.filename)
            abs_out = os.path.abspath(out_path)
            if os.path.commonpath([abs_dest, abs_out]) != abs_dest:
                raise ValueError(f"Unsafe path in archive: {info.filename!r}")
        zf.extractall(abs_dest)


def _run_clamscan(scan_root: str) -> dict[str, Any]:
    """
    clamscan exit: 0=clean, 1=found, 2=error (typical ClamAV semantics).
    """
    cmd = ["clamscan", "--recursive", "--no-summary", scan_root]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    infected_lines = [
        line.strip()
        for line in (proc.stdout or "").splitlines()
        if "FOUND" in line
    ]
    return {
        "command": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
        "infected_report_lines": infected_lines,
    }


def _clamav_verdict(scan_result: dict[str, Any]) -> str:
    code = scan_result.get("exit_code")
    if code == 0:
        return "clean"
    if code == 1:
        return "infected"
    return "error"


def _process_s3_object(bucket: str, key: str) -> dict[str, Any]:
    work = tempfile.mkdtemp(prefix="s3scan_", dir="/tmp")
    local_zip = os.path.join(work, "object.bin")
    extract_dir = os.path.join(work, "extracted")

    try:
        s3_client.download_file(bucket, key, local_zip)

        sha256_hex = _sha256_file(local_zip)

        if not zipfile.is_zipfile(local_zip):
            return {
                "bucket": bucket,
                "key": key,
                "sha256": sha256_hex,
                "error": "Downloaded object is not a valid ZIP file",
                "clamav": None,
            }

        try:
            _safe_extract_zip(local_zip, extract_dir)
        except ValueError as e:
            return {
                "bucket": bucket,
                "key": key,
                "sha256": sha256_hex,
                "error": str(e),
                "clamav": None,
            }

        scan = _run_clamscan(extract_dir)
        verdict = _clamav_verdict(scan)

        return {
            "bucket": bucket,
            "key": key,
            "sha256": sha256_hex,
            "clamav": {
                "verdict": verdict,
                "exit_code": scan.get("exit_code"),
                "command": scan.get("command"),
                "infected_report_lines": scan.get("infected_report_lines"),
                "stdout": scan.get("stdout"),
                "stderr": scan.get("stderr"),
            },
        }
    finally:
        try:
            shutil.rmtree(work, ignore_errors=True)
        except OSError:
            logger.exception("Failed to remove work dir %s", work)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    records = event.get("Records") or []
    if not records:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "No S3 Records in event"}),
        }

    outcomes: list[dict[str, Any]] = []
    for record in records:
        if record.get("eventSource") != "aws:s3" and record.get("EventSource") != "aws:s3":
            continue
        try:
            bucket = record["s3"]["bucket"]["name"]
            key = unquote_plus(record["s3"]["object"]["key"])
        except (KeyError, TypeError) as e:
            outcomes.append({"error": f"Invalid S3 record: {e}"})
            continue

        logger.info("Processing s3://%s/%s", bucket, key)
        try:
            outcomes.append(_process_s3_object(bucket, key))
        except Exception:
            logger.exception("Failed processing s3://%s/%s", bucket, key)
            outcomes.append(
                {
                    "bucket": bucket,
                    "key": key,
                    "error": "processing_failed",
                }
            )

    return {
        "statusCode": 200,
        "body": json.dumps({"results": outcomes}, ensure_ascii=False),
    }
