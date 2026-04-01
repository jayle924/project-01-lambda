import json
import boto3
import hashlib
import os
import shutil
import subprocess
import tempfile
import urllib.parse
import zipfile

s3 = boto3.client("s3")

def calculate_file_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def safe_extract_zip(zip_path, dest_dir):
    abs_dest = os.path.abspath(dest_dir)
    os.makedirs(abs_dest, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            out_path = os.path.join(abs_dest, info.filename)
            abs_out = os.path.abspath(out_path)
            if os.path.commonpath([abs_dest, abs_out]) != abs_dest:
                raise ValueError(f"Unsafe path in archive: {info.filename!r}")
        zf.extractall(abs_dest)


def run_clamscan(scan_root):
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
    if proc.returncode == 0:
        verdict = "clean"
    elif proc.returncode == 1:
        verdict = "infected"
    else:
        verdict = "error"
    return {
        "verdict": verdict,
        "exit_code": proc.returncode,
        "command": cmd,
        "infected_report_lines": infected_lines,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def lambda_handler(event, context):
    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    key = urllib.parse.unquote_plus(
        event["Records"][0]["s3"]["object"]["key"], encoding="utf-8"
    )

    work = tempfile.mkdtemp(prefix="s3scan_", dir="/tmp")
    tmp_file_path = os.path.join(work, os.path.basename(key) or "object.zip")
    extract_path = os.path.join(work, "extracted")

    try:
        print(f"[*] S3 다운로드 시작: {key}")
        s3.download_file(bucket, key, tmp_file_path)

        file_hash = calculate_file_sha256(tmp_file_path)
        print(f"[*] 파일 SHA-256: {file_hash}")

        if not zipfile.is_zipfile(tmp_file_path):
            return {
                "statusCode": 400,
                "body": json.dumps(
                    {
                        "file_name": key,
                        "hash": file_hash,
                        "status": "Not a ZIP file",
                    },
                    ensure_ascii=False,
                ),
            }

        print(f"[*] 압축 해제 시작: {tmp_file_path}")
        safe_extract_zip(tmp_file_path, extract_path)

        extracted_files = os.listdir(extract_path)
        print(f"[*] 압축 해제 완료: {extracted_files}")

        print("[*] ClamAV 검사 시작")
        clamav = run_clamscan(extract_path)
        print(f"[*] ClamAV 판정: {clamav['verdict']}, exit={clamav['exit_code']}")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "file_name": key,
                    "hash": file_hash,
                    "extracted_count": len(extracted_files),
                    "clamav": clamav,
                    "status": "Success",
                },
                ensure_ascii=False,
            ),
        }

    except Exception as e:
        print(f"[!] 에러 발생: {str(e)}")
        raise e
    finally:
        if os.path.exists(work):
            shutil.rmtree(work, ignore_errors=True)