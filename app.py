import json
import boto3
import hashlib
import os
import shutil
import subprocess
import tempfile
import urllib.parse
import zipfile
from botocore.exceptions import ClientError

s3 = boto3.client("s3")

# =========================
# 설정값
# =========================
MAX_ZIP_SIZE_BYTES = 200 * 1024 * 1024          # 원본 ZIP 최대 200MB
MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 압축 해제 총합 최대 500MB
MAX_FILE_COUNT = 1000                           # 압축 해제 대상 최대 파일 수
MAX_SINGLE_FILE_BYTES = 100 * 1024 * 1024       # 개별 파일 최대 100MB
MAX_PATH_DEPTH = 10                             # 디렉터리 깊이 제한
CLAMSCAN_TIMEOUT_SECONDS = 840                  # Lambda 최대 900초보다 여유 있게
LOG_FILE_LIST_LIMIT = 20                        # 로그에 출력할 파일 개수 제한


def calculate_file_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def format_bytes(num):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:.2f}{unit}"
        num /= 1024.0
    return f"{num:.2f}PB"


def get_s3_object_size(bucket, key):
    response = s3.head_object(Bucket=bucket, Key=key)
    return response["ContentLength"]


def validate_zip_contents(zip_path):
    """
    ZIP 내부 엔트리를 검사하여
    - 경로 탈출 방지
    - 압축 해제 총량 제한
    - 파일 수 제한
    - 개별 파일 크기 제한
    - 경로 깊이 제한
    등을 수행
    """
    total_uncompressed = 0
    total_files = 0
    file_names = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()

        if not infos:
            raise ValueError("ZIP archive is empty")

        for info in infos:
            name = info.filename

            # 디렉터리 엔트리도 경로 검사는 필요
            normalized = os.path.normpath(name)

            if os.path.isabs(name):
                raise ValueError(f"Absolute path is not allowed in archive: {name!r}")

            if normalized.startswith("..") or "/.." in normalized.replace("\\", "/"):
                raise ValueError(f"Unsafe path traversal in archive: {name!r}")

            # 디렉터리 깊이 제한
            depth = len([p for p in normalized.replace("\\", "/").split("/") if p not in ("", ".")])
            if depth > MAX_PATH_DEPTH:
                raise ValueError(f"Path depth exceeded limit: {name!r}")

            if info.is_dir():
                continue

            total_files += 1
            total_uncompressed += info.file_size
            file_names.append(name)

            if total_files > MAX_FILE_COUNT:
                raise ValueError(
                    f"Too many files in ZIP: {total_files} > {MAX_FILE_COUNT}"
                )

            if info.file_size > MAX_SINGLE_FILE_BYTES:
                raise ValueError(
                    f"Single file too large in ZIP: {name!r}, "
                    f"{info.file_size} bytes > {MAX_SINGLE_FILE_BYTES}"
                )

            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ValueError(
                    f"Total uncompressed size too large: "
                    f"{total_uncompressed} bytes > {MAX_TOTAL_UNCOMPRESSED_BYTES}"
                )

    return {
        "total_files": total_files,
        "total_uncompressed": total_uncompressed,
        "file_names": file_names,
    }


def safe_extract_zip(zip_path, dest_dir):
    """
    validate_zip_contents()를 통과한 뒤 실제 압축 해제 수행
    """
    abs_dest = os.path.abspath(dest_dir)
    os.makedirs(abs_dest, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            out_path = os.path.join(abs_dest, info.filename)
            abs_out = os.path.abspath(out_path)

            if os.path.commonpath([abs_dest, abs_out]) != abs_dest:
                raise ValueError(f"Unsafe path in archive: {info.filename!r}")

        zf.extractall(abs_dest)


def list_all_extracted_files(root_dir):
    files = []
    for base, _, filenames in os.walk(root_dir):
        for filename in filenames:
            full_path = os.path.join(base, filename)
            rel_path = os.path.relpath(full_path, root_dir)
            files.append(rel_path)
    return files


def run_clamscan(scan_root):
    cmd = ["clamscan", "--recursive", "--no-summary", scan_root]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLAMSCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return {
            "verdict": "error",
            "exit_code": None,
            "command": cmd,
            "infected_report_lines": [],
            "stdout": e.stdout or "",
            "stderr": (e.stderr or "") + f"\nClamAV scan timed out after {CLAMSCAN_TIMEOUT_SECONDS} seconds",
            "error_type": "ClamAVTimeout",
        }

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
        "error_type": None,
    }


def build_response(status_code, payload):
    return {
        "statusCode": status_code,
        "body": json.dumps(payload, ensure_ascii=False),
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
        print(f"[*] S3 이벤트 수신 - bucket={bucket}, key={key}")

        # 1) 원본 ZIP 크기 사전 점검
        object_size = get_s3_object_size(bucket, key)
        print(f"[*] S3 객체 크기: {object_size} bytes ({format_bytes(object_size)})")

        if object_size > MAX_ZIP_SIZE_BYTES:
            return build_response(
                413,
                {
                    "file_name": key,
                    "status": "ZIP file too large",
                    "object_size_bytes": object_size,
                    "max_allowed_zip_size_bytes": MAX_ZIP_SIZE_BYTES,
                },
            )

        # 2) 다운로드
        print(f"[*] S3 다운로드 시작: {key}")
        s3.download_file(bucket, key, tmp_file_path)

        # 3) 해시 계산
        file_hash = calculate_file_sha256(tmp_file_path)
        print(f"[*] 파일 SHA-256: {file_hash}")

        # 4) ZIP 여부 검사
        if not zipfile.is_zipfile(tmp_file_path):
            return build_response(
                400,
                {
                    "file_name": key,
                    "hash": file_hash,
                    "status": "Not a ZIP file",
                },
            )

        # 5) ZIP 내부 구조/용량 검사
        print("[*] ZIP 내부 유효성 검사 시작")
        zip_meta = validate_zip_contents(tmp_file_path)
        print(
            f"[*] ZIP 검사 완료 - files={zip_meta['total_files']}, "
            f"estimated_uncompressed={zip_meta['total_uncompressed']} bytes "
            f"({format_bytes(zip_meta['total_uncompressed'])})"
        )

        # 로그 과다 방지
        preview_files = zip_meta["file_names"][:LOG_FILE_LIST_LIMIT]
        print(f"[*] ZIP 내부 파일 미리보기({len(preview_files)}개): {preview_files}")

        # 6) 압축 해제
        print(f"[*] 압축 해제 시작: {tmp_file_path}")
        safe_extract_zip(tmp_file_path, extract_path)

        # 7) 실제 압축 해제된 전체 파일 수 집계
        extracted_files = list_all_extracted_files(extract_path)
        extracted_count = len(extracted_files)
        extracted_preview = extracted_files[:LOG_FILE_LIST_LIMIT]

        print(f"[*] 압축 해제 완료 - total_files={extracted_count}")
        print(f"[*] 압축 해제 파일 미리보기({len(extracted_preview)}개): {extracted_preview}")

        # 8) ClamAV 검사
        print("[*] ClamAV 검사 시작")
        clamav = run_clamscan(extract_path)
        print(f"[*] ClamAV 판정: {clamav['verdict']}, exit={clamav['exit_code']}")

        # stdout/stderr가 너무 길 수 있으니 응답용으로 제한
        response_clamav = {
            "verdict": clamav["verdict"],
            "exit_code": clamav["exit_code"],
            "infected_report_lines": clamav["infected_report_lines"][:50],
            "stderr_preview": clamav["stderr"][:3000],
            "error_type": clamav.get("error_type"),
        }

        return build_response(
            200,
            {
                "file_name": key,
                "hash": file_hash,
                "object_size_bytes": object_size,
                "zip_entry_count": zip_meta["total_files"],
                "estimated_uncompressed_bytes": zip_meta["total_uncompressed"],
                "extracted_count": extracted_count,
                "clamav": response_clamav,
                "status": "Success",
            },
        )

    except zipfile.BadZipFile:
        print("[!] 손상된 ZIP 파일입니다.")
        return build_response(
            400,
            {
                "file_name": key,
                "status": "Bad ZIP file",
            },
        )

    except ClientError as e:
        print(f"[!] S3 처리 오류: {str(e)}")
        return build_response(
            500,
            {
                "file_name": key,
                "status": "S3 operation failed",
                "error": str(e),
            },
        )

    except ValueError as e:
        # ZIP bomb, path traversal, 파일 수 초과 등 정책 위반
        print(f"[!] ZIP 정책 위반: {str(e)}")
        return build_response(
            400,
            {
                "file_name": key,
                "status": "ZIP validation failed",
                "error": str(e),
            },
        )

    except Exception as e:
        print(f"[!] 예상치 못한 에러 발생: {str(e)}")
        return build_response(
            500,
            {
                "file_name": key,
                "status": "Internal error",
                "error": str(e),
            },
        )

    finally:
        if os.path.exists(work):
            shutil.rmtree(work, ignore_errors=True)
            print(f"[*] 작업 디렉터리 정리 완료: {work}")