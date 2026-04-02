import os
import json
import shutil
import tempfile
import urllib.parse
import zipfile

import boto3
from botocore.exceptions import ClientError

from file_hash import calculate_file_sha256
from scan import run_clamscan
from sns import publish_scan_notification
from util import (
    LOG_PREVIEW_FILE_LIMIT,
    build_response,
    format_bytes,
    get_s3_object_size,
)
from zip_ops import (
    MAX_ZIP_SIZE_BYTES,
    list_all_extracted_files,
    safe_extract_zip,
    validate_zip_contents,
)

s3 = boto3.client("s3")
sns_client = boto3.client("sns")


def lambda_handler(event, context):
    # S3 직접 트리거 대신 SQS를 중간에 두면, SQS 이벤트의 Record.body에 S3 이벤트(JSON)가 문자열로 들어옵니다.
    # (구성에 따라 body 포맷이 달라질 수 있어, 최대한 방어적으로 파싱합니다.)
    sqs_record = event["Records"][0]
    body = sqs_record.get("body")

    if isinstance(body, str):
        payload = json.loads(body)
    else:
        payload = body or sqs_record

    # 1) body가 "S3 event" 형태라면 payload["Records"][0]["s3"]를 사용
    if isinstance(payload, dict) and payload.get("Records"):
        bucket = payload["Records"][0]["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(
            payload["Records"][0]["s3"]["object"]["key"], encoding="utf-8"
        )
    else:
        # 2) body가 단순 {bucket, key} 형태라면 그 키를 사용
        bucket = payload["bucket"]
        key = urllib.parse.unquote_plus(payload["key"], encoding="utf-8")

    work = tempfile.mkdtemp(prefix="s3scan_", dir="/tmp")
    tmp_file_path = os.path.join(work, os.path.basename(key) or "object.zip")
    extract_path = os.path.join(work, "extracted")

    try:
        print(f"[*] S3 이벤트 수신 - bucket={bucket}, key={key}")

        object_size = get_s3_object_size(s3, bucket, key)
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

        # print(f"[*] S3 다운로드 시작: {key}")
        s3.download_file(bucket, key, tmp_file_path)

        file_hash = calculate_file_sha256(tmp_file_path)
        # print(f"[*] 파일 SHA-256: {file_hash}")

        if not zipfile.is_zipfile(tmp_file_path):
            return build_response(
                400,
                {
                    "file_name": key,
                    "hash": file_hash,
                    "status": "Not a ZIP file",
                },
            )

        # print("[*] ZIP 내부 유효성 검사 시작")
        zip_meta = validate_zip_contents(tmp_file_path)
        # print(
        #     f"[*] ZIP 검사 완료 - files={zip_meta['total_files']}, "
        #     f"estimated_uncompressed={zip_meta['total_uncompressed']} bytes "
        #     f"({format_bytes(zip_meta['total_uncompressed'])})"
        # )

        preview_files = zip_meta["file_names"][:LOG_PREVIEW_FILE_LIMIT]
        # print(f"[*] ZIP 내부 파일 미리보기({len(preview_files)}개): {preview_files}")

        # print(f"[*] 압축 해제 시작: {tmp_file_path}")
        safe_extract_zip(tmp_file_path, extract_path)

        extracted_files = list_all_extracted_files(extract_path)
        extracted_count = len(extracted_files)
        extracted_preview = extracted_files[:LOG_PREVIEW_FILE_LIMIT]

        print(f"[*] 압축 해제 완료 - total_files={extracted_count}")
        # print(f"[*] 압축 해제 파일 미리보기({len(extracted_preview)}개): {extracted_preview}")

        # print("[*] ClamAV 검사 시작")
        clamav = run_clamscan(extract_path)
        print(f"[*] ClamAV 판정: {clamav['verdict']}, exit={clamav['exit_code']}")

        response_clamav = {
            "verdict": clamav["verdict"],
            "exit_code": clamav["exit_code"],
            "infected_report_lines": clamav["infected_report_lines"][:50],
            "stderr_preview": clamav["stderr"][:3000],
            "error_type": clamav.get("error_type"),
        }

        final_response_body = {
            "file_name": key,
            "hash": file_hash,
            "object_size_bytes": object_size,
            "zip_entry_count": zip_meta["total_files"],
            "estimated_uncompressed_bytes": zip_meta["total_uncompressed"],
            "extracted_count": extracted_count,
            "clamav": response_clamav,
            "status": "Success",
        }

        publish_scan_notification(sns_client, final_response_body)

        return build_response(200, final_response_body)

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
        print(f"[!] 유효하지 않은 ZIP 파일: {str(e)}")
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
