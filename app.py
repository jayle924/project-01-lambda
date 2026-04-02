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
    # 변수 초기화 (에러 방지)
    bucket = None
    key = None

    sqs_record = event["Records"][0]
    body = sqs_record.get("body")

    if isinstance(body, str):
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            print(f"[!] body가 JSON이 아닙니다: {body}")
            return {"status": "ignored", "reason": "body is not valid json"}
    else:
        payload = body or sqs_record

    # 1) S3 이벤트 알림 형태 (S3 -> SQS -> Lambda)
    if isinstance(payload, dict) and payload.get("Records"):
        s3_info = payload["Records"][0].get("s3", {})
        bucket = s3_info.get("bucket", {}).get("name")
        key = urllib.parse.unquote_plus(
            s3_info.get("object", {}).get("key", ""), encoding="utf-8"
        )
    
    # 2) 사용자 정의 JSON 형태 (직접 SQS에 넣었을 때)
    elif isinstance(payload, dict) and "bucket" in payload:
        bucket = payload.get("bucket")
        key = urllib.parse.unquote_plus(payload.get("key", ""), encoding="utf-8")
    
    # 3) 인식할 수 없는 포맷
    else:
        print(f"[!] 알 수 없는 메시지 형식입니다: {payload}")
        return {"status": "ignored", "reason": "invalid payload format"}

    # bucket이나 key가 없으면 이후 로직 진행 불가
    if not bucket or not key:
        print("[!] 버킷 이름 또는 키를 찾을 수 없습니다.")
        return {"status": "error", "message": "Missing bucket or key"}

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
