import json

LOG_PREVIEW_FILE_LIMIT = 20  # 로그에 출력할 파일 개수 제한


def build_response(status_code, payload):
    return {
        "statusCode": status_code,
        "body": json.dumps(payload, ensure_ascii=False),
    }


def format_bytes(num):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:.2f}{unit}"
        num /= 1024.0
    return f"{num:.2f}PB"


def get_s3_object_size(s3_client, bucket, key):
    response = s3_client.head_object(Bucket=bucket, Key=key)
    return response["ContentLength"]
