import os
from typing import Any, Mapping, Optional

from botocore.exceptions import ClientError


def publish_scan_notification(sns_client, payload: Mapping[str, Any]) -> Optional[str]:
    """
    SNS Topic을 구독한 수신자(이메일 등)에게 ClamAV 스캔 결과를 발행합니다.
    환경 변수 SNS_TOPIC_ARN이 비어 있으면 발행하지 않고 None을 반환합니다.
    """
    topic_arn = (os.environ.get("SNS_TOPIC_ARN") or "").strip()
    if not topic_arn:
        print("[*] SNS_TOPIC_ARN 미설정 — 알림 생략")
        return None

    clamav = payload.get("clamav") or {}
    verdict = clamav.get("verdict", "unknown")
    file_name = payload.get("file_name", "unknown")

    subject = f"[ClamAV] {verdict} — {file_name}"
    if len(subject) > 100:
        subject = subject[:97] + "..."

    lines = [
        f"파일: {file_name}",
        f"SHA-256: {payload.get('hash', '')}",
        f"객체 크기(bytes): {payload.get('object_size_bytes', '')}",
        f"판정: {verdict}",
        f"exit_code: {clamav.get('exit_code')}",
    ]
    if clamav.get("error_type"):
        lines.append(f"error_type: {clamav['error_type']}")
    infected = clamav.get("infected_report_lines") or []
    if infected:
        lines.append("탐지 내역:")
        lines.extend(f"  - {line}" for line in infected[:30])
    stderr_preview = (clamav.get("stderr_preview") or "")[:2000]
    if stderr_preview:
        lines.append("")
        lines.append("stderr (일부):")
        lines.append(stderr_preview)

    message = "\n".join(lines)

    try:
        resp = sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message,
        )
        mid = resp.get("MessageId")
        print(f"[*] SNS 알림 발행: MessageId={mid}")
        return mid
    except ClientError as e:
        print(f"[!] SNS 발행 실패: {e}")
        return None
