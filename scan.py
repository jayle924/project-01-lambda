import subprocess

CLAMSCAN_TIMEOUT_SECONDS = 840                  # Lambda 최대 900초보다 여유 있게

def run_clamscan(scan_root):
    # 수정: -d 옵션으로 DB 경로를 명시적으로 지정합니다.
    # Dockerfile에서 설정한 /var/lib/clamav 경로를 사용합니다.
    cmd = [
        "clamscan", 
        "-d", "/var/lib/clamav/main.cvd", 
        "--recursive", 
        "--no-summary", 
        scan_root
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CLAMSCAN_TIMEOUT_SECONDS,
            check=False,
        )

        # 추가: 만약 에러가 났다면 stderr를 로그에 강제로 찍어봅니다.
        if proc.returncode >= 2:
            print(f"[!] ClamAV 시스템 에러 발생 (stderr): {proc.stderr}")

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
