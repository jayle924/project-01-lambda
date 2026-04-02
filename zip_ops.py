import os
import zipfile

# ZIP 정책 (압축 해제 전·후 검증)
MAX_ZIP_SIZE_BYTES = 200 * 1024 * 1024          # 원본 ZIP 최대 200MB
MAX_TOTAL_UNCOMPRESSED_BYTES = 500 * 1024 * 1024  # 압축 해제 총합 최대 500MB
MAX_FILE_COUNT = 1000                           # 압축 해제 대상 최대 파일 수
MAX_SINGLE_FILE_BYTES = 100 * 1024 * 1024       # 개별 파일 최대 100MB
MAX_PATH_DEPTH = 10                             # 디렉터리 깊이 제한


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

            normalized = os.path.normpath(name)

            if os.path.isabs(name):
                raise ValueError(f"Absolute path is not allowed in archive: {name!r}")

            if normalized.startswith("..") or "/.." in normalized.replace("\\", "/"):
                raise ValueError(f"Unsafe path traversal in archive: {name!r}")

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
