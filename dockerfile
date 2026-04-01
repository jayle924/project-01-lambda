FROM fedora:39 AS builder
RUN dnf install -y clamav clamav-update curl && dnf clean all
RUN mkdir -p /var/lib/clamav

# DB 미리 다운로드 (Wazuh 미러 사용 - 깃허브 액션 IP 차단 우회)
RUN curl -L -o /var/lib/clamav/main.cvd https://packages.wazuh.com/deps/clamav/main.cvd && \
    curl -L -o /var/lib/clamav/daily.cvd https://packages.wazuh.com/deps/clamav/daily.cvd && \
    curl -L -o /var/lib/clamav/bytecode.cvd https://packages.wazuh.com/deps/clamav/bytecode.cvd

# 2단계: 최종 이미지 (Lambda용 Python 3.14)
FROM public.ecr.aws/lambda/python:3.14

# [해결 포인트] dnf install을 하지 않고, 빌더에서 실행 파일과 필수 라이브러리를 모두 복사합니다.
# ClamAV 실행 파일
COPY --from=builder /usr/bin/clamscan /usr/bin/clamscan

# ClamAV 엔진 라이브러리 (핵심!)
COPY --from=builder /usr/lib64/libclam* /usr/lib64/
# ClamAV가 의존하는 기타 라이브러리들 (Fedora에서 검증된 것들)
COPY --from=builder /usr/lib64/libjson-c.so* /usr/lib64/
COPY --from=builder /usr/lib64/libxml2.so* /usr/lib64/
COPY --from=builder /usr/lib64/libpcre2-8.so* /usr/lib64/
COPY --from=builder /usr/lib64/libltdl.so* /usr/lib64/

# 바이러스 DB 복사
COPY --from=builder /var/lib/clamav /var/lib/clamav

# 권한 설정
RUN chmod -R 755 /var/lib/clamav

# Lambda 코드 복사 및 실행
COPY app.py ${LAMBDA_TASK_ROOT}
CMD ["app.lambda_handler"]