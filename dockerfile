# 1단계: 빌더(Builder) - ClamAV 패키지가 있는 곳에서 파일만 가져오기
FROM fedora:39 AS builder
RUN dnf install -y clamav clamav-update curl && dnf clean all
RUN mkdir -p /var/lib/clamav

# DB 미리 다운로드 (차단 없는 Wazuh 미러 사용)
RUN curl -L -o /var/lib/clamav/main.cvd https://packages.wazuh.com/deps/clamav/main.cvd && \
    curl -L -o /var/lib/clamav/daily.cvd https://packages.wazuh.com/deps/clamav/daily.cvd && \
    curl -L -o /var/lib/clamav/bytecode.cvd https://packages.wazuh.com/deps/clamav/bytecode.cvd

# 2단계: 최종 이미지 (Lambda용 Python 3.14)
FROM public.ecr.aws/lambda/python:3.14

# 필요한 실행 라이브러리 설치 (최소한의 도구)
RUN dnf install -y json-c pcre2 libprelude libxml2 bzip2-libs libtool-ltdl && dnf clean all

# 빌더 단계에서 설치된 ClamAV 파일들을 람다 이미지로 복사
COPY --from=builder /usr/bin/clamscan /usr/bin/clamscan
COPY --from=builder /usr/lib64/libclam* /usr/lib64/
COPY --from=builder /var/lib/clamav /var/lib/clamav

# 권한 설정
RUN chmod -R 755 /var/lib/clamav

# Lambda 코드 복사 및 실행
COPY app.py ${LAMBDA_TASK_ROOT}
CMD ["app.lambda_handler"]