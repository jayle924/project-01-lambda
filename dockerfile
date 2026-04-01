# 1) 빌더: Amazon Linux 2023에서 ClamAV 설치
FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS builder

RUN dnf install -y \
    clamav1.4 \
    clamav1.4-lib \
    curl \
    findutils \
    tar \
    gzip \
    unzip \
    && dnf clean all

# DB 디렉토리 준비
RUN mkdir -p /var/lib/clamav && chmod -R 755 /var/lib/clamav

# DB 직접 다운로드
RUN curl -L --fail --retry 3 --connect-timeout 20 \
      -o /var/lib/clamav/main.cvd \
      https://packages.wazuh.com/deps/clamav/main.cvd && \
    curl -L --fail --retry 3 --connect-timeout 20 \
      -o /var/lib/clamav/daily.cvd \
      https://packages.wazuh.com/deps/clamav/daily.cvd && \
    curl -L --fail --retry 3 --connect-timeout 20 \
      -o /var/lib/clamav/bytecode.cvd \
      https://packages.wazuh.com/deps/clamav/bytecode.cvd

# 실행 파일/라이브러리 위치 확인용
RUN which clamscan && ldd /usr/bin/clamscan

# 2) 최종: Lambda Python 3.14
FROM public.ecr.aws/lambda/python:3.14

# 빌더에서 ClamAV 실행 파일과 라이브러리 복사
COPY --from=builder /usr/bin/clamscan /usr/bin/clamscan
COPY --from=builder /usr/lib64/libclamav.so* /usr/lib64/
COPY --from=builder /usr/lib64/libclammspack.so* /usr/lib64/

# ClamAV가 의존하는 자주 필요한 런타임 라이브러리도 같이 복사
COPY --from=builder /usr/lib64/libbz2.so* /usr/lib64/
COPY --from=builder /usr/lib64/libpcre2-8.so* /usr/lib64/
COPY --from=builder /usr/lib64/libxml2.so* /usr/lib64/
COPY --from=builder /usr/lib64/libz.so* /usr/lib64/
COPY --from=builder /usr/lib64/libm.so* /usr/lib64/
COPY --from=builder /usr/lib64/libgcc_s.so* /usr/lib64/
COPY --from=builder /usr/lib64/libstdc++.so* /usr/lib64/

# DB 복사
COPY --from=builder /var/lib/clamav /var/lib/clamav

# Lambda 코드
COPY app.py ${LAMBDA_TASK_ROOT}

CMD ["app.lambda_handler"]