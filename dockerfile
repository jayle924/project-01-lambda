FROM public.ecr.aws/lambda/python:3.14

# ClamAV + curl 설치
RUN dnf install -y \
    clamav \
    curl \
    tar \
    gzip \
    unzip \
    findutils \
    && dnf clean all

# DB 디렉토리 준비
RUN mkdir -p /var/lib/clamav && chmod -R 755 /var/lib/clamav

# freshclam은 쓰지 않고, curl로 DB 직접 다운로드
# Wazuh 미러 사용
RUN curl -L --fail --retry 3 --connect-timeout 20 \
      -o /var/lib/clamav/main.cvd \
      https://packages.wazuh.com/deps/clamav/main.cvd && \
    curl -L --fail --retry 3 --connect-timeout 20 \
      -o /var/lib/clamav/daily.cvd \
      https://packages.wazuh.com/deps/clamav/daily.cvd && \
    curl -L --fail --retry 3 --connect-timeout 20 \
      -o /var/lib/clamav/bytecode.cvd \
      https://packages.wazuh.com/deps/clamav/bytecode.cvd

# Lambda 코드 복사
COPY app.py ${LAMBDA_TASK_ROOT}

# 확인용
RUN clamscan --version && ls -lh /var/lib/clamav

CMD ["app.lambda_handler"]