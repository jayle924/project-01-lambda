FROM public.ecr.aws/lambda/python:3.14

# 1. ClamAV 및 curl 설치 (wget 대신 curl 사용)
RUN dnf install -y clamav clamav-update curl && dnf clean all

# 2. 필수 디렉토리 생성
RUN mkdir -p /var/lib/clamav

# 3. 우회 다운로드: Cloudflare 차단이 없는 Wazuh의 ClamAV 미러 서버 사용
RUN curl -L -o /var/lib/clamav/main.cvd https://packages.wazuh.com/deps/clamav/main.cvd && \
    curl -L -o /var/lib/clamav/daily.cvd https://packages.wazuh.com/deps/clamav/daily.cvd && \
    curl -L -o /var/lib/clamav/bytecode.cvd https://packages.wazuh.com/deps/clamav/bytecode.cvd

# 4. 권한 설정
RUN chmod -R 755 /var/lib/clamav

# 5. Lambda 코드 복사
COPY app.py ${LAMBDA_TASK_ROOT}

# 6. Lambda 핸들러 지정
CMD ["app.lambda_handler"]