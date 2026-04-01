FROM public.ecr.aws/lambda/python:3.14

# 1. ClamAV 및 wget 설치
RUN dnf install -y clamav clamav-update wget && dnf clean all

# 2. 필수 디렉토리 생성
RUN mkdir -p /var/lib/clamav

# 3. freshclam 대신 수동으로 DB 파일 직접 다운로드 (GitHub Actions IP 차단 우회)
# User-Agent를 조작하여 일반 웹 브라우저의 요청인 것처럼 속입니다.
RUN wget --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -O /var/lib/clamav/main.cvd https://database.clamav.net/main.cvd && \
    wget --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -O /var/lib/clamav/daily.cvd https://database.clamav.net/daily.cvd && \
    wget --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -O /var/lib/clamav/bytecode.cvd https://database.clamav.net/bytecode.cvd

# 4. 권한 설정 (Lambda 실행 시 읽을 수 있도록)
RUN chmod -R 755 /var/lib/clamav

# 5. Lambda 코드 복사
COPY app.py ${LAMBDA_TASK_ROOT}

# 6. Lambda 핸들러 지정
CMD ["app.lambda_handler"]