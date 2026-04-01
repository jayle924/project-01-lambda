FROM public.ecr.aws/lambda/python:3.14

# 1. ClamAV 설치
RUN dnf install -y clamav clamav-update && dnf clean all

# 2. 필수 디렉토리 생성 및 권한 설정
RUN mkdir -p /var/lib/clamav && chmod 755 /var/lib/clamav

# 3. freshclam 설정 파일 생성 (핵심 수정 사항)
# DatabaseMirror를 지정해줘야 어디서 받을지 압니다.
RUN echo "DatabaseDirectory /var/lib/clamav" > /etc/freshclam.conf && \
    echo "UpdateLogFile /tmp/freshclam.log" >> /etc/freshclam.conf && \
    echo "DatabaseMirror database.clamav.net" >> /etc/freshclam.conf

# 4. 바이러스 정의 업데이트 (빌드 시 DB 포함)
# 네트워크 순시 장애 대비를 위해 1회 시도 후 실패 시 로그 확인
RUN freshclam

# 5. Lambda 코드 복사
COPY app.py ${LAMBDA_TASK_ROOT}

# 6. Lambda 핸들러 지정
CMD ["app.lambda_handler"]