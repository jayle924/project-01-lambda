FROM public.ecr.aws/lambda/python:3.14

# ClamAV 설치
RUN dnf install -y clamav clamav-update && dnf clean all

# ClamAV DB 초기 생성 (없으면 scan 안 됨)
RUN mkdir -p /var/lib/clamav && chmod -R 755 /var/lib/clamav

# freshclam 설정 파일 생성 (간단 버전)
RUN echo "DatabaseDirectory /var/lib/clamav" > /etc/freshclam.conf

# 바이러스 정의 업데이트 (이미지 빌드 시 1회)
RUN freshclam

# Lambda 코드 복사
COPY app.py ${LAMBDA_TASK_ROOT}

# Lambda 핸들러 지정
CMD ["app.lambda_handler"]
