# 1. 람다용 베이스 이미지 대신 일반 Fedora 사용
FROM fedora:39

# 2. 필수 패키지 및 ClamAV 설치 (Fedora는 패키지가 풍부해서 한 방에 됩니다)
RUN dnf install -y \
    python3 \
    python3-pip \
    clamav \
    clamav-update \
    curl \
    && dnf clean all

# 3. 람다 런타임 인터페이스 에뮬레이터(RIE) 설치 
# (일반 OS 이미지를 람다에서 돌리려면 이 인터페이스가 필요합니다)
RUN pip3 install boto3 awslambdaric

# 4. 바이러스 DB 폴더 준비 및 미리 다운로드
RUN mkdir -p /var/lib/clamav && chmod 755 /var/lib/clamav
RUN curl -L -o /var/lib/clamav/main.cvd https://packages.wazuh.com/deps/clamav/main.cvd && \
    curl -L -o /var/lib/clamav/daily.cvd https://packages.wazuh.com/deps/clamav/daily.cvd && \
    curl -L -o /var/lib/clamav/bytecode.cvd https://packages.wazuh.com/deps/clamav/bytecode.cvd

# 5. 작업 디렉토리 설정 및 코드 복사
ENV LAMBDA_TASK_ROOT=/var/task
RUN mkdir -p ${LAMBDA_TASK_ROOT}
COPY app.py ${LAMBDA_TASK_ROOT}
WORKDIR ${LAMBDA_TASK_ROOT}

# 6. 환경 변수 설정 (Python이 app.py를 찾을 수 있도록 경로 지정)
ENV PYTHONPATH=${LAMBDA_TASK_ROOT}

# 7. 실행 명령 (awslambdaric을 통해 python 핸들러 호출)
ENTRYPOINT [ "/usr/bin/python3", "-m", "awslambdaric" ]
CMD [ "app.lambda_handler" ]