# S3 name: s3-upload-trigger
 
1. S3에 ZIP파일 업로드
    - lambda 함수 트리거
2. /tmp에 s3파일 다운로드
3. 해당 ZIP파일 sha-256 해시값 계산
3. /tmp위치에 ZIP파일 압축풀기
4. 압축푼 파일에 대한 Clamav 검사실행
    - clamav는 dockerfile로 정의된 컨테이너 참조
    - 검사 실행
    - 판정 결과를 JSON 또는 구조화된 로그 형태로 정리
    
