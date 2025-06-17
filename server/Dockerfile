FROM python:3.13.2

# requirements.txt 파일을 컨테이너에 복사
COPY requirements.txt requirements.txt

# Flask 및 다른 패키지 설치
RUN pip install -r requirements.txt

# app.py 및 다른 Flask 파일을 /app 디렉토리로 복사
COPY . /app

# Mysql 데이터가 처음 실행될 때 user_db.sql 파일을 자동 실행하도록 복사
COPY user_db.sql /docker-entrypoint-initdb.d/

# 작업 디렉토리 설정
WORKDIR /app

# Flask 애플리케이션 실행 명령
CMD ["python3", "app.py"]
