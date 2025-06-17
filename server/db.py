# 1)MySQL 연결 및 CRUD 로직을 담당하는 모듈
import os
import mysql.connector
import time
import json
import re                          # 암호화 탐지용 (정규표현식, Base64 패턴 탐지에 사용)
import base64                      # 암호화 탐지용 (Base64 인코딩/디코딩 확인용)
from datetime import datetime      # 분석 시각 기록용
import hashlib                     # 해시 탐지용


# 2)MySQL 재시도 로직을 포함한 연결 함수
def get_connection():
    retries = 5
    for attempt in range(retries):
        try:
            return mysql.connector.connect(
                host=os.getenv('MYSQL_HOST', 'my-mysql-app'),
                user=os.getenv('MYSQL_USER', 'root'),
                password=os.getenv('MYSQL_PASSWORD', '1234'),
                database=os.getenv('MYSQL_DATABASE', 'set_db')
            )
        except mysql.connector.Error as err:
            print(f"[!] MySQL 연결 오류: {err}")
            if attempt < retries - 1:
                time.sleep(5)
            else:
                raise


# 3)요청 로그를 cloud 테이블에 저장
def log_request(ip, message, filename, data):
    conn = get_connection()
    cursor = conn.cursor()
    log_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    insert = (
        "INSERT INTO cloud (ip, message, filename, log_time, data)"
        " VALUES (%s, %s, %s, %s, %s)"
    )
    cursor.execute(insert, (
        ip, message, filename, log_time,
        json.dumps(data, ensure_ascii=False)
    ))
    conn.commit()
    cursor.close()
    conn.close()


# 4)cloud 테이블에서 지정한 컬럼 데이터를 조회
def get_data(column):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(f"SELECT {column} FROM cloud")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


# 5)cloud 테이블에 새 데이터를 저장
def save_data(ip, message, filename, payload):
    conn = get_connection()
    cursor = conn.cursor()
    log_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    insert = (
        "INSERT INTO cloud (ip, message, filename, log_time, data)"
        " VALUES (%s, %s, %s, %s, %s)"
    )
    cursor.execute(insert, (
        ip, message, filename, log_time,
        json.dumps(payload, ensure_ascii=False)
    ))
    conn.commit()
    cursor.close()
    conn.close()


# 6)health_check 테이블을 생성 및 테스트용 레코드 삽입 후 카운트 반환
def health_check():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS health_check (id INT AUTO_INCREMENT PRIMARY KEY)"
    )
    conn.commit()
    cursor.execute("INSERT INTO health_check () VALUES ()")
    conn.commit()
    cursor.execute("SELECT COUNT(*) FROM health_check")
    count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return count
    

# 7)암호화 탐지와 분석 시간 기록에 필요한 모듈
# 7-1)data 기반 암호화 방식 식별 함수
def detect_encryption(data):
    base64_pattern = r'^[A-Za-z0-9+/=\\s]+$'
    if isinstance(data, str) and re.fullmatch(base64_pattern, data) and len(data) % 4 == 0:
        try:
            base64.b64decode(data)
            return 'Base64'
        except Exception:
            pass

    if isinstance(data, str):
        non_ascii_ratio = sum(1 for c in data if ord(c) > 127) / len(data)
        if 0.2 < non_ascii_ratio < 0.8:
            return 'XOR'

    if isinstance(data, str):
        if len(data) % 16 == 0 and all(ord(c) > 127 or not c.isprintable() for c in data):
            return 'AES'

    return 'Unknown'


# 7-2)랜섬노트 탐지 함수
def contains_ransom_note(filename, data):
    ransom_keywords = ['readme', 'decrypt', 'recover', 'instructions', 'info', 'hta']
    return any(k in filename.lower() for k in ransom_keywords) or \
           any(k in data.lower() for k in ransom_keywords)


# 7-3)비정상 확장자 탐지 함수
def has_suspicious_extension(filename):
    suspicious_exts = ['.locked', '.encrypted', '.cry', '.wnry', '.wal']
    return any(filename.lower().endswith(ext) for ext in suspicious_exts)


# 7-4)SHA256 해시 계산 함수
def get_sha256_hash(data):
    return hashlib.sha256(data.encode('utf-8', errors='ignore')).hexdigest()


# 7-5)KISA Dharma 해시값 기반 탐지 함수
KNOWN_RANSOMWARE_HASHES = {
    '955544abc801355ee1e8e48488c6e9150d431fec63b7e74d19f22982b396e637',
}

def is_known_ransomware(hash_val):
    return hash_val.lower() in KNOWN_RANSOMWARE_HASHES


# 8)암호화 방식 내용을 모두 malware 테이블에 저장하는 함수
def analyze_and_log(filename, message, data):
    conn    = get_connection()
    cursor  = conn.cursor()

    # 7-1) 암호화 방식 탐지
    encryption   = detect_encryption(data)
    # 7-4) SHA256 해시 계산
    sha256_hash  = get_sha256_hash(data)

    # 7-5) 탐지 조건 분기 (해시 매칭 우선)
    if is_known_ransomware(sha256_hash):
        activity    = '[랜섬웨어 탐지] KISA 등록 샘플과 해시 일치'
        is_blocked  = 0
    elif 'Decoy access' in message and encryption in ['Base64', 'XOR', 'AES']:
        activity    = '[차단] 미끼파일 및 암호화 행위 감지됨'
        is_blocked  = 1
    elif contains_ransom_note(filename, data):
        activity    = '[의심] 랜섬노트 형태의 파일 또는 내용 감지됨'
        is_blocked  = 0
    elif has_suspicious_extension(filename):
        activity    = '[의심] 비정상 확장자 감지됨'
        is_blocked  = 0
    elif 'receive' in message:
        activity    = '데이터 업로드 요청 메시지입니다.'
        is_blocked  = 0
    else:
        activity    = '일반 메시지입니다.'
        is_blocked  = 0

    # malware 테이블에 분석 결과 저장 (is_blocked 컬럼 포함)
    insert_sql = (
        "INSERT INTO malware "
        "(filename, encryption, activity, analyzed_time, is_blocked) "
        "VALUES (%s, %s, %s, %s, %s)"
    )
    cursor.execute(
        insert_sql,
        (filename, encryption, activity, datetime.now(), is_blocked)
    )

    conn.commit()
    cursor.close()
    conn.close()



# 9)유저 ID 기반 테이블을 user_db에 자동 생성
def create_user_table_if_not_exists(user_id):
    conn = mysql.connector.connect(
        host=os.getenv('MYSQL_HOST', 'my-mysql-app'),
        user=os.getenv('MYSQL_USER', 'test1'),
        password=os.getenv('MYSQL_PASSWORD', 'test1'),
        database=os.getenv('MYSQL_DATABASE', 'user_db')
    )
    cursor = conn.cursor()
    sql = f"""
    CREATE TABLE IF NOT EXISTS `{user_id}` (
        id INT AUTO_INCREMENT PRIMARY KEY,
        activity TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(sql)
    conn.commit()
    cursor.close()
    conn.close()


# 10)유저 액티비티(로그인/조회/로그아웃 등)를 해당 테이블에 기록
def log_user_activity(user_id: str, activity_text: str):
    """
    - user_id 이름으로 테이블이 없으면 생성
    - 해당 테이블에 activity_text를 기록
    """
    try:
        conn = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'my-mysql-app'),
            user=os.getenv('MYSQL_USER', 'test1'),
            password=os.getenv('MYSQL_PASSWORD', 'test1'),
            database=os.getenv('MYSQL_DATABASE', 'user_db')
        )
        cursor = conn.cursor()

        # user_id 테이블이 없으면 생성
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS `{user_id}` (
            id INT AUTO_INCREMENT PRIMARY KEY,
            activity TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
        cursor.execute(create_table_sql)

        # 로그 삽입
        insert_sql = f"INSERT INTO `{user_id}` (activity) VALUES (%s);"
        cursor.execute(insert_sql, (activity_text,))

        conn.commit()

    except mysql.connector.Error as e:
        print(f"[ERROR] 사용자 활동 기록 중 오류 발생: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()
