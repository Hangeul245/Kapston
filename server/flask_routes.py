# Flask 라우트 정의 및 백그라운드 DB 처리 모듈 
from flask import Flask, request, jsonify
from threading import Thread
from db import log_request, get_data, save_data, health_check, analyze_and_log
from db import create_user_table_if_not_exists  # 유저별 테이블 자동 생성 함수 호출용

import os
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)


def _insert_user_activity(user_id: str, activity_text: str):
    # user_id 이름의 테이블이 없으면 생성
    # 해당 테이블에 activity_text를 기록
    conn = None
    cursor = None
    try:
        conn = mysql.connector.connect(
            host=os.getenv('MYSQL_HOST', 'my-mysql-app'),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', '1234'),
            database=os.getenv('MYSQL_DATABASE', 'user_db')
        )
        cursor = conn.cursor()

        # 테이블이 이미 생성되었는지 확인은 create_user_table_if_not_exists에서 처리됨
        insert_sql = f"INSERT INTO `{user_id}` (activity) VALUES (%s);"
        cursor.execute(insert_sql, (activity_text,))
        conn.commit()

    except Error as e:
        print(f"[ERROR] 사용자 활동 기록 중 오류 발생: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


# 1)모든 요청을 비동기로 cloud 테이블에 기록
@app.before_request
def before_any_request():
    try:
        ip = request.remote_addr or ''
        message = f"{request.method} {request.path}"
        filename = ''
        data = request.get_json() if request.is_json else request.get_data(as_text=True)
        Thread(target=log_request, args=(ip, message, filename, data), daemon=True).start()
    except Exception as e:
        print(f"[!] Request logging error: {e}")


# 2)클라이언트 요청 처리 라우트
@app.route('/receive', methods=['POST'])
def receive_route():
    js = request.get_json() or {}
    filename = js.get('filename', '')
    message = js.get('message', f"{request.method} {request.path}")
    data = js.get('data', '')
    user_id = js.get('user_id', '').strip()  # 유저명 가져오기

    # 2-1)user_db 내에 유저 테이블 자동 생성
    if user_id:
        Thread(target=create_user_table_if_not_exists, args=(user_id,), daemon=True).start()
        # 유저 활동 기록 (예: "로그인" 대신, 여기선 요청받은 엔드포인트 정보를 남김)
        Thread(target=_insert_user_activity, args=(user_id, message), daemon=True).start()

    # 2-2)cloud 테이블에 저장
    Thread(target=save_data, args=(
        request.remote_addr,
        message,
        filename,
        js
    ), daemon=True).start()

    # 2-3)malware 분석기 실행
    Thread(target=analyze_and_log, args=(filename, message, data), daemon=True).start()

    return jsonify({'message': 'Received & Analyzed'}), 200


# 3)GET /get_data?column=<컬럼명> : 지정 컬럼 필드값 반환
@app.route('/get_data', methods=['GET'])
def get_data_route():
    col = request.args.get('column')
    if not col:
        return jsonify({'error': 'Column name is required'}), 400
    if col not in ['ip','message','filename','log_time','data']:
        return jsonify({'error': 'Not allowed column name'}), 400
    rows = get_data(col)
    return jsonify(rows), 200


# 4)GET /health : DB 연결 및 읽기/쓰기 확인
@app.route('/health', methods=['GET'])
def health_route():
    try:
        count = health_check()
        return jsonify({'status': 'ok', 'health_records': count}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
