# Flask 애플리케이션 실행 스크립트
from flask_routes import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)   # 포트 5002로 고정
