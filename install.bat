@echo off

:: 현재 디렉토리를 myfoldername로 설정
set folderPath=%cd%\capston

:: INF 파일을 사용하여 드라이버 설치
pnputil /add-driver "%folderPath%\driver.inf" /install

:: EXE 파일 실행
start "" "%folderPath%\agent.exe"
