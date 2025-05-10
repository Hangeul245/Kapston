@echo off
:: 관리자 권한 확인
openfiles >nul 2>&1
if %errorlevel% NEQ 0 (
    echo 관리자 권한이 필요합니다. 관리자 권한으로 실행해 주세요.
    pause
    exit /b
)

:: VC++ Redistributable 설치 여부 확인
echo VC++ Redistributable 설치 여부 확인 중...
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" >nul 2>&1
if %errorlevel% NEQ 0 (
    echo VC++ Redistributable이 설치되지 않았습니다. 설치를 진행합니다...
    :: VC++ Redistributable 설치 명령어 예시 (설치 파일 경로가 필요함)
    start "" "vcredist_x64.exe"
    if %errorlevel% NEQ 0 (
        echo VC++ Redistributable 설치 중 오류가 발생했습니다.
        echo 오류 코드: %errorlevel% >> error_log.txt
        pause
        exit /b
    )
    echo VC++ Redistributable 설치가 완료되었습니다.
) else (
    echo VC++ Redistributable이 이미 설치되어 있습니다.
)

:: INF 파일을 사용하여 드라이버 설치
pnputil /add-driver "kernell1.inf" /install
if %errorlevel% NEQ 0 (
    echo 드라이버 설치 중 오류가 발생했습니다.
    echo 오류 코드: %errorlevel% >> error_log.txt
    pause
    exit /b
)

:: EXE 파일 실행
start "" "AgentGUI2.exe"
if %errorlevel% NEQ 0 (
    echo EXE 파일 실행 중 오류가 발생했습니다.
    echo 오류 코드: %errorlevel% >> error_log.txt
    pause
    exit /b
)

echo 모든 작업이 성공적으로 완료되었습니다.
pause
