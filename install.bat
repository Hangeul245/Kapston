@echo off


:: 관리자 권한 확인
openfiles >nul 2>&1
if %errorlevel% NEQ 0 (
    echo This script requires Administrator privileges. Please run as Administrator.
    pause
    exit /b
)

:: VC++ Redistributable 설치 여부 확인
echo Checking if VC++ Redistributable is installed...
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64" >nul 2>&1
if %errorlevel% NEQ 0 (
    echo VC++ Redistributable is not installed. Please run VC_redist.x64.exe first, then proceed.
    echo VC_redist.x64.exe is in the VC++ file.
   
) else (
    echo VC++ Redistributable is already installed.
)

:: INF 파일을 사용하여 드라이버 설치
pnputil /add-driver "Drive\drive.inf" /install
if %errorlevel% NEQ 0 (
    echo An error occurred while installing the driver.
    echo Error code: %errorlevel% >> error_log.txt
    pause
    exit /b
)

:: EXE 파일 실행
start "" "Agent\AgentGUI.exe"
if %errorlevel% NEQ 0 (
    echo An error occurred while running the EXE file.
    echo Error code: %errorlevel% >> error_log.txt
    pause
    exit /b
)

echo Ran_block have been downloaded complete.
pause
