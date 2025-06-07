 이 프로그램은 중부대학교 정보보호학과 2025년도 캡스톤 디자인 대회 출품을 위한 랜섬웨어 차단 프로그램 입니다.

정상적인 설치 및 운영을 위해 다음 단계를 준수하여 주시기 바랍니다.
**SDK와 WDK가 설치되어 있는 환경에서 진행하여주세요.**

1. VC_redist.x64.exe를 실행시켜 설치해주세요.
2. "capston\Drive\kernell1.inf" 를 우클릭하여 설치합니다.
3. 윈도우 검색창에 "cmd" 검색 후 관리자로 실행합니다.
4. 다음 명령어를 순서대로 입력해주세요.
 - cd <capston 폴더 경로>\Drive
 - "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\Inf2Cat.exe" /driver:. /os:10_x64 /verbose
 - sc create CapstonDV type= kernel start= demand binPath= "System32\drivers\kernel1.sys" group= "FSFilter Activity Monitor"
 - fltmc load CapstonDV
