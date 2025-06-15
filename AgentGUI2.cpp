#include "pch.h"
#include "framework.h"
#include "AgentGUI2.h"
#include "AgentGUI2Dlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_MESSAGE_MAP(CAgentGUI2App, CWinApp)
    ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()

// CAgentGUI2App 생성
CAgentGUI2App::CAgentGUI2App()
{
    m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;
    // TODO: 여기에 생성자 코드를 추가하고 InitInstance에 모든 중요한 초기화를 배치하세요.
}

// 유일한 CAgentGUI2App 개체입니다.
CAgentGUI2App theApp;

// CAgentGUI2App 초기화
BOOL CAgentGUI2App::InitInstance()
{
    CWinApp::InitInstance();

    // 컨트롤 컨테이너 활성화
    AfxEnableControlContainer();

    // DPI 대응
    SetProcessDPIAware();  // 고해상도 환경에서 GUI 깨짐 방지

    // 대화상자 객체 생성 및 실행
    CAgentGUI2Dlg dlg;
    m_pMainWnd = &dlg;
    INT_PTR nResponse = dlg.DoModal();

    if (nResponse == IDOK)
    {
        // OK 버튼 클릭 후 처리 (예: 설정 저장 등)
    }
    else if (nResponse == IDCANCEL)
    {
        // Cancel 버튼 클릭 후 처리 (예: 로그 저장 등)
    }
    else if (nResponse == -1)
    {
        AfxMessageBox(_T(" 대화상자 생성 실패: 시스템 리소스 부족 또는 기타 오류"), MB_ICONERROR);
    }

    // 프로그램 종료 → 메시지 루프 생략
    return FALSE;

}
