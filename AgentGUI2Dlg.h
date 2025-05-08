#pragma once

#include "resource.h"
#include <afxwin.h>  // CDialogEx 포함을 보장

// CAgentGUI2Dlg 대화상자
class CAgentGUI2Dlg : public CDialogEx
{
public:
	CAgentGUI2Dlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_AGENTGUI2_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg LRESULT OnPostInit(WPARAM wParam, LPARAM lParam);    // 초기 자동 전송 메시지
	afx_msg void ClickedButton1();  // 버튼 클릭 시 호출되는 함수

	DECLARE_MESSAGE_MAP()

private:
	HICON m_hIcon;

	// UI 컨트롤 변수
	CButton m_btnAlert;
	CStatic m_lblStatus;
	CEdit m_editInput;

	// 내부 함수 선언
	void AppendLog(CString log);           // GUI 로그 출력
	void AppendToFile(CString text);       // 텍스트 파일 로그 저장
	void PostToServer(CString jsonData);   // WinHTTP POST 전송
	void RequestDirectoryFromKernel();     // 🔁 커널로부터 디렉터리 요청  ← 이거 추가!

};