#pragma once

#include "resource.h"
#include <afxwin.h>

class CAgentGUI2Dlg : public CDialogEx
{
public:
    CAgentGUI2Dlg(CWnd* pParent = nullptr);

    void AppendLog(CString log);
    void PostToServer(CString jsonData);

#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_AGENTGUI2_DIALOG };
#endif

protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    virtual BOOL OnInitDialog();
    afx_msg void OnDestroy();
    afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
    afx_msg void OnPaint();
    afx_msg HCURSOR OnQueryDragIcon();
    afx_msg LRESULT OnPostInit(WPARAM, LPARAM);
    afx_msg void ClickedButton1();

    DECLARE_MESSAGE_MAP()

protected:
    HICON m_hIcon;
    CButton m_btnAlert;
    CStatic m_lblStatus;
    CEdit m_editInput;

    HANDLE m_hPort;   // 💡 커널 포트 핸들 (공유용)
public:
    HANDLE GetPortHandle() const { return m_hPort; }

    void AppendToFile(CString text);
    void RequestDirectoryFromKernel();
};
