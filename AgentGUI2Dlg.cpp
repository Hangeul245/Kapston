#include "pch.h"
#include "framework.h"
#include "AgentGUI2.h"
#include "AgentGUI2Dlg.h"
#include "afxdialogex.h"
#include <winhttp.h>
#include <atlconv.h>
#include <fstream>
#include <vector>
#include <shlobj.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fltuser.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "fltLib.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WM_POST_INIT (WM_USER + 1)
#define SERVER_HOST L"172.20.10.2"
#define SERVER_PORT 5000
#define SERVER_PATH L"/receive"
#define CONTENT_TYPE_HEADER L"Content-Type: application/json\r\n"

CString GetLocalIPAddress()
{
    CString ipStr = _T("172.20.10.2");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0)
    {
        addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        char hostname[256] = { 0 };
        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            addrinfo* result = nullptr;
            if (getaddrinfo(hostname, nullptr, &hints, &result) == 0)
            {
                for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next)
                {
                    sockaddr_in* ipv4 = (sockaddr_in*)ptr->ai_addr;
                    char ip[INET_ADDRSTRLEN] = { 0 };
                    if (inet_ntop(AF_INET, &(ipv4->sin_addr), ip, sizeof(ip)))
                    {
                        ipStr = CString(ip);
                        break;
                    }
                }
                freeaddrinfo(result);
            }
        }
        WSACleanup();
    }
    return ipStr;

}

CString GetCurrentTimeString()
{
    CTime now = CTime::GetCurrentTime();
    CString timeStr;
    timeStr.Format(_T("[%04d-%02d-%02d %02d:%02d:%02d]"),
        now.GetYear(), now.GetMonth(), now.GetDay(),
        now.GetHour(), now.GetMinute(), now.GetSecond());
    return timeStr;
}

class CAboutDlg : public CDialogEx
{
public:
    CAboutDlg();
#ifdef AFX_DESIGN_TIME
    enum { IDD = IDD_ABOUTBOX };
#endif
protected:
    virtual void DoDataExchange(CDataExchange* pDX);
    DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX) {}
void CAboutDlg::DoDataExchange(CDataExchange* pDX) { CDialogEx::DoDataExchange(pDX); }
BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()

CAgentGUI2Dlg::CAgentGUI2Dlg(CWnd* pParent)
    : CDialogEx(IDD_AGENTGUI2_DIALOG, pParent)
{
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAgentGUI2Dlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_BUTTON1, m_btnAlert);
    DDX_Control(pDX, IDC_STATIC_STATUS, m_lblStatus);
    DDX_Control(pDX, IDC_EDIT1, m_editInput);
}

BEGIN_MESSAGE_MAP(CAgentGUI2Dlg, CDialogEx)
    ON_WM_SYSCOMMAND()
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON1, &CAgentGUI2Dlg::ClickedButton1)
    ON_MESSAGE(WM_POST_INIT, &CAgentGUI2Dlg::OnPostInit)
END_MESSAGE_MAP()

DWORD WINAPI ListenFromKernel(LPVOID lpParam)
{
    HANDLE hPort = NULL;
    HRESULT hr;

    hr = FilterConnectCommunicationPort(L"\\MiniFilterPort", 0, NULL, 0, NULL, &hPort);
    if (!SUCCEEDED(hr)) {
        AfxMessageBox(_T(" 커널 포트 연결 실패 (FilterConnectCommunicationPort)"));
        return 1;
    }

    while (true)
    {
        BYTE messageBuffer[512] = { 0 };
        DWORD bytesReturned = 0;

        hr = FilterGetMessage(hPort, (PFILTER_MESSAGE_HEADER)messageBuffer, sizeof(messageBuffer), NULL);
        if (SUCCEEDED(hr))
        {
            CHAR* payload = (CHAR*)(messageBuffer + sizeof(FILTER_MESSAGE_HEADER));

            CString alert;
            alert.Format(_T(" 탐지 메시지 수신됨: %S"), payload);
            AfxMessageBox(alert);

            CAgentGUI2Dlg* pThis = (CAgentGUI2Dlg*)lpParam;
            if (pThis)
            {
                pThis->AppendLog(alert);

                if (strcmp(payload, "RANSOMWARE_DETECTED") == 0)
                {
                    CString json;
                    json.Format(_T("{\"ip\":\"%s\", \"message\":\"%S\", \"filename\":\"bait.hwp\", \"log_time\":\"%s\", \"data\":\"alert\"}"),
                        GetLocalIPAddress().GetString(), payload, GetCurrentTimeString().GetString());

                    pThis->PostToServer(json);
                }
            }
        }
        else
        {
            break;
        }
    }

    CloseHandle(hPort);
    return 0;
}


BOOL CAgentGUI2Dlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    // 창 제목 설정
    SetWindowText(_T("캡스톤_흰둥단"));

    // 시스템 메뉴 설정
    CMenu* pSysMenu = GetSystemMenu(FALSE);
    if (pSysMenu)
    {
        CString strAboutMenu;
        strAboutMenu.LoadString(IDS_ABOUTBOX);
        if (!strAboutMenu.IsEmpty())
        {
            pSysMenu->AppendMenu(MF_SEPARATOR);
            pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
        }
    }

    // 아이콘 설정
    SetIcon(m_hIcon, TRUE);
    SetIcon(m_hIcon, FALSE);

    // 기본 경로 초기화
    SetDlgItemText(IDC_EDIT1, _T("C:\\Downloads"));
    SetDlgItemText(IDC_STATIC_STATUS, _T("랜섬웨어 탐지"));
    m_btnAlert.SetWindowText(_T("검사 시작"));

    // 테스트용 경고창 제거
    // AfxMessageBox(_T("Ransomware detected!"));

    // POST 메시지 전송 및 커널 통신 요청
    PostMessage(WM_POST_INIT);
    RequestDirectoryFromKernel();
    
    CreateThread(NULL, 0, ListenFromKernel, this, 0, NULL);
    return TRUE;
}


void CAgentGUI2Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
    if ((nID & 0xFFF0) == IDM_ABOUTBOX)
    {
        CAboutDlg dlgAbout;
        dlgAbout.DoModal();
    }
    else
    {
        CDialogEx::OnSysCommand(nID, lParam);
    }
}

void CAgentGUI2Dlg::OnPaint()
{
    if (IsIconic())
    {
        CPaintDC dc(this);
        SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
        int cxIcon = GetSystemMetrics(SM_CXICON);
        int cyIcon = GetSystemMetrics(SM_CYICON);
        CRect rect;
        GetClientRect(&rect);
        int x = (rect.Width() - cxIcon + 1) / 2;
        int y = (rect.Height() - cyIcon + 1) / 2;
        dc.DrawIcon(x, y, m_hIcon);
    }
    else
    {
        CDialogEx::OnPaint();
    }
}

HCURSOR CAgentGUI2Dlg::OnQueryDragIcon()
{
    return static_cast<HCURSOR>(m_hIcon);
}

LRESULT CAgentGUI2Dlg::OnPostInit(WPARAM, LPARAM)
{
    CString ip = GetLocalIPAddress();
    CString jsonMessage;
    jsonMessage.Format(_T("{\"ip\":\"%s\", \"message\":\"Decoy access detected\", \"filename\":\"ransome.exe\", \"log_time\":\"%s\", \"data\":\"some_data\"}"), ip, GetCurrentTimeString());
    PostToServer(jsonMessage);
    return 0;
}

void CAgentGUI2Dlg::ClickedButton1()
{
    CString ip = GetLocalIPAddress();
    CString jsonMessage;
    jsonMessage.Format(_T("{\"ip\":\"%s\", \"message\":\"Decoy access detected\", \"filename\":\"ransome.exe\", \"log_time\":\"%s\", \"data\":\"some_data\"}"), ip, GetCurrentTimeString());
    PostToServer(jsonMessage);
    RequestDirectoryFromKernel();
}

void CAgentGUI2Dlg::AppendLog(CString log)
{
    CString currentText;
    m_editInput.GetWindowText(currentText);
    currentText += log + _T("\r\n");
    m_editInput.SetWindowText(currentText);
    m_editInput.LineScroll(m_editInput.GetLineCount());
}

void CAgentGUI2Dlg::AppendToFile(CString text)
{
    TCHAR path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_DESKTOP, NULL, 0, path)))
    {
        CString logPath = CString(path) + _T("\\agent_log.txt");
        CStdioFile file;
        if (file.Open(logPath, CFile::modeWrite | CFile::modeCreate | CFile::modeNoTruncate))
        {
            file.SeekToEnd();
            file.WriteString(text + _T("\r\n"));
            file.Close();
        }
    }
}

void CAgentGUI2Dlg::PostToServer(CString message)
{
    HINTERNET hSession = WinHttpOpen(L"AgentApp", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession)
    {
        CString log = GetCurrentTimeString() + _T(" WinHttpOpen failed");
        AppendLog(log); AppendToFile(log);
        return;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, SERVER_HOST, SERVER_PORT, 0);
    if (!hConnect)
    {
        CString log = GetCurrentTimeString() + _T(" WinHttpConnect failed");
        AppendLog(log); AppendToFile(log);
        WinHttpCloseHandle(hSession);
        return;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", SERVER_PATH, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest)
    {
        CString log = GetCurrentTimeString() + _T(" WinHttpOpenRequest failed");
        AppendLog(log); AppendToFile(log);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    WinHttpSetTimeouts(hRequest, 3000, 3000, 3000, 5000);
    CW2A utf8(message, CP_UTF8);
    const char* data = (LPCSTR)utf8;
    size_t len = strlen(data);

    // ✅ DWORD 범위 초과 방지
    if (len > MAXDWORD)
    {
        AppendLog(_T(" 전송 데이터 길이가 DWORD를 초과합니다. 전송 취소됨."));
        AppendToFile(_T(" 너무 큰 데이터로 인해 WinHttpSendRequest 중단됨."));
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    DWORD dwLen = static_cast<DWORD>(len);

    BOOL sent = WinHttpSendRequest(hRequest, CONTENT_TYPE_HEADER, -1L, (LPVOID)data, dwLen, dwLen, 0);


    if (sent && WinHttpReceiveResponse(hRequest, NULL))
    {
        DWORD statusCode = 0, size = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &size, NULL);

        CString log1;
        log1.Format(_T("%s Response code: %lu"), GetCurrentTimeString(), statusCode);
        AppendLog(log1); AppendToFile(log1);

        DWORD dwSize = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);

        CString log2;
        if (dwSize > 0)
        {
            std::vector<char> buffer(dwSize + 1);
            DWORD dwDownloaded = 0;
            WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded);
            buffer[dwDownloaded] = '\0';
            // ✅ UTF-8 → 유니코드 CString 변환
            CString response = CString(CA2W(buffer.data(), CP_UTF8));

            log2.Format(_T("%s Server replied: %s"), GetCurrentTimeString(), response);
        }
        else
        {
            log2.Format(_T("%s Response received (no message)"), GetCurrentTimeString());
        }
        AppendLog(log2); AppendToFile(log2);
    }
    else
    {
        DWORD err = GetLastError();
        CString errMsg;
        errMsg.Format(_T("%s Failed to send request - error code: %lu"), GetCurrentTimeString(), err);
        AppendLog(errMsg); AppendToFile(errMsg);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

}

// ✅ 커널
#pragma pack(push, 1)
typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION;
#pragma pack(pop)

void CAgentGUI2Dlg::RequestDirectoryFromKernel()
{
    CString watchPath = _T("C:\\Downloads");               // 1. 유동 경로 선언
    GetDlgItemText(IDC_EDIT1, watchPath);   // ✅ 입력창에서 경로 읽기


    // ✅ [1] 경로 유효성 검사
    if (watchPath.IsEmpty())
    {
        AppendLog(_T("⚠️ No path entered"));
        return;
    }


    // ✅ [2] 끝에 역슬래시 제거
    watchPath.TrimRight(_T("\\"));

    CString log;
    log.Format(_T(">> Requested path: %s"), watchPath);
    AppendLog(log);
    AppendToFile(log);

    CString ntPath = L"\\??\\" + watchPath;         // 2. NT 포맷으로 변환
    WCHAR pathBuffer[MAX_PATH] = { 0 };
    wcscpy_s(pathBuffer, ntPath);                          // 3. WCHAR 배열로 복사

    HANDLE hPort = NULL;
    HRESULT hr = FilterConnectCommunicationPort(L"\\MiniFilterPort", 0, NULL, 0, NULL, &hPort);
    if (!SUCCEEDED(hr)) {
        AppendLog(_T("Failed to connect to filter port"));
        return;
    }

    BYTE buffer[4096] = { 0 };
    DWORD bytesReturned = 0;

    hr = FilterSendMessage(
        hPort, pathBuffer, (DWORD)(wcslen(pathBuffer) + 1) * sizeof(WCHAR),
        buffer, sizeof(buffer), &bytesReturned);

    if (!SUCCEEDED(hr)) {
        AppendLog(_T("Failed to send message to driver"));
        CloseHandle(hPort);
        return;
    }

    AppendLog(_T("Received response from kernel driver"));

    FILE_DIRECTORY_INFORMATION* pInfo = (FILE_DIRECTORY_INFORMATION*)buffer;
    while (true)
    {
        CString fileName(pInfo->FileName, pInfo->FileNameLength / sizeof(WCHAR));

        // ✅ 경고 방지를 위해 GetString() 추가
        CString msg;
        msg.Format(_T("File name: %s"), fileName.GetString());
        AppendLog(msg);

        // ✅ 여기서도 모든 CString 파라미터에 .GetString() 추가
        CString json;
        json.Format(_T("{\"ip\":\"%s\", \"message\":\"File listed\", \"filename\":\"%s\", \"log_time\":\"%s\", \"data\":\"dirinfo\"}"),
            GetLocalIPAddress().GetString(), fileName.GetString(), GetCurrentTimeString().GetString());
        PostToServer(json);

        if (pInfo->NextEntryOffset == 0) break;
        pInfo = (FILE_DIRECTORY_INFORMATION*)((BYTE*)pInfo + pInfo->NextEntryOffset);
    }

    CloseHandle(hPort);
}
