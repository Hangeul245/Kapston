#pragma once

#ifndef __AFXWIN_H__
#error "pch.h를 먼저 포함하세요."
#endif

#include "resource.h"  // 리소스 심볼 정의

// CAgentGUI2App:
// 이 클래스의 구현은 AgentGUI2.cpp에 있습니다.
class CAgentGUI2App : public CWinApp
{
public:
    CAgentGUI2App();

    // 재정의
public:
    virtual BOOL InitInstance();  // 애플리케이션 초기화

    // 구현
    DECLARE_MESSAGE_MAP()
};

extern CAgentGUI2App theApp;
