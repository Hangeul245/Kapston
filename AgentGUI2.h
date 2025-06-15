#pragma once

//  반드시 pch.h를 먼저 포함해야 함
#include "pch.h"

#ifndef AGENTGUI2_H
#define AGENTGUI2_H

#include "resource.h"  // 리소스 심볼 정의

// CAgentGUI2App:
// 이 클래스의 구현은 AgentGUI2.cpp에 있습니다.
class CAgentGUI2App : public CWinApp
{
public:
    CAgentGUI2App();

    // 애플리케이션 초기화
    virtual BOOL InitInstance();

    DECLARE_MESSAGE_MAP()
};

extern CAgentGUI2App theApp;

#endif // AGENTGUI2_H
