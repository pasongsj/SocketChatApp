//SocketBase.cpp

#include "SocketBase.h"
#include <unistd.h>  
/*
SocketBase::SocketBase(const std::string& ipAddress, int port)
    : m_ipAddress(ipAddress), m_port(port), m_socketFd(-1) 
{
    // 생성자: IP 주소와 포트를 초기화하고 소켓 파일 디스크립터를 -1로 설정
}

SocketBase::~SocketBase() 
{
    // 소멸자: 소켓 종료
    SocketClose();
}

void SocketBase::CreateSocket() 
{
    // 소켓 생성
    m_socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socketFd == -1) 
    {
        throw std::runtime_error("소켓 생성에 실패했습니다."); // 에러 메시지
    }
}

void SocketBase::SocketClose() 
{
    // 소켓 종료
    if (m_socketFd != -1) 
    {
        close(m_socketFd);
        m_socketFd = -1;
    }
}*/
