#pragma once

#include "SocketBase.h"
#include <atomic>
#include <string>
#include <openssl/ssl.h>

class SocketClient : public SocketBase 
{
public:
    // 생성자: IP 주소와 포트 번호를 설정
    SocketClient(const std::string& ipAddress, int port);

    // 소멸자: 자원 정리
    virtual ~SocketClient(); 

    // 클라이언트 설정
    void Setting(); 
    
    // 소켓 실행
    void SocketRunning(); 

private:

	// SSL 객체
    SSL* m_ssl; 

    // 클라이언트 이름
    std::string MyName; 

    // 실행 여부 확인
    std::atomic<bool> m_Running = true;

    // 시도 횟수
    int m_Trycnt;

    // 서버에 연결
    void SocketConnect(); 
    
    // 사용자 입력 처리
    void HandleInput(); 
    
    // 서버 응답 처리
    void HandleServerResponse(); 
};
