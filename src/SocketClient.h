#pragma once

#include "SocketBase.h"
#include <atomic>
#include <string>
#include <openssl/ssl.h>

class SocketClient : public SocketBase 
{
public:
    SocketClient(const std::string& ipAddress, int port) 
        : SocketBase(ipAddress, port) 
	{
		MyName = "";
		m_Trycnt = 0;
	}

    // 소멸자: 자원 정리
    ~SocketClient();

    // 클라이언트 설정
    void Setting(); 
    
    // 소켓 실행
    void SocketRunning(); 

private:

	// 클라이언트이름
    std::string MyName; 

	// 실행 여부 확인
    std::atomic<bool> m_Running = true;

    int m_Trycnt;
    

	SSL_CTX* ctx;

	// 서버에 연결
    void SocketConnect(); 
    
    // 사용자 입력 처리
    void HandleInput(); 
    
    // 서버 응답 처리
    void HandleServerResponse(); 
    
    // 비블로킹 입력 확인
    bool IsInputAvailable();

	void InitSSL();
    
};
