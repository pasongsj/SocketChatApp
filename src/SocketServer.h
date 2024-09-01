#pragma once

#include "SocketBase.h"
#include <map>
#include <string>
#include <set>
#include <mutex>
#include <vector>
#include <fstream>

class SocketServer : public SocketBase 
{
public:
    // 생성자: IP 주소와 포트 번호를 설정
    SocketServer(const std::string& ipAddress, int port);

    // 소멸자: 자원 정리
    ~SocketServer();

    // 설정 및 실행
    void Setting() override;
    void SocketRunning() override;

private:
    // 클라이언트 이름 집합
    std::set<std::string> m_NameSet;
    
    // SSL 클라이언트 리스트
    std::vector<SSL*> m_SSLClients;
    
    // 닫힌 SSL 클라이언트 리스트
    std::vector<SSL*> m_SSLClosedClients;
    
    // SSL 클라이언트 이름 매핑
    std::map<SSL*, std::string> m_SSLClientNames;
    
    // 로그 파일 스트림
    std::ofstream m_logFile;

    // 소켓 바인드 및 리스닝 설정
    void SocketBind();
    void SocketListen();

    // 클라이언트 연결 수락 및 처리
    void SocketAccept();
    void ConnectNewClient();

    // 로그 관련
    void LogEvent(const std::string& event);
    void OpenLogFile();

    // 문자열을 대문자로 변환
    void ToUpper(std::string& str);

    // SSL 관련
    void InitializeSSL();
    void HandleClientSSLData(SSL* c_ssl);
    void SSLBroadcastMessage(const std::string& msg, SSL* senderSSL, int flag = 1);

    // 닫힌 클라이언트 제거
    void RemoveClosedClients();
};
