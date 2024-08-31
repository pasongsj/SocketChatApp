#pragma once

#include "SocketBase.h"
#include <map>
#include <string>
#include <set>
#include <mutex>
#include <vector>
#include <fstream>
#include <openssl/ssl.h>

// 클라이언트 데이터 클래스
class ClientData
{
public:
    int Fd = -1;
    SSL* ssl = nullptr;
    std::string Name = "";
};

class SocketServer : public SocketBase 
{
public:
    SocketServer(const std::string& ipAddress, int port);
    ~SocketServer();

    // 소켓 바인드 및 리스닝 설정
    void SocketBind();
    void SocketListen();

    // 클라이언트 연결 수락 및 처리
    void SocketAccept();

    // 설정 및 실행
    void Setting() override;
    void SocketRunning() override;

private:
    std::vector<ClientData*> m_Clients; // 클라이언트 데이터 관리
    std::vector<ClientData*> m_ClosedClients; // 닫힌 클라이언트 목록
    std::ofstream m_logFile; // 로그 파일 스트림
    SSL_CTX* ctx;

    std::set<std::string> m_NameSet; // 클라이언트 이름 집합

    // accept
    void ConnectNewClient();
    // 클라이언트 메시지 처리
    void HandleClientData(ClientData* clientData);

    // 메시지 브로드캐스트
    void BroadcastMessage(const std::string& message, ClientData* senderClientData, int flag = 1);

    // 로그 관련
    void LogEvent(const std::string& event);
    void OpenLogFile();

    // 클라이언트와 접속 종료
    void CloseClient(ClientData* clientData);
    // 문자열을 대문자로 변환
    void ToUpper(std::string& str);

    // 클라이언트 소켓 리스트에서 닫힌 소켓 제거
    void RemoveClosedClients();

    void InitSSL();
};
