#pragma once

#include "SocketBase.h"
#include <map>
#include <string>
#include <set>
#include <mutex>
#include <vector>
#include <fstream>
#include <openssl/ssl.h>

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
    // 클라이언트 관련 데이터
    std::map<SSL*, std::string> m_ClientNames;	// fd와 클라이언트 이름
	std::map<SSL*,int> m_ClientFds;
	std::map<int,SSL*> m_mapClientSSL;
	std::set<std::string> m_NameSet;			// 클라이언트 이름 집합

    std::vector<int> m_ClientSockets;			// 클라이언트 소켓 파일 디스크립터 목록
	std::vector<SSL*> m_ClientSSL;
	std::vector<SSL*> m_ClosedClients;			// 닫힌(떠난)클라이언트 소켓
    std::ofstream m_logFile;					// 로그 파일 스트림

	SSL_CTX* ctx;

	// accept
	void ConnectNewClient();
    // 클라이언트 메시지 처리
	void HandleClientData(SSL* cssl);

    // 메시지 브로드캐스트
    void BroadcastMessage(const std::string& message, SSL* cssl, int flag = 1);

    // 로그 관련
    void LogEvent(const std::string& event);
    void OpenLogFile();

    // 클라이언트와 접속 종료
    void CloseClientSocket(int clientFd);
    //void CloseClientSSL(int clientFd);
    // 문자열을 대문자로 변환
    void ToUpper(std::string& str);

    // 클라이언트 소켓 리스트에서 닫힌 소켓 제거
    void RemoveClosedClients();

	void InitSSL();

};
