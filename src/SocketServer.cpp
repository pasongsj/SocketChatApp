#include "SocketServer.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <sys/select.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>


// 생성자
SocketServer::SocketServer(const std::string& ipAddress, int port)
    : SocketBase(ipAddress, port), m_Isinit(false)
{
    OpenLogFile(); // 로그 파일 열기
	OpenKeyLogFile(); // SSL 키 로그 파일 열기
}

// 소멸자
SocketServer::~SocketServer()
{
    std::cout << "SocketServer destructor called." << std::endl;

    if (m_logFile.is_open())
    {
        m_logFile.close();
    }

    for (SSL* ssl : m_SSLClients) 
    {
        if (ssl != nullptr)
        {
            int clientFd = SSL_get_fd(ssl); // 소켓 디스크립터를 가져옵니다.
            
            // SSL 연결 종료
            SSL_shutdown(ssl);
            
            // SSL 객체 해제
            SSL_free(ssl);
            
            // 소켓 닫기
            if (clientFd >= 0) {
                close(clientFd);
            }
        }
    }
    m_SSLClients.clear(); // 벡터를 비워서 포인터들을 제거합니다.

    SSL_CTX_free(m_ctx);
    close(m_socketFd);
}

// 로그 파일 열기
void SocketServer::OpenLogFile()
{
    std::time_t now = std::time(nullptr);
    std::tm* localTime = std::localtime(&now);
    std::stringstream filename;
    filename << "log/" << (-100 + localTime->tm_year)
             << std::setw(2) << std::setfill('0') << (1 + localTime->tm_mon) 
             << std::setw(2) << std::setfill('0') << localTime->tm_mday << "_"
             << std::setw(2) << std::setfill('0') << localTime->tm_hour
             << std::setw(2) << std::setfill('0') << localTime->tm_min << ".txt";
    m_logFile.open(filename.str(), std::ios::out | std::ios::app);
    if (!m_logFile.is_open())
    {
        throw std::runtime_error("로그 파일을 열 수 없습니다");
    }
}

// SSL 키 로그 파일 열기
void SocketServer::OpenKeyLogFile()
{
    m_keylogFile.open("/Users/n22406007/Documents/0909/SocketChatApp/sslkeys.log", std::ios::out | std::ios::app);
    if (!m_keylogFile.is_open())
    {
        throw std::runtime_error("SSL 키 로그 파일을 열 수 없습니다");
    }
}


// 로그 남기기
void SocketServer::LogEvent(const std::string& event)
{
    std::cout << event << std::flush;
    if (m_logFile.is_open())
    {
        std::time_t now = std::time(nullptr);
        std::tm* localTime = std::localtime(&now);
        m_logFile << std::put_time(localTime, "%Y-%m-%d %H:%M:%S") << " " << event << std::endl;
    }
}

// 소켓 바인드
void SocketServer::SocketBind()
{
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(m_ipAddress.c_str());
    serverAddr.sin_port = htons(m_port);

    if (bind(m_socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1)
    {
        throw std::runtime_error("소켓 바인드 실패");
    }
}

// 소켓 리슨
void SocketServer::SocketListen()
{
    if (listen(m_socketFd, 10) == -1)
    {
        throw std::runtime_error("소켓 리슨 실패");
    }
}

// 클라이언트 연결 수락
void SocketServer::ConnectNewClient()
{
    sockaddr_in clientAddr{};
    socklen_t clientAddrLen = sizeof(clientAddr);
    int clientFd = accept(m_socketFd, (struct sockaddr*)&clientAddr, &clientAddrLen);
   
    fcntl(clientFd, F_GETFL, 0);


    if (clientFd == -1)
    {
        std::cerr << "클라이언트 수락 실패" << std::endl;
        return;
    }

	if(false == m_Isinit)
	{
		InitializeSSL();
		m_Isinit = true;
	}

    SSL *new_ssl = SSL_new(m_ctx);

    if (new_ssl == nullptr) 
    {
        std::cerr << "SSL_new failed" << std::endl;
        ERR_print_errors_fp(stderr);
        return;
    }

    SSL_set_fd(new_ssl, clientFd);

    std::cout << "SSL handshake 시작" << std::endl;

    // TLS/SSL 핸드쉐이크 수행
    // SSL_accept()는 클라이언트로부터 수신된 요청을 처리하고, SSL/TLS 핸드쉐이크 과정의 모든 단계(인증서 교환, 암호화 설정 등)를 진행
    if (SSL_accept(new_ssl) <= 0) 
    {
        std::cerr << "SSL accept failed" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(new_ssl);
        close(clientFd);
        return;
    }

    m_SSLClients.push_back(new_ssl);
    m_SSLClientNames[new_ssl] = "Default";

	SSLBroadcastMessage("ClientFd: " + std::to_string(clientFd) + " entered\n",nullptr, -1);

	fcntl(clientFd, F_GETFL, 0);

}

// 클라이언트 SSL 데이터 처리
void SocketServer::HandleClientSSLData(SSL* c_ssl)
{
    char buffer[1024];
    int len = SSL_read(c_ssl, buffer, sizeof(buffer) - 1);

    if (len > 0) 
    {
        buffer[len] = '\0';
        std::string message(buffer);

        if (message == "exit\n")
        {
            m_SSLClosedClients.push_back(c_ssl);
            return;
        }
        else
        {
            if (m_SSLClientNames[c_ssl] == "Default")
            {
				message.pop_back();
                ToUpper(message);
                if (
                    m_NameSet.find(message) == m_NameSet.end() &&
                    std::find(message.begin(), message.end(), ' ') == message.end() &&
                    message != "DEFAULT" && message != "ERROR"
                )
                {
                    m_SSLClientNames[c_ssl] = message;
                    m_NameSet.insert(message);
                    SSLBroadcastMessage(message, c_ssl, 2);
                }
                else
                {
                    SSLBroadcastMessage("ERROR", c_ssl, 100);
                }
            }
            else
            {
                SSLBroadcastMessage(m_SSLClientNames[c_ssl] + ": " + message, c_ssl);
            }
        }
    }
    else
    {
        m_SSLClosedClients.push_back(c_ssl);
    }
}

// 소켓 수용 및 데이터 처리
void SocketServer::SocketAccept()
{
    fd_set readfds;
    int max_fd = m_socketFd;

	std::cout<<"클라이언트 연결 대기 시작"<<std::flush;

    while (true)
    {
        RemoveClosedClients();

        // 파일 디스크립터 집합 초기화
        FD_ZERO(&readfds);
        FD_SET(m_socketFd, &readfds);

        // 클라이언트 SSL을 통해 소켓 추가
        for (auto &client_ssl : m_SSLClients)
        {
            int client_fd = SSL_get_fd(client_ssl);
            FD_SET(client_fd, &readfds);
            if (client_fd > max_fd)
            {
                max_fd = client_fd;
            }
        }

        // select 호출
        int activity = select(max_fd + 1, &readfds, nullptr, nullptr, nullptr);
        if (activity < 0)
        {
            std::cerr << "select 오류" << std::endl;
            continue;
        }

        // 새로운 연결 요청 수락
        if (FD_ISSET(m_socketFd, &readfds))
        {
            ConnectNewClient();
			std::cout<<"ssl handshake done"<<std::endl;
        }

        // 클라이언트 데이터 처리
        for (auto it = m_SSLClients.begin(); it != m_SSLClients.end(); ++it) 
        {
            SSL *c_ssl = *it;
            int clientFd = SSL_get_fd(c_ssl);

            if (FD_ISSET(clientFd, &readfds)) 
            {
                HandleClientSSLData(c_ssl);
            }
        }
    }
}

// 닫힌 클라이언트 제거
void SocketServer::RemoveClosedClients()
{
    for (SSL* c_ssl : m_SSLClosedClients)
    {
        if (c_ssl != nullptr)
        {
            std::string newMessage;
            int clientFd = SSL_get_fd(c_ssl);

            if (m_SSLClientNames[c_ssl] == "Default")
            {
                newMessage = "ClientFd: " + std::to_string(clientFd) + " leave\n";
				SSLBroadcastMessage(newMessage, c_ssl,-1);
			}
            else
            {
                newMessage = m_SSLClientNames[c_ssl] + " leave\n";
                m_NameSet.erase(m_SSLClientNames[c_ssl]);
				SSLBroadcastMessage(newMessage, c_ssl);
            }


            m_SSLClients.erase(std::find(m_SSLClients.begin(), m_SSLClients.end(), c_ssl));
            m_SSLClientNames.erase(c_ssl);
            SSL_shutdown(c_ssl);
            SSL_free(c_ssl);
            close(clientFd);
        }
    }
    m_SSLClosedClients.clear();
}

// 대문자 처리
void SocketServer::ToUpper(std::string& str)
{
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return std::toupper(c);
    });
}

// SSL 메시지 브로드캐스트
void SocketServer::SSLBroadcastMessage(const std::string& message, SSL* senderSSL, int flag)
{
 // -1 : Broadcast하지 않고 로그만 남김
// 0 : 본인 포함 모든 클라이언트에게 Broadcast
// 1 : 본인 제외 모든 클라이언트에게 Broadcast
// 2: 이름 설정 성공
// 100 : 이름 설정 실패(senderFd에게만 send)
// 101 : sender에게만 보냄
    std::string logMessage = message;

    switch (flag)
    {
        case -1:
            // 플래그가 -1인 경우, 메시지를 아무 클라이언트에게도 전송하지 않음
            break;
        case 0:
            // 플래그가 0인 경우, 모든 클라이언트에게 메시지 전송
            for (SSL* c_ssl : m_SSLClients)
            {
                if (SSL_write(c_ssl, message.c_str(), message.size()) <= 0)
                {
                    std::cerr << "메시지 전송 실패" << std::endl;
                }
            }
            break;
        case 1:
            // 플래그가 1인 경우, 발신자를 제외한 모든 클라이언트에게 메시지 전송
            for (SSL* c_ssl : m_SSLClients)
            {
                if (c_ssl != senderSSL && m_SSLClientNames[c_ssl] != "Default")
                {
                    if (SSL_write(c_ssl, message.c_str(), message.size()) <= 0)
                    {
                        std::cerr << "메시지 전송 실패" << std::endl;
                    }
                }
            }
            break;
        case 2:
            // 플래그가 2인 경우, 발신자를 제외한 모든 클라이언트에게 입장 메시지 전송
            logMessage = m_SSLClientNames[senderSSL] + " entered\n";
            for (SSL* c_ssl : m_SSLClients)
            {
                if (c_ssl != senderSSL && m_SSLClientNames[c_ssl] != "Default")
                {
                    if (SSL_write(c_ssl, logMessage.c_str(), logMessage.size()) <= 0)
                    {
                        std::cerr << "메시지 전송 실패" << std::endl;
                    }
                }
            }
            if (SSL_write(senderSSL, message.c_str(), message.size()) <= 0)
            {
                std::cerr << "메시지 전송 실패" << std::endl;
            }
            break;
        case 100:
            // 플래그가 100인 경우, 발신자에게만 에러 메시지 전송
            logMessage = "ClientFd: " + std::to_string(SSL_get_fd(senderSSL)) + " Invalid input\n";
            if (SSL_write(senderSSL, message.c_str(), message.size()) <= 0)
            {
                std::cerr << "메시지 전송 실패" << std::endl;
            }
            break;
	case 101:
	    // 발신자에게만 메세지 전송
	    if (SSL_write(senderSSL, message.c_str(), message.size()) <= 0)
            {
                std::cerr << "메시지 전송 실패" << std::endl;
            }
			break;
    }
    
    // 로그 메시지 기록
    LogEvent(logMessage);
}

// 소켓 옵션 설정 및 바인드, 리스닝
void SocketServer::Setting()
{
    // 소켓 옵션 설정
    int opt = 1;
    if (setsockopt(m_socketFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        throw std::runtime_error("소켓 옵션 설정 실패");
    }

    SocketBind();
    SocketListen();
}

// 소켓을 통한 클라이언트 연결 수락
void SocketServer::SocketRunning()
{
    SocketAccept();
}



// SSL 초기화 및 설정
void SocketServer::InitializeSSL()
{
    // OpenSSL 라이브러리 초기화
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms(); // OpenSSL에서 지원하는 모든 알고리즘을 로드하는 것.

    // SSL 컨텍스트 생성
    m_ctx = SSL_CTX_new(TLS_server_method());  // TLS_server_method() : 서버 측에서 사용할 SSL/TLS 프로토콜 메서드를 반환. 최신 TLS 프로토콜을 지원하며, 서버용 SSL/TLS 연결을 설정할 때 사용함
    if (!m_ctx)
    {
        std::cerr << "Failed to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(1);
    }

/*    
	const char *cipher_list = "AES256-SHA";
    if (SSL_CTX_set_cipher_list(m_ctx, cipher_list) != 1) {
        fprintf(stderr, "Error setting cipher list\n");
        ERR_print_errors_fp(stderr);
    }

*/
	// 인증서 및 개인 키 로드
    if (SSL_CTX_use_certificate_file(m_ctx, "testkey/server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(m_ctx, "testkey/server.key", SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Failed to load certificate or key" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(m_ctx);
        exit(1);
    }
	// SSL 키 로그 콜백 설정
    SSL_CTX_set_keylog_callback(m_ctx, [](const SSL *ssl, const char *line) {
        static std::ofstream keylog_file("/Users/n22406007/Documents/0909/SocketChatApp/sslkeys.log", std::ios::app);
        if (keylog_file.is_open()) {
            keylog_file << line << std::endl;
        }
    });
    // SSL 초기화 성공 메시지
    std::cout << "서버 SSL 초기화 성공" << std::endl;

}
