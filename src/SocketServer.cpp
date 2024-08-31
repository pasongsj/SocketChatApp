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

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// 생성자
SocketServer::SocketServer(const std::string& ipAddress, int port)
    : SocketBase(ipAddress, port)
{
    OpenLogFile(); // 로그 파일 열기
    InitSSL();
}

// 소멸자
SocketServer::~SocketServer()
{
    std::cout << "SocketServer destructor called." << std::endl;
    for (ClientData* clientData : m_Clients)
    {
        CloseClient(clientData);
        delete clientData; // 메모리 해제
    }
    m_Clients.clear();

    SSL_CTX_free(ctx);
    SocketClose(); // 메인 소켓 닫기
    if (m_logFile.is_open())
    {
        m_logFile.close();
    }
}

// 로그 폴더 생성
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

// 로그 남기기
void SocketServer::LogEvent(const std::string& event)
{
    std::cout << event << std::endl;
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

// SSL 초기화
void SocketServer::InitSSL()
{
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    const SSL_METHOD* meth = TLS_server_method();
    ctx = SSL_CTX_new(meth);

    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    const char* pem_file = "./key/server.pem";
    if (SSL_CTX_use_certificate_file(ctx, pem_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(2);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, pem_file, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
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

void SocketServer::ConnectNewClient()
{
    sockaddr_in clientAddr{};
    socklen_t clientAddrLen = sizeof(clientAddr);
    int clientFd = accept(m_socketFd, (struct sockaddr*)&clientAddr, &clientAddrLen);
    if (clientFd == -1)
    {
        std::cerr << "클라이언트 수락 실패" << std::endl;
        return;
    }

    std::cout << "클라이언트 fd 번호 " << clientFd << std::endl;

    SSL* clissl = SSL_new(ctx);
    if (nullptr == clissl)
    {
        exit(1);
    }
    SSL_set_fd(clissl, clientFd);
    int err = SSL_accept(clissl);
    if (-1 == err)
    {
        exit(1);
    }

    ClientData* newClient = new ClientData();
    newClient->Fd = clientFd;
    newClient->ssl = clissl;
    newClient->Name = "Default";

    m_Clients.push_back(newClient);
}

void SocketServer::HandleClientData(ClientData* clientData)
{
    char buffer[1024];
    ssize_t bytesRead = SSL_read(clientData->ssl, buffer, sizeof(buffer) - 1);
    if (bytesRead > 0)
    {
        buffer[bytesRead] = '\0';
        std::string message(buffer);
		std::cout<<message<<'\n';
		if (message == "exit")
        {
            CloseClient(clientData);
            m_ClosedClients.push_back(clientData);
        }
        else
        {
            if (clientData->Name == "Default")
            {
                ToUpper(message);
                auto it = m_NameSet.find(message);
                if (it == m_NameSet.end() &&
                    message.find(' ') == std::string::npos &&
                    message != "DEFAULT" && message != "ERROR")
                {
                    m_NameSet.insert(message);
                    clientData->Name = message;
                    BroadcastMessage(message, clientData, 2);
                }
                else
                {
                    BroadcastMessage("ERROR", clientData, 100);
                }
            }
            else
            {
                BroadcastMessage(clientData->Name + ": " + message, clientData);
            }
        }
    }
    else
    {
        CloseClient(clientData);
        m_ClosedClients.push_back(clientData);
    }
}

// 소켓 에셉
void SocketServer::SocketAccept()
{
    fd_set readfds;
    int max_sd = m_socketFd;

    while (true)
    {
        FD_ZERO(&readfds);
        FD_SET(m_socketFd, &readfds);

        for (ClientData* clientData : m_Clients)
        {
            FD_SET(clientData->Fd, &readfds);
            if (clientData->Fd > max_sd)
            {
                max_sd = clientData->Fd;
            }
        }

        int activity = select(max_sd + 1, &readfds, nullptr, nullptr, nullptr);
        if (activity < 0)
        {
            std::cerr << "select 오류" << std::endl;
            continue;
        }

        if (FD_ISSET(m_socketFd, &readfds))
        {
            ConnectNewClient();
        }

        for (ClientData* clientData : m_Clients)
        {
            if (FD_ISSET(clientData->Fd, &readfds))
            {
                HandleClientData(clientData);
            }
        }

        RemoveClosedClients();
    }
}

void SocketServer::RemoveClosedClients()
{
    for (ClientData* clientData : m_ClosedClients)
    {
        auto it = std::find_if(m_Clients.begin(), m_Clients.end(),
            [clientData](ClientData* data) 
			{ 
				return data->Fd == clientData->Fd; 
			});
        if (it != m_Clients.end())
        {
            m_Clients.erase(it);
        }
        delete clientData; // 메모리 해제
    }
    m_ClosedClients.clear();
}

// 종료한 클라이언트 정보 지우기
void SocketServer::CloseClient(ClientData* clientData)
{
    std::string newMessage;
    if (clientData->Name == "Default")
    {
        newMessage = "ClientFd: " + std::to_string(clientData->Fd) + " exit";
    }
    else
    {
        newMessage = clientData->Name + " exit";
        m_NameSet.erase(clientData->Name);
    }
    BroadcastMessage(newMessage, clientData);

    auto it = std::find(m_Clients.begin(), m_Clients.end(), clientData);
    if (it != m_Clients.end())
    {
        m_Clients.erase(it);
    }

    SSL_free(clientData->ssl);
    close(clientData->Fd);
}

// 대문자처리
void SocketServer::ToUpper(std::string& str)
{
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return std::toupper(c);
    });
}

// 브로드 캐스트
void SocketServer::BroadcastMessage(const std::string& message, ClientData* senderClientData, int flag)
{
    std::string logmessage = message;
    switch (flag)
    {
        case -1:
            break;
        case 0:
            for (ClientData* clientData : m_Clients)
            {
//                SSL_write(clientData->ssl, message.c_str(), message.size());
            }
            break;
        case 2:
            logmessage = senderClientData->Name + " entered";
            for (ClientData* clientData : m_Clients)
            {
                if ((clientData == senderClientData) || clientData->Name == "Default")
                {
                    continue;
                }
//                SSL_write(clientData->ssl, logmessage.c_str(), logmessage.size());
            }
//            SSL_write(senderClientData->ssl, message.c_str(), message.size());
            break;
        case 1:
            for (ClientData* clientData : m_Clients)
            {
                if ((clientData == senderClientData) || clientData->Name == "Default")
                {
                    continue;
                }
//                SSL_write(clientData->ssl, message.c_str(), message.size());
            }
            break;
        case 100:
            logmessage = "ClientFd: " + std::to_string(senderClientData->Fd) + " Invalid input";
//            SSL_write(senderClientData->ssl, message.c_str(), message.size());
            break;
    }
    LogEvent(logmessage);
}

void SocketServer::Setting()
{
    SocketBind();
    SocketListen();
}

void SocketServer::SocketRunning()
{
    SocketAccept();
}
