#include "SocketClient.h"
#include <iostream>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <poll.h>
#include <vector>
#include <openssl/err.h>

// 생성자: IP 주소와 포트 번호를 설정
SocketClient::SocketClient(const std::string& ipAddress, int port)
    : SocketBase(ipAddress, port), m_ssl(nullptr), MyName(""), m_Trycnt(0) 
{
    // 생성자 내용 추가
}


// 소멸자: 자원 정리
SocketClient::~SocketClient()
{
    std::cout << "SocketClient destructor called." << std::endl;

    // SSL 핸드쉐이크 종료
    if (m_ssl) 
    {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
    }

    // 소켓 종료
    if (m_socketFd != -1) 
    {
        close(m_socketFd);
    }

    // SSL_CTX 종료
    if (m_ctx) 
    {
        SSL_CTX_free(m_ctx);
    }

    // 소켓 종료
    SocketClose();
}

// 서버에 연결
void SocketClient::SocketConnect() 
{
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(m_port);

    if (inet_pton(AF_INET, m_ipAddress.c_str(), &serverAddr.sin_addr) <= 0) 
    {
        throw std::runtime_error("유효하지 않은 IP 주소");
    }

    if (connect(m_socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) 
    {
        throw std::runtime_error("서버에 연결 실패");
    }

    std::cout << "서버 연결 완료" << std::endl;
}

// 클라이언트 설정
void SocketClient::Setting() 
{
    SocketConnect();

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx) 
    {
        std::cerr << "Failed to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_load_verify_locations(m_ctx, "key/ca.pem", nullptr) <= 0) 
    {
        std::cerr << "Failed to load CA certificate" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(m_ctx);
        exit(1);
    }

    // TLS/SSL 핸드쉐이크를 위한 SSL 객체 생성
    m_ssl = SSL_new(m_ctx);
    SSL_set_fd(m_ssl, m_socketFd);

    // TLS/SSL 핸드쉐이크 수행
    if (SSL_connect(m_ssl) <= 0) 
    {
        std::cerr << "SSL connect failed" << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(m_ssl);
        close(m_socketFd);
        SSL_CTX_free(m_ctx);
        exit(1);
    }
}

// 사용자 입력 처리
void SocketClient::HandleInput() 
{
    std::string message;
    if (std::getline(std::cin, message)) 
    {
        SSL_write(m_ssl, message.c_str(), message.size());
        if (message == "exit") 
        {
            m_Running = false;
            return;
        }
    } 
    else 
    {
        std::cerr << "입력 오류 발생" << std::endl;
        m_Running = false;
        return;
    }
}

// 서버 응답 처리
void SocketClient::HandleServerResponse() 
{
    char buffer[1024];
    ssize_t bytesRead = SSL_read(m_ssl, buffer, sizeof(buffer) - 1);
    if (bytesRead > 0 && m_Trycnt < 3) 
    {
        buffer[bytesRead] = '\0'; // 문자열 끝에 NULL 추가
        if (bytesRead == 4 && std::string(buffer) == "exit") 
        {
            m_Running = false;
            return;
        }

        if (MyName.empty()) 
        {
            std::string recv_Message(buffer);
            if (recv_Message == "ERROR") 
            {
                m_Trycnt++;
                if (m_Trycnt < 3) 
                {
                    std::cout << "이름을 다시 입력해주세요 : " << std::flush;
                } 
            }
            else 
            {
                MyName = recv_Message;
            }
        } 
        else 
        {
            std::cout << buffer << std::endl;
        }
    } 
    else 
    {
        m_Running = false;
        std::cerr << "\n서버와의 연결이 끊어졌습니다." << std::endl;
        return;
    }
}

// 소켓 실행
void SocketClient::SocketRunning() 
{
    m_Running = true;
    std::cout << "이름을 입력하세요 : " << std::flush;

    // Poll setup
    std::vector<struct pollfd> fds;
    fds.push_back({m_socketFd, POLLIN, 0});     // 소켓 모니터링
    fds.push_back({STDIN_FILENO, POLLIN, 0});   // 터미널 입력 모니터링 

    while (m_Running) 
    {
        int poll_count = poll(fds.data(), fds.size(), 0);
        if (poll_count < 0) 
        {
            std::cerr << "Poll error" << std::endl;
            break;
        }

        if (fds[0].revents & POLLIN) 
        {
            // 데이터 read 처리
            HandleServerResponse();
        }

        if (fds[1].revents & POLLIN) 
        {
            HandleInput();
        }
    }

    SSL_shutdown(m_ssl);
    SSL_free(m_ssl);
    close(m_socketFd);
    SSL_CTX_free(m_ctx);
}
