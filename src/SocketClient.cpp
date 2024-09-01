#include "SocketClient.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <sys/select.h>
#include <poll.h>
#include <fcntl.h>

// 소멸자: 자원 정리
SocketClient::~SocketClient()
{
	std::cout << "SocketServer destructor called." << std::endl;
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
/*	{
		int flags = fcntl(m_socketFd, F_GETFL, 0);
		if (flags == -1) 
		{
			throw std::runtime_error("fcntl get failed");
		}
		if (fcntl(m_socketFd, F_SETFL, flags | O_NONBLOCK) == -1) 
		{
			throw std::runtime_error("fcntl set failed");
		}
	}*/
    SocketConnect();
	SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

	m_ctx = SSL_CTX_new(TLS_client_method());
    if (!m_ctx) {
        std::cerr << "Failed to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(1);
    }


	if (SSL_CTX_load_verify_locations(m_ctx, "key/ca.pem", nullptr) <= 0) {
    std::cerr << "Failed to load CA certificate" << std::endl;
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(m_ctx);
    exit(1);
	}

	// TLS/SSL 핸드쉐이크를 위한 SSL 객체 생성
    m_ssl = SSL_new(m_ctx);
    SSL_set_fd(m_ssl, m_socketFd);

    // TLS/SSL 핸드쉐이크 수행
    if (SSL_connect(m_ssl) <= 0) {
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
    //while (m_Running && m_Trycnt < 3) 
    //{
        std::string message;
        if (std::getline(std::cin, message)) 
        {
			SSL_write(m_ssl,message.c_str(),message.size());
            if (message == "exit") 
            {
            //    SocketWrite(m_socketFd, "exit", 4); // "exit" 문자열 전송
                m_Running = false; // 종료 신호 설정
                return;
            }
           // SocketWrite(m_socketFd, message.c_str(), message.size());
        } 
        else 
        {
            std::cerr << "입력 오류 발생" << std::endl;
            m_Running = false;
            return;
        }

    //}
    //SocketClose();
}

// 서버 응답 처리
void SocketClient::HandleServerResponse() 
{
    char buffer[1024];
   // while (m_Running) 
   // {
       // ssize_t bytesRead = SocketRead(m_socketFd, buffer, sizeof(buffer) - 1);
        ssize_t bytesRead = SSL_read(m_ssl,buffer,sizeof(buffer)-1);
		if (bytesRead > 0 && m_Trycnt < 3) 
        {
            buffer[bytesRead] = '\0'; // 문자열 끝에 NULL 추가
            if (bytesRead == 4 && std::string(buffer) == "exit") 
            {
                m_Running = false;
				return;
            }
			if(true == MyName.empty())
			{
				std::string recv_Message(buffer);
				if("ERROR" == recv_Message)
				{
					m_Trycnt++;
					if(m_Trycnt<3)
					{
					std::cout<<"이름을 다시 입력해주세요 : "<< std::flush;
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
    //}
}

// 소켓 실행
void SocketClient::SocketRunning() 
{

    m_Running = true;
    
	std::cout<<"이름을 입력하세요 : "<< std::flush;// 버퍼에 담긴 데이터가 모두 쏟아지는 것

	// Poll setup
    std::vector<struct pollfd> fds;
    fds.push_back({m_socketFd, POLLIN, 0});     // 소켓 모니터링
    fds.push_back({STDIN_FILENO, POLLIN, 0});   // 터미널 입력 모니터링 


    while (m_Running) {
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
/*

			char buffer[1024];
            int len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (len > 0) {
                buffer[len] = '\0';
                std::cout << "Received from server: " << buffer << std::endl;
            } else {
                std::cerr << "Server connection closed" << std::endl;
                break;
            }
  */      }

        if (fds[1].revents & POLLIN) 
		{
            HandleInput();
/*
			std::string message;
            std::getline(std::cin, message);
            if (!message.empty()) {
                SSL_write(ssl, message.c_str(), message.size());
            }
  */      }
    }

	/*
	std::vector<struct pollfd> fds;
    fds.push_back({m_socketFd, POLLIN, 0});		// 소켓 모니터링
    fds.push_back({STDIN_FILENO, POLLIN, 0});	// 터미널 입력 모니터링	

    while (true == m_Running) {
        int ret = poll(fds.data(), fds.size(), 0); // -1 means wait indefinitely
        if (ret < 0) {
            perror("Poll failed");
            close(m_socketFd);
			break;
		}

        // 서버에서 온 데이터가 있는지 확인 
        if (fds[0].revents & POLLIN) 
		{
            // 데이터 read 처리
			HandleServerResponse();
        }

        // Check if there is user input
        if (fds[1].revents & POLLIN) 
		{
			HandleInput();
        }
    }
	SocketClose();
*/
	SSL_shutdown(m_ssl);
    SSL_free(m_ssl);
    close(m_socketFd);
    SSL_CTX_free(m_ctx);
}
