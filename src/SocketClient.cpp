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



#include <openssl/rsa.h>        /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
	


	ssl = SSL_new(ctx);  // 세션을 위한 자원을 할당받는다.
	if(nullptr == ssl)
    {
       exit(1);
    }

    SSL_set_fd(ssl, m_socketFd);
    int err = SSL_connect(ssl); // 기존의 connect() 함수 대신 사용하여 서버로 접속한다.
    if(-1 == err)
	{
		exit(1);
	}
   
    /* Following two steps are optional and not required for data exchange to be successful. */
   
    /* Get the Cipher – opt */
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));
   
    /* Get server’s certificate (note: beware of dynamic allocation) – opt */
    /* 서버의 인증서를 받는다. */
    X509* server_cert = SSL_get_peer_certificate(ssl);
    if(nullptr == server_cert)
	{
		exit(1);
	}

    printf("Server certificate\n");
   
	char* str = nullptr;
    /* 인증서의 이름을 출력한다. */
    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    if(nullptr == str)
	{
		exit(1);
		printf("t subject: %s\n", str);
	}
    OPENSSL_free(str);
   
    /* 인증서의 issuer를 출력한다. */
    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    if(nullptr == str)
	{
		exit(1);
		printf("t issuer: %s\n", str);
	}
    OPENSSL_free(str);


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
	InitSSL();
    SocketConnect();
}
void SocketClient::InitSSL()
{
    std::cout << "initSSL" << std::endl;
    // SSL 초기화
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); // `SSLeay_add_ssl_algorithms` 대신 `OpenSSL_add_ssl_algorithms` 사용

    const SSL_METHOD* meth = TLS_client_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx) 
    {
        std::cerr << "Failed to create SSL_CTX" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    
    std::cout << "set cert file" << std::endl;
    const char* pem_file = "./key/client.pem";
    if (SSL_CTX_use_certificate_file(ctx, pem_file, SSL_FILETYPE_PEM) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        exit(3);
    }

    std::cout << "set key file" << std::endl;
    if (SSL_CTX_use_PrivateKey_file(ctx, pem_file, SSL_FILETYPE_PEM) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    std::cout << "check key" << std::endl;
    if (!SSL_CTX_check_private_key(ctx)) 
    {
        std::cerr << "Private key does not match the certificate public key" << std::endl;
        exit(5);
    }
}



// 비블로킹 입력 확인
bool SocketClient::IsInputAvailable() 
{
    struct pollfd pfd;
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN; // Read available

    int ret = poll(&pfd, 1, 0); // Non-blocking mode (timeout = 0)
    return ret > 0 && (pfd.revents & POLLIN);
}


// 사용자 입력 처리
void SocketClient::HandleInput() 
{
    //while (m_Running && m_Trycnt < 3) 
    //{
        std::string message;
        if (std::getline(std::cin, message)) 
        {
            if (message == "exit") 
            {
                SSL_write(ssl, "exit", 4); // "exit" 문자열 전송
                m_Running = false; // 종료 신호 설정
                return;
            }
            SSL_write(ssl, message.c_str(), message.size());
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
        ssize_t bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
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
    std::cout << "이름을 입력하세요 : " << std::flush;

    std::vector<struct pollfd> fds;
    fds.push_back({m_socketFd, POLLIN, 0});     // 소켓 모니터링
    fds.push_back({STDIN_FILENO, POLLIN, 0});   // 터미널 입력 모니터링

    while (m_Running) 
    {
        int ret = poll(fds.data(), fds.size(), 1000); // 타임아웃 설정
        if (ret < 0) 
        {
            perror("Poll failed");
            close(m_socketFd);
            break;
        }
        if (ret == 0) 
        {
            // 타임아웃
            continue;
        }

        // 서버에서 온 데이터가 있는지 확인 
        if (fds[0].revents & POLLIN) 
        {
            std::cout << "reading" << std::endl;
            HandleServerResponse();
        }

        // 사용자 입력이 있는지 확인
        if (fds[1].revents & POLLIN) 
        {
            std::cout << "User input" << std::flush;
            HandleInput();
        }
    }
    SocketClose();
}


