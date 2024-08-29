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
    SocketConnect();
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
    while (m_Running && m_Trycnt < 3) 
    {
        if (IsInputAvailable()) 
        {
            std::string message;
            if (std::getline(std::cin, message)) 
            {
                if (message == "exit") 
                {
                    SocketWrite(m_socketFd, "exit", 4); // "exit" 문자열 전송
                    m_Running = false; // 종료 신호 설정
                    break;
                }
                SocketWrite(m_socketFd, message.c_str(), message.size());
            } 
            else 
            {
                std::cerr << "입력 오류 발생" << std::endl;
                m_Running = false;
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    }
    SocketClose();
}

// 서버 응답 처리
void SocketClient::HandleServerResponse() 
{
    char buffer[1024];
    while (m_Running) 
    {
        ssize_t bytesRead = SocketRead(m_socketFd, buffer, sizeof(buffer) - 1);
        if (bytesRead > 0 && m_Trycnt < 3) 
        {
            buffer[bytesRead] = '\0'; // 문자열 끝에 NULL 추가
            if (bytesRead == 4 && std::string(buffer) == "exit") 
            {
                m_Running = false;
                break;
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
            break;
        }
    }
}

// 소켓 실행
void SocketClient::SocketRunning() 
{

    m_Running = true;
    std::cout<<"이름을 입력하세요 : "<< std::flush;// 버퍼에 담긴 데이터가 모두 쏟아지는 것

    // 서버 응답을 처리할 스레드 시작
    std::thread responseThread(&SocketClient::HandleServerResponse, this);

    // 사용자 입력 스레드 시작
    
    HandleInput();


    // 응답 스레드와 입력 스레드 종료 대기
    if (responseThread.joinable()) 
    {
        responseThread.join();
    }

}
