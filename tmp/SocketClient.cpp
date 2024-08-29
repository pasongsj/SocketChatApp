#include "SocketClient.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <sys/select.h>

// 소멸자: 자원 정리
SocketClient::~SocketClient()
{
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

    while (m_Running) 
    {
        if (IsInputAvailable()) 
        {
            	std::string message;
            	if (std::getline(std::cin, message)) 
            	{
                	if (message == "exit") 
                	{
                    	//SocketWrite(m_socketFd, "exit", 4); // "exit" 문자열 전송
                    	running = false; // 종료 신호 설정
                    	break;
                	}
                	SocketWrite(m_socketFd, message.c_str(), message.size());
		   	// 서버로부터 응답 받기
        	   	char buffer[1024];
        	   	ssize_t bytesRead = SocketRead(m_socketFd, buffer, sizeof(buffer) - 1);
        	   	if (bytesRead > 0) 
        	   	{
            	   		buffer[bytesRead] = '\0'; // 문자열 끝에 NULL 추가
            	  		std::string message(buffer);
             		if (message == "exit")
            			{
                			m_Running = false;
                			break;
            			} 
            			else if (message != "ERROR")
            			{
                			MyName = message;
                			std::cout << "이름 설정 완료" << std::endl;
                			break;
            			}
            			else
            			{
                			std::cerr << "이름 설정 실패. 다시 시도하세요." << std::endl;
                			attempt++;
            			}
        		} 
        		else 
        		{
            			m_Running = false;
            			std::cerr << "서버와의 연결이 끊어졌습니다." << std::endl;
            			break;
        		}
            } 
            else 
            {
                	std::cerr << "입력 오류 발생" << std::endl;
                	running = false;
                	break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

/*
    int attempt = 0;
    while (attempt < 3 && MyName.empty()) 
    {
        std::string name;
        std::cout << "이름을 입력하세요: ";
        std::getline(std::cin, name);
        
        // 이름 보내기
        SocketWrite(m_socketFd, name.c_str(), name.size());

        // 서버로부터 응답 받기
        char buffer[1024];
        ssize_t bytesRead = SocketRead(m_socketFd, buffer, sizeof(buffer) - 1);
        if (bytesRead > 0) 
        {
            buffer[bytesRead] = '\0'; // 문자열 끝에 NULL 추가
            std::string message(buffer);
            if (message == "exit")
            {
                m_Running = false;
                break;
            } 
            else if (message != "ERROR")
            {
                MyName = message;
                std::cout << "이름 설정 완료" << std::endl;
                break;
            }
            else
            {
                std::cerr << "이름 설정 실패. 다시 시도하세요." << std::endl;
                attempt++;
            }
        } 
        else 
        {
            m_Running = false;
            std::cerr << "서버와의 연결이 끊어졌습니다." << std::endl;
            break;
        }
    }
*/
}

// 비블로킹 입력 확인
bool SocketClient::IsInputAvailable() {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);

    struct timeval timeout = {0, 0}; // Non-blocking

    return select(STDIN_FILENO + 1, &readfds, nullptr, nullptr, &timeout) > 0;
}

// 사용자 입력 처리
void SocketClient::HandleInput(std::atomic<bool>& running) 
{
    while (m_Running) 
    {
        if (IsInputAvailable()) 
        {
            std::string message;
            if (std::getline(std::cin, message)) 
            {
                if (message == "exit") 
                {
                    SocketWrite(m_socketFd, "exit", 4); // "exit" 문자열 전송
                    running = false; // 종료 신호 설정
                    break;
                }
                SocketWrite(m_socketFd, message.c_str(), message.size());
            } 
            else 
            {
                std::cerr << "입력 오류 발생" << std::endl;
                running = false;
                break;
            }
        }
        // Optionally, add a small sleep to reduce CPU usage
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// 서버 응답 처리
void SocketClient::HandleServerResponse(std::atomic<bool>& running) 
{
    char buffer[1024];
    while (running) 
    {
        ssize_t bytesRead = SocketRead(m_socketFd, buffer, sizeof(buffer) - 1);
        if (bytesRead > 0) 
        {
            buffer[bytesRead] = '\0'; // 문자열 끝에 NULL 추가
            if (bytesRead == 4 && std::string(buffer) == "exit") 
            {
                running = false;
                break;
            }
            std::cout << buffer << std::endl;
        } 
        else 
        {
            // 서버가 종료되었거나 연결이 끊어진 경우
            running = false;
            std::cerr << "서버와의 연결이 끊어졌습니다." << std::endl;
            break;
        }
    }
}

// 소켓 실행
void SocketClient::SocketRunning() 
{
    if (MyName.empty()) 
    {
        std::cerr << "이름이 설정되지 않았습니다." << std::endl;
        return;
    }

    std::atomic<bool> running{true};

    // 서버 응답을 처리할 스레드 시작
    std::thread responseThread(&SocketClient::HandleServerResponse, this, std::ref(running));

    // 사용자 입력을 비동기적으로 처리
    //std::future<void> inputFuture = std::async(std::launch::async, [this, &running]() 
    //{
    //    HandleInput(running);
    //});

    // 사용자 입력 스레드가 완료될 때까지 기다리기
    //inputFuture.get();
    HandleInput(running);
    // 응답 스레드 종료 대기
    if (responseThread.joinable()) 
    {
        responseThread.join();
    }
}
