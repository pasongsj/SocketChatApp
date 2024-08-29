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

// 생성자
SocketServer::SocketServer(const std::string& ipAddress, int port)
    : SocketBase(ipAddress, port)
{
    OpenLogFile(); // 로그 파일 열기
}

// 소멸자
SocketServer::~SocketServer()
{
	std::cout << "SocketServer destructor called." << std::endl;
    for (int fd : m_ClientSockets)
    {
        close(fd); // 클라이언트 소켓 닫기
    }
    m_ClientSockets.clear(); // 클라이언트 소켓 목록 비우기
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

    m_ClientNames[clientFd] = "Default";
    m_ClientSockets.push_back(clientFd);
}

void SocketServer::HandleClientData(int _fd)
{
	char buffer[1024];
    ssize_t bytesRead = SocketRead(_fd, buffer, sizeof(buffer) - 1);
    if (bytesRead > 0)
    {
		buffer[bytesRead] = '\0';
        std::string message(buffer);
        if (message == "exit")
        {
			CloseClientSocket(_fd);
            m_ClosedClients.push_back(_fd);
        }
        else
        {
			if (m_ClientNames[_fd] == "Default")
			{
				ToUpper(message);
                if (
						m_NameSet.find(message) == m_NameSet.end() &&
						std::find(message.begin(), message.end(), ' ') == message.end() &&
                        message != "DEFAULT" && message != "ERROR"
					)
                    {
						m_ClientNames[_fd] = message;
                        m_NameSet.insert(message);
						BroadcastMessage(message, _fd, 2);
					}
                else
                {
                    BroadcastMessage("ERROR", _fd, 100);
                }
            }
            else
            {
                BroadcastMessage(m_ClientNames[_fd] + ": " + message, _fd);
            }
        }
    }
    else
    {
		CloseClientSocket(_fd);
        m_ClosedClients.push_back(_fd);
    }
}


// 소켓 에셉
void SocketServer::SocketAccept()
{
    fd_set readfds;
    int max_sd = m_socketFd;

    while (true)
    {
        // 파일 디스크립터 집합 초기화
        FD_ZERO(&readfds);
        FD_SET(m_socketFd, &readfds);

        // 클라이언트 소켓 추가
        for (int fd : m_ClientSockets)
        {
            FD_SET(fd, &readfds);
            if (fd > max_sd)
            {
                max_sd = fd;
            }
        }

        // select 호출
        int activity = select(max_sd + 1, &readfds, nullptr, nullptr, nullptr);
        if (activity < 0)
        {
            std::cerr << "select 오류" << std::endl;
            continue;
        }

        // 새로운 연결 요청 수락
        if (FD_ISSET(m_socketFd, &readfds))
        {
            ConnectNewClient();
        }

        // 클라이언트 소켓에서 데이터 읽기
        for (int fd : m_ClientSockets)
        {
            if (FD_ISSET(fd, &readfds))
            {
				HandleClientData(fd);
            }
        }

        // 클라이언트 소켓 리스트에서 닫힌 소켓 제거
		RemoveClosedClients();
    }
}

void SocketServer::RemoveClosedClients() {
    for (int fd : m_ClosedClients) {
        auto it = std::find(m_ClientSockets.begin(), m_ClientSockets.end(), fd);
        if (it != m_ClientSockets.end()) {
            m_ClientSockets.erase(it);
        }
    }
}

// 종료한 클라이언트 정보 지우기
void SocketServer::CloseClientSocket(int clientFd)
{
	std::string newMessage;
	if("Default" == m_ClientNames[clientFd])
	{
		newMessage = "ClientFd: "+std::to_string(clientFd) +" exit";
	}
	else
	{ 
		newMessage = m_ClientNames[clientFd] + " exit";
	}
	BroadcastMessage(newMessage, clientFd);
    if (m_ClientNames.find(clientFd) != m_ClientNames.end() && m_ClientNames[clientFd] != "Default")
    {
        m_NameSet.erase(m_ClientNames[clientFd]);
        m_ClientNames.erase(clientFd);
    }
    close(clientFd);
}

// 대문자처리
void SocketServer::ToUpper(std::string& str)
{
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return std::toupper(c);
    });
}

// 브로드 캐스트
void SocketServer::BroadcastMessage(const std::string& message, int senderFd, int flag)
{
// -1 : Broadcast하지 않고 로그만 남김
// 0 : 본인 포함 모든 클라이언트에게 Broadcast
// 1 : 본인 제외 모든 클라이언트에게 Broadcast
// 2: 이름 설정 성공
// 100 : 이름 설정 실패(senderFd에게만 send)

	std::string logmessage;
	logmessage = message;
	switch(flag)
	{
		case -1:
			{
				break;
			}
		case 0:
			{
				for (int fd : m_ClientSockets)
				{
					SocketWrite(fd, message.c_str(), message.size());
				}
				break;
			}
		case 2:
			{
				logmessage = m_ClientNames[senderFd] + " entered";
			}
		case 1:
			{
				for (int fd : m_ClientSockets)
				{
					if ((fd == senderFd) || m_ClientNames[fd] == "Default")
					{
						continue;
					}
					SocketWrite(fd, message.c_str(), message.size());
				}
				break;
			}

		case 100:
			{
				logmessage = "ClientFd: "+ std::to_string(senderFd) + " Invalid input";
				SocketWrite(senderFd,message.c_str(),message.size());
				break;
			}
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
