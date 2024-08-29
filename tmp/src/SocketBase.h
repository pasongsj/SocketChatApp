//SocketBase.h
#pragma once

#include <string>
#include <stdexcept>
#include <arpa/inet.h> 
#include <cstring>
#include <unistd.h>  

class SocketBase 
{
public:
    // 생성자: IP 주소와 포트 번호를 설정
    SocketBase(const std::string& ipAddress, int port)
	: m_ipAddress(ipAddress), m_port(port), m_socketFd(-1) 
    {
    	// 생성자: IP 주소와 포트를 초기화하고 소켓 파일 디스크립터를 -1로 설정
    }

    // 소멸자: 소켓 종료
    virtual ~SocketBase()
    {
    	// 소멸자: 소켓 종료
        SocketClose();
    }

    // 소켓 생성
    void CreateSocket()
    {
    	// 소켓 생성
    	m_socketFd = socket(AF_INET, SOCK_STREAM, 0);
    	if (m_socketFd == -1) 
    	{
            throw std::runtime_error("소켓 생성에 실패했습니다."); // 에러 메시지
        }
    }

    // 소켓 종료
    void SocketClose()
    {
        // 소켓 종료
        if (m_socketFd != -1) 
        {
            close(m_socketFd);
            m_socketFd = -1;
        }
    }

    // 설정 메서드 (서브클래스에서 재정의 가능)
    virtual void Setting() {}

    // 소켓 실행 메서드 (서브클래스에서 재정의 가능)
    virtual void SocketRunning() {}

    // IP 주소 설정
    void SetIp(const std::string& ipAddress) 
    {
        m_ipAddress = ipAddress;
    }

    // 포트 설정
    void SetPort(const int port) 
    {
        m_port = port;
    }

    // IP 주소 가져오기
    std::string GetIp() const
    {
        return m_ipAddress;
    }

    // 포트 가져오기
    int GetPort() const
    {
        return m_port;
    }
    
protected:
    std::string m_ipAddress;  // IP 주소
    int m_port;               // 포트 번호
    int m_socketFd;           // 소켓 파일 디스크립터
    
    // 소켓에 데이터 쓰기
    ssize_t SocketWrite(int fd, const void* buffer, size_t length) const 
    {
        return write(fd, buffer, length);
    }

    // 소켓에서 데이터 읽기
    ssize_t SocketRead(int fd, void* buffer, size_t length) const 
    {
        return read(fd, buffer, length);
    }

private:
    // 복사 생성자 및 대입 연산자 삭제
    SocketBase(const SocketBase&) = delete;
    SocketBase& operator=(const SocketBase&) = delete;
};