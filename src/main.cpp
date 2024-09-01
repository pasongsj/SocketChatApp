#include <iostream>
#include <memory>
#include "SocketServer.h"
#include "SocketClient.h"
#include <csignal>
#include <stdlib.h>
// 소켓 객체 생성
std::unique_ptr<SocketBase> mySocket;
void signalHandler(int signal) {
    // Handle signal
    std::cout << "Signal received: " << signal << std::endl;
	if(mySocket)
	{
//		mySocket->close();
	}
	mySocket.reset();
	std::exit(0); // 정상 종료
}
int main() 
{
    char choice;
    std::string ipAddress;
    int port;

    // 서버 또는 클라이언트 선택
    std::cout << "서버(s) 또는 클라이언트(c) 선택: ";
    std::cin >> choice;
    std::cin.ignore(); // 입력 버퍼에서 개행 문자 제거

    // 유효한 선택인지 검사
    if (choice != 's' && choice != 'c') {
        std::cerr << "잘못된 입력입니다." << std::endl;
        return 1; // 비정상 종료
    }

    // IP 주소와 포트 입력
/*    std::cout << "서버 IP 입력: ";
    std::getline(std::cin, ipAddress);
    std::cout << "서버 포트 입력: ";
    std::cin >> port;
    std::cin.ignore(); // 입력 버퍼에서 개행 문자 제거
*/
	ipAddress= "127.0.0.1";
	port = 1234;

    try {
        if (choice == 's') {
            mySocket = std::make_unique<SocketServer>(ipAddress, port);
        } else if (choice == 'c') {
            mySocket = std::make_unique<SocketClient>(ipAddress, port);
        }
		if (SIG_ERR == signal(SIGINT, signalHandler)) 
		{
			std::cerr << "Error setting up signal handler." << std::endl;
			return 1;
		}
        // 소켓 생성 및 설정
        mySocket->CreateSocket();

        mySocket->Setting();

        // 소켓 실행
        mySocket->SocketRunning();
    } 
    catch (const std::exception& e) {
        std::cerr << "실행 실패: " << e.what() << std::endl;
        return 1; // 비정상 종료
    }

    return 0;
}
