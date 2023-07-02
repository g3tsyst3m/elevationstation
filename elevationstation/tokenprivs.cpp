#pragma once
#include <Windows.h>
#include <iostream>
#include <conio.h>
#include "def.h"
void setThreadPrivs(LPCWSTR privname)
{
   
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE pToken;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        privname,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("[!] LookupPrivilegeValue error: %u\n", GetLastError());
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
        Color(14);
        printf("{!] AdjustTokenPrivileges error: %u\n", GetLastError());
        Color(7);
        exit(0);
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        Color(14);
        printf("[!] The thread token does not have this specified privilege available to the process. \n");
        Color(7);
        exit(0);
    }
    Color(2);
    printf("[+] Privilege: %ws added successfully to the thread!!!\n", privname);
    Color(7);
    CloseHandle(pToken);
   
}


void setProcessPrivs(LPCWSTR privname)
{
    
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE pToken;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        privname,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        Color(14);
        printf("[!] LookupPrivilegeValue error: %u\n", GetLastError());
        Color(7);
        exit(0);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &pToken))
        printf("[+] opened process token!\n");

    if (!AdjustTokenPrivileges(pToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        Color(14);
        printf("[!] AdjustTokenPrivileges error: %u\n", GetLastError());
        Color(7);
        exit(0);
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        Color(14);
        printf("[!] The token does not have this specified privilege available to the process. \n");
        Color(7);
        exit(0);
    }
    Color(2);
    printf("[+] Privilege: %ws added successfully!!!\n", privname);
    Color(7);
    CloseHandle(pToken);
    
}