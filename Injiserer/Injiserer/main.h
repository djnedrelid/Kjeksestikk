#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <deque>
#include <strsafe.h>
#include <thread>
#include <TlHelp32.h>
#include <algorithm>
#include <ctime>
#include <filesystem>

SYSTEM_INFO SysInfo;
HWND __HWNDCss;
HANDLE __HandleProcess;
PROCESSENTRY32W __GameProcess;

//
//	Generell feilhåndterer av exceptions o.l. i programmet.
//
void GetError(std::string lpszFunction)
{
	int err = GetLastError();
	std::string lpDisplayBuf;
	char* lpMsgBuf;

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&lpMsgBuf,
		0,
		NULL
	);

	lpDisplayBuf.append("(" + std::to_string(err) + ") ");
	lpDisplayBuf.append(lpMsgBuf);

	MessageBoxA(
		NULL,
		lpszFunction.c_str(),
		lpDisplayBuf.c_str(),
		MB_OK | MB_ICONINFORMATION
	);
}

//
//	Generell feilhåndterer av exceptions o.l. i programmet.
//
void GetErrorW(std::wstring lpszFunction)
{
	int err = GetLastError();
	std::wstring lpDisplayBuf;
	wchar_t* lpMsgBuf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&lpMsgBuf,
		0,
		NULL);

	lpDisplayBuf.append(L"(" + std::to_wstring(err) + L") ");
	lpDisplayBuf.append(lpMsgBuf);

	std::wstring TotalMessage;
	TotalMessage.append(lpszFunction + L"\n\nSystem:\n" + lpDisplayBuf);

	MessageBoxW(
		NULL,
		(LPCWSTR)TotalMessage.c_str(),
		L"Information",
		MB_OK | MB_ICONINFORMATION
	);
}

void Log(const wchar_t* s, bool NewLine)
{
	std::wofstream f;
	
	f.open("Injiserer.log", std::fstream::app);
	
	f << s;
	if (NewLine)
		f << std::endl;

	f.close();
}

//
//	Funksjon for å hente PID til målprosess.
//
bool FindProcessName(
	const wchar_t *__ProcessName,
	PROCESSENTRY32W *pEntry
) {
	PROCESSENTRY32W __ProcessEntry = { 0 };
	__ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(
		TH32CS_SNAPPROCESS,
		0
	);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;

	if (!Process32FirstW(hSnapshot, &__ProcessEntry)) {
		CloseHandle(hSnapshot);
		return false;
	}

	// wchar_t logstr[100];
	do {
		if (!_wcsicmp(__ProcessEntry.szExeFile, __ProcessName))
		{
			memcpy(
				(void *)pEntry,
				(void *)&__ProcessEntry,
				sizeof(PROCESSENTRY32W)
			);
			CloseHandle(hSnapshot);
			
			/*
			memset(&logstr[0],0,sizeof(logstr));
			wcscpy(logstr, __ProcessEntry.szExeFile);
			wcscat(logstr, L" == ");
			wcscat(logstr, __ProcessName);
			Log(logstr, true);
			*/

			return true;
		}

	} while (Process32NextW(hSnapshot, &__ProcessEntry));

	CloseHandle(hSnapshot);
	return false;
}

//
//	Funksjon for debug-privilegier for oss selv. 
//	Gir optimale tilgangsrettigheter mot målprosess.
//
void runSetDebugPrivs()
{
	HANDLE __HandleProcess = GetCurrentProcess(), __HandleToken;
	TOKEN_PRIVILEGES priv;
	LUID __LUID;

	OpenProcessToken(
		__HandleProcess,
		TOKEN_ADJUST_PRIVILEGES,
		&__HandleToken
	);

	LookupPrivilegeValueA(0, "SeDebugPrivilege", &__LUID);
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = __LUID;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(__HandleToken, false, &priv, 0, 0, 0);

	CloseHandle(__HandleToken);
	CloseHandle(__HandleProcess);
}

bool PrepProcess(const wchar_t* TheProcess)
{
	try {

	//
	//	Funksjon for klargjøring av prosess og tilhørende moduler.
	//	Kjøres en enkelt gang under oppstart og kaster evt. et unntak 
	//	for videre feilhåndtering og avslutting av programmet.
	// 
	runSetDebugPrivs();

	// Prosessinfo.
	if(!FindProcessName(
		TheProcess,
		&__GameProcess
	)) 
		throw 1;

	// HANDLE til hovedprosess.
	if((__HandleProcess = OpenProcess(
		PROCESS_VM_READ |
		PROCESS_VM_WRITE |
		PROCESS_VM_OPERATION |
		PROCESS_QUERY_INFORMATION,
		false,
		__GameProcess.th32ProcessID
	)) == 0)
		throw 1;

	return true;

	} catch (...) {
		GetError("Sjekk at prosessen faktisk kjører...");
		MessageBoxW(
			NULL,
			TheProcess,
			L"",
			MB_OK | MB_ICONINFORMATION
		);
		return false;
	}
}

// Hjelpefunksjon for å se om DLL allerede er lastet inn.
bool FindDLLModule(
	const wchar_t* LPSTRModuleName,
	DWORD __DwordProcessId
) {
	MODULEENTRY32W lpModuleEntry;
	lpModuleEntry.dwSize = sizeof(MODULEENTRY32W);
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, __DwordProcessId);

	if(hSnapShot == INVALID_HANDLE_VALUE)
		return false;

	if (!Module32FirstW(hSnapShot, &lpModuleEntry)) {
		CloseHandle(hSnapShot);
		return false;
	}

	do {
		if (!_wcsicmp(lpModuleEntry.szModule, LPSTRModuleName)) {
			CloseHandle(hSnapShot);
			return true;
		}
	} while (Module32NextW(hSnapShot, &lpModuleEntry));
		
	CloseHandle(hSnapShot);
	return false;
}

extern "C" __declspec(dllexport) bool Injiser(const wchar_t* FullDllPath, const wchar_t* ProcessName)
{
	if (!PrepProcess(ProcessName))
		return false;

	// Se om DLL allerede er lastet.
	std::filesystem::path _FullDllPath = FullDllPath;
	if(FindDLLModule(_FullDllPath.filename().wstring().c_str(), __GameProcess.th32ProcessID)) {
		std::wstring beskjed = _FullDllPath.filename().wstring().c_str();
		beskjed.append(L" er allerede lastet inn i prosessen.");
		GetErrorW(beskjed);
		return false;
	}

	// Allocate memory for the file path inside of the target process.
	SIZE_T AllocSize = (wcslen(FullDllPath)+1) * sizeof(wchar_t);
	uintptr_t pAllocFilePathAddr = (uintptr_t)VirtualAllocEx(
		__HandleProcess, 0, AllocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
	); 
	
	// If allocation failed.
	if (pAllocFilePathAddr == 0) {
		GetError("VirtualAllocEx feilet.");
		return false;
	}

	// Write the file path into memory.
	if (WriteProcessMemory(__HandleProcess, (void*)pAllocFilePathAddr, FullDllPath, AllocSize, 0) == 0) {
		GetError("WriteProcessMemory feilet.");
		VirtualFreeEx(__HandleProcess, (void*)pAllocFilePathAddr, AllocSize, MEM_RELEASE);
		return false;
	}

	// Create a thread on the load library function address, 
	// and use the file path that we allocated as parameter.
	HANDLE hThread = CreateRemoteThread(__HandleProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, (void*)pAllocFilePathAddr, 0, nullptr); 	
	if (hThread == nullptr) {
		GetError("CreateRemoteThread feilet.");
		VirtualFreeEx(__HandleProcess, (void*)pAllocFilePathAddr, AllocSize, MEM_RELEASE);
		return false;
	}

	// Wait for the thread to terminate.
	DWORD dwExitCode = 0;
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &dwExitCode);

	if (dwExitCode == 0) {
		GetError("Injeksjon feilet, LoadLibraryA returnerte 0.");
		CloseHandle(hThread);
		VirtualFreeEx(__HandleProcess, (void*)pAllocFilePathAddr, AllocSize, MEM_RELEASE);
		return false;
	}

	// Clean up to avoid memory leak.
	VirtualFreeEx(__HandleProcess, (void*)pAllocFilePathAddr, AllocSize, MEM_RELEASE);
	CloseHandle(hThread);

	// Operations successful. 
	// Assume we injected OK.
	return true;
}