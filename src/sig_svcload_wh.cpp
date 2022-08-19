#include "sc4.h"
#include <WinInet.h>



SC_MAIN_BEGIN()
{
	FUNC_BEGIN;
	GET_API_ADDRESS("wininet.dll", InternetOpenA);
	auto buff = InternetOpenA(0, 0, 0, 0, 0);
}
SC_MAIN_END()