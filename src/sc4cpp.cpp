#include "sc4cpp.h"



// *** Place function definition here! ***


SC_CODESEG_REORDERING SC_FORCEINLINE PPEB GetPEB_t() {
#ifdef _WIN64
	return (PPEB)__readgsqword(offsetof(TEB, ProcessEnvironmentBlock));
#else
	return (PPEB)__readfsdword(offsetof(TEB, ProcessEnvironmentBlock));
#endif  // _WIN64
}


SC_CODESEG_REORDERING SC_FORCEINLINE PLDR_DATA_TABLE_ENTRY GetDataTableEntry_t(PLIST_ENTRY lpList) {
	SIZE_T zuEntryOffset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	return (PLDR_DATA_TABLE_ENTRY)((LPBYTE)lpList - zuEntryOffset);
}


SC_CODESEG_REORDERING SC_FORCEINLINE PIMAGE_NT_HEADERS GetNTHeaders_t(PVOID lpDLLBase) {
	PIMAGE_DOS_HEADER lpDOSHeader = (PIMAGE_DOS_HEADER)lpDLLBase;
	return (PIMAGE_NT_HEADERS)((PBYTE)lpDLLBase + lpDOSHeader->e_lfanew);
}

template <typename Converter_t>
SC_CODESEG_REORDERING SC_FORCEINLINE SC_CONSTEXPR DWORD Hash_t(PCSTR lpName) {
	DWORD dwHash = 2166136261u;
	for (; *lpName != '\0'; ++lpName) {
		dwHash = (dwHash ^ (BYTE)Converter_t()(*lpName)) * 16777619ull;
	}
	return dwHash;
}

SC_CODESEG_REORDERING SC_FORCEINLINE SC_CONSTEXPR DWORD Hash_t(PCSTR lpName) {
	struct Converter_t {
		SC_CONSTEXPR Converter_t() {}
		SC_CONSTEXPR CHAR operator()(CHAR c) const { return c; }
	};
	return Hash_t<Converter_t>(lpName);
}

SC_CODESEG_REORDERING SC_FORCEINLINE SC_CONSTEXPR DWORD HashI_t(PCSTR lpName) {
	struct Converter_t {
		SC_CONSTEXPR Converter_t() {}
		SC_CONSTEXPR CHAR operator()(CHAR c) const {
			return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
		}
	};
	return Hash_t<Converter_t>(lpName);
}

SC_CODESEG_REORDERING SC_NOINLINE LPSTR GetModuleHandleByHash_t(DWORD dwDLLHash) {
	PLIST_ENTRY lpSentryNode = &GetPEB_t()->Ldr->InMemoryOrderModuleList;
	for (PLIST_ENTRY lpIterNode = lpSentryNode->Flink;
		lpIterNode != lpSentryNode;
		lpIterNode = lpIterNode->Flink) {
		PLDR_DATA_TABLE_ENTRY lpDLLEntry = GetDataTableEntry_t(lpIterNode);
		LPSTR lpDLLBase = (LPSTR)lpDLLEntry->DllBase;
		if (lpDLLBase == NULL) {
			continue;
		}
		PIMAGE_NT_HEADERS lpNTHeaders = GetNTHeaders_t(lpDLLBase);
		DWORD dwExportDirectoryRAV =
			lpNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (dwExportDirectoryRAV == 0) {
			continue;
		}
		PIMAGE_EXPORT_DIRECTORY lpExportDirectory =
			(PIMAGE_EXPORT_DIRECTORY)(lpDLLBase + dwExportDirectoryRAV);
		if (HashI_t(lpDLLBase + lpExportDirectory->Name) == dwDLLHash) {
			return (LPSTR)lpDLLBase;
		}
	}
	return nullptr;
}

SC_CODESEG_REORDERING SC_NOINLINE PVOID GetProcAddressByHashA_t(LPSTR lpDLLBase, DWORD dwProcHash) {
	PIMAGE_NT_HEADERS lpNTHeaders = GetNTHeaders_t(lpDLLBase);
	DWORD dwExportDirectoryRAV =
		lpNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (dwExportDirectoryRAV == 0) {
		return nullptr;
	}
	PIMAGE_EXPORT_DIRECTORY lpExportDirectory =
		(PIMAGE_EXPORT_DIRECTORY)(lpDLLBase + dwExportDirectoryRAV);
	PDWORD lpNameRAVs = (PDWORD)(lpDLLBase + lpExportDirectory->AddressOfNames);
	PWORD lpOrdinals = (PWORD)(lpDLLBase + lpExportDirectory->AddressOfNameOrdinals);
	PDWORD lpProcRAVs = (PDWORD)(lpDLLBase + lpExportDirectory->AddressOfFunctions);
	for (DWORD dwIdx = 0; dwIdx < lpExportDirectory->NumberOfNames; ++dwIdx) {
		if (Hash_t(lpDLLBase + lpNameRAVs[dwIdx]) == dwProcHash) {
			// FIXME: DLL Function Forwarding
			return lpDLLBase + lpProcRAVs[lpOrdinals[dwIdx]];
		}
	}
	return nullptr;
}




SC_CODESEG_REORDERING SC_NOINLINE DWORD WINAPI WorkerThread(PVOID lpAnsiMsg) {
	SC_IMPORT_API_BATCH_BEGIN();
	SC_IMPORT_API_BATCH("User32.dll", MessageBoxA);
	SC_IMPORT_API_BATCH("User32.dll", MessageBoxW);
	SC_IMPORT_API_BATCH_END();

	MessageBoxA(NULL, (PCSTR)lpAnsiMsg, SC_PISTRINGA("Hello!"), MB_OK);
	MessageBoxW(NULL, SC_PISTRINGW(L"Hello Unicode!"), SC_PISTRINGW(L"Hello!"), MB_OK);

	return 0;
}

typedef int(__cdecl* __stdio_common_vsprintf_t)(
	char* _Buffer,
	_In_z_ _Printf_format_string_params_(2) char const* _Format,
	va_list          _ArgList
	);

int SC_CODESEG_REORDERING SC_NOINLINE _Sprintf(char* buff, const char* szFormat, ...)
{
	auto ntdll = GetModuleHandleByHash_t(HashI_t("ntdll.dll"));
	auto vsprintf = (__stdio_common_vsprintf_t)GetProcAddressByHashA_t(ntdll, Hash_t("vsprintf"));

	va_list pArgs;

	va_start(pArgs, szFormat);
	int iReturn = vsprintf(buff, szFormat, pArgs);
	va_end(pArgs);

	return iReturn;
}

// clang-format off
SC_MAIN_BEGIN()
{
	// clang-format on
	SC_IMPORT_API_BATCH_BEGIN();
	SC_IMPORT_API_BATCH("User32.dll", MessageBoxA);
	SC_IMPORT_API_BATCH("kernel32.dll", GetCurrentProcessId);
	SC_IMPORT_API_BATCH_END();

	//// *** Place code here! ***
	char buff[0x200];

	_Sprintf(buff, SC_PISTRINGA("Hello x64 Shellcode!\r\nPid: %d"), GetCurrentProcessId());

	MessageBoxA(NULL, buff, SC_PISTRINGA("->"), MB_OK);

	// clang-format off
}
SC_MAIN_END()
// clang-format on
