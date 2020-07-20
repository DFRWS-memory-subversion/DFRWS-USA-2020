#include "windows.h"

typedef struct _HIDING_INFO
{
	int PID;
	DWORD64 VADtargetStartAddress;
	DWORD64 VADtargetEndAddress;
	DWORD64 PTEtargetStartAddress;
	DWORD64 PTEtargetEndAddress;
	DWORD64 VADPTEtargetStartAddress;
	DWORD64 VADPTEtargetEndAddress;
	DWORD64 cleanStartAddress;
	DWORD64 cleanEndAddress;

} HIDING_INFO, *PHIDING_INFO;
