#include "ntddk.h"

//
// The following value is arbitrarily chosen from the space defined by Microsoft
// as being "for non-Microsoft use"
//
#define FILE_DEVICE_NOTHING 0xCF53

//
// Device control codes - values between 2048 and 4095 arbitrarily chosen
//
#define IOCTL_NOTHING CTL_CODE(FILE_DEVICE_NOTHING, 2049, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Windows kernel structs
// VAD structs derived from the Blackbone project by Darthton (https://github.com/DarthTon/Blackbone/tree/master/src/BlackBoneDrv)
//
#pragma warning(disable : 4214 4201)
typedef struct _MM_AVL_NODE // Size=24
{
     struct _MM_AVL_NODE* LeftChild; // Size=8 Offset=0
     struct _MM_AVL_NODE* RightChild; // Size=8 Offset=8
     union ___unnamed1666 // Size=8
     {
         struct
         {
             __int64 Balance : 2; // Size=8 Offset=0 BitOffset=0 BitCount=2
         };
         struct _MM_AVL_NODE* Parent; // Size=8 Offset=0
     } u1;
} MM_AVL_NODE, * PMM_AVL_NODE, * PMMADDRESS_NODE;

union _EX_PUSH_LOCK // Size=8
{
    struct
    {
        unsigned __int64 Locked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
        unsigned __int64 Waiting : 1; // Size=8 Offset=0 BitOffset=1 BitCount=1
        unsigned __int64 Waking : 1; // Size=8 Offset=0 BitOffset=2 BitCount=1
        unsigned __int64 MultipleShared : 1; // Size=8 Offset=0 BitOffset=3 BitCount=1
        unsigned __int64 Shared : 60; // Size=8 Offset=0 BitOffset=4 BitCount=60
    };
	unsigned __int64 Value; // Size=8 Offset=0
    void* Ptr; // Size=8 Offset=0
};

struct _MI_VAD_SEQUENTIAL_INFO // Size=8
{
    unsigned __int64 Length : 12; // Size=8 Offset=0 BitOffset=0 BitCount=12
    unsigned __int64 Vpn : 52; // Size=8 Offset=0 BitOffset=12 BitCount=52
};

struct _MMVAD_FLAGS // Size=4
{
    unsigned long VadType : 3; // Size=4 Offset=0 BitOffset=0 BitCount=3
    unsigned long Protection : 5; // Size=4 Offset=0 BitOffset=3 BitCount=5
    unsigned long PreferredNode : 6; // Size=4 Offset=0 BitOffset=8 BitCount=6
    unsigned long NoChange : 1; // Size=4 Offset=0 BitOffset=14 BitCount=1
    unsigned long PrivateMemory : 1; // Size=4 Offset=0 BitOffset=15 BitCount=1
    unsigned long Teb : 1; // Size=4 Offset=0 BitOffset=16 BitCount=1
    unsigned long PrivateFixup : 1; // Size=4 Offset=0 BitOffset=17 BitCount=1
    unsigned long Spare : 13; // Size=4 Offset=0 BitOffset=18 BitCount=13
    unsigned long DeleteInProgress : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
};
struct _MMVAD_FLAGS1 // Size=4
{
    unsigned long CommitCharge : 31; // Size=4 Offset=0 BitOffset=0 BitCount=31
    unsigned long MemCommit : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
};

struct _MMVAD_FLAGS2 // Size=4
{
    unsigned long FileOffset : 24; // Size=4 Offset=0 BitOffset=0 BitCount=24
    unsigned long Large : 1; // Size=4 Offset=0 BitOffset=24 BitCount=1
    unsigned long TrimBehind : 1; // Size=4 Offset=0 BitOffset=25 BitCount=1
    unsigned long Inherit : 1; // Size=4 Offset=0 BitOffset=26 BitCount=1
    unsigned long CopyOnWrite : 1; // Size=4 Offset=0 BitOffset=27 BitCount=1
    unsigned long NoValidationNeeded : 1; // Size=4 Offset=0 BitOffset=28 BitCount=1
    unsigned long Spare : 3; // Size=4 Offset=0 BitOffset=29 BitCount=3
};

union _u // Size=4
{
    unsigned long LongFlags; // Size=4 Offset=0
    struct _MMVAD_FLAGS VadFlags; // Size=4 Offset=0
};
union _u1 // Size=4
{
    unsigned long LongFlags1; // Size=4 Offset=0
    struct _MMVAD_FLAGS1 VadFlags1; // Size=4 Offset=0
};
union _u2 // Size=4
{
    unsigned long LongFlags2; // Size=4 Offset=0
    struct _MMVAD_FLAGS2 VadFlags2; // Size=4 Offset=0
};
union _u4 // Size=8
{
    struct _MI_VAD_SEQUENTIAL_INFO SequentialVa; // Size=8 Offset=0
    struct _MMEXTEND_INFO* ExtendedInfo; // Size=8 Offset=0
};

typedef struct _MMVAD_SHORT // Size=64
{
    union
    {
        struct _MM_AVL_NODE VadNode; // Size=24 Offset=0
        struct _MMVAD_SHORT* NextVad; // Size=8 Offset=0
    };
	unsigned long StartingVpn; // Size=4 Offset=24
	unsigned long EndingVpn; // Size=4 Offset=28
    unsigned char StartingVpnHigh; // Size=1 Offset=32
    unsigned char EndingVpnHigh; // Size=1 Offset=33
    unsigned char CommitChargeHigh; // Size=1 Offset=34
    unsigned char LargeImageBias; // Size=1 Offset=35
    long ReferenceCount; // Size=4 Offset=36
    union _EX_PUSH_LOCK PushLock; // Size=8 Offset=40
    union _u u; // Size=4 Offset=48
    union _u1 u1; // Size=4 Offset=52
    struct _MI_VAD_EVENT_BLOCK* EventList; // Size=8 Offset=56
} MMVAD_SHORT, * PMMVAD_SHORT;

typedef struct _MMVAD // Size=128
{
    struct _MMVAD_SHORT Core; // Size=64 Offset=0
    union _u2 u2; // Size=4 Offset=64
    struct _SUBSECTION* Subsection; // Size=8 Offset=72
    struct _MMPTE* FirstPrototypePte; // Size=8 Offset=80
    struct _MMPTE* LastContiguousPte; // Size=8 Offset=88
    struct _LIST_ENTRY ViewLinks; // Size=16 Offset=96
    struct _EPROCESS* VadsProcess; // Size=8 Offset=112
    union _u4 u4; // Size=8 Offset=120
} MMVAD, * PMMVAD;

typedef struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;
	ULONGLONG Writable : 1;
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1;
	ULONGLONG Prototype : 1;
	ULONGLONG WriteSoftware : 1;
	ULONGLONG PageFrameNumber : 36;
	ULONGLONG ReservedHardware : 4;
	ULONGLONG ReservedSoftware : 4;
	ULONGLONG WsleAge : 4;
	ULONGLONG WsleProtection : 3;
	ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE, * PMMPTE_HARDWARE;

typedef struct _MMPTE
{
	union
	{
		ULONG_PTR Long;
		MMPTE_HARDWARE Hard;
	} u;
} MMPTE;
typedef MMPTE* PMMPTE;

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

} HIDING_INFO, * PHIDING_INFO;


