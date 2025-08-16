/*++
Copyright (C) Microsoft Corporation, 1991 - 1999

Module Name:

	diskperf.c

Abstract:

	This driver monitors disk accesses capturing performance data.

Environment:

	kernel mode only

Notes:

--*/


#define INITGUID

#include <ntifs.h>
#include <ntdddisk.h>
#include <stdarg.h>
#include <stdio.h>
#include <ntddvol.h>

#include <mountdev.h>
#include "wmistr.h"
#include "wmidata.h"
#include "wmiguid.h"
#include "wmilib.h"

#include "diskfltlib.h"
#include "ThawSpace.h"
#include "DirectDisk.h"

#ifdef POOL_TAGGING
#ifdef ExAllocatePool
#undef ExAllocatePool
#endif
#define ExAllocatePool(a,b) ExAllocatePoolWithTag(a,b,'frPD')
#endif

#define DISKPERF_MAXSTR         64

//
// Device Extension
//

typedef struct _DEVICE_EXTENSION {

	//
	// Back pointer to device object
	//

	PDEVICE_OBJECT DeviceObject;

	//
	// Target Device Object
	//

	PDEVICE_OBJECT TargetDeviceObject;

	//
	// Physical device object
	//
	PDEVICE_OBJECT PhysicalDeviceObject;

	//
	// Use to keep track of Volume info from ntddvol.h
	//

	WCHAR StorageManagerName[8];

	//
	// must synchronize paging path notifications
	//
	KEVENT PagingPathCountEvent;
	ULONG  PagingPathCount;

	//
	// Physical Device name or WMI Instance Name
	//

	UNICODE_STRING PhysicalDeviceName;
	WCHAR PhysicalDeviceNameBuffer[DISKPERF_MAXSTR];

	//
	// Storage device number of the partition, add by tanwen.
	//
	STORAGE_DEVICE_NUMBER StorageNumber;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

#define DEVICE_EXTENSION_SIZE sizeof(DEVICE_EXTENSION)



//
// Function declarations
//

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
);

NTSTATUS
DiskPerfForwardIrpSynchronous(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfAddDevice(
	IN PDRIVER_OBJECT DriverObject,
	IN PDEVICE_OBJECT PhysicalDeviceObject
);


NTSTATUS
DiskPerfDispatchPnp(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfDispatchPower(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfStartDevice(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfRemoveDevice(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfSendToNextDriver(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);


NTSTATUS
DiskPerfCreate(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfReadWrite(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfDeviceControl(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

NTSTATUS
DiskPerfShutdownFlush(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
);

VOID
DiskPerfUnload(
	IN PDRIVER_OBJECT DriverObject
);

VOID
DiskPerfLogError(
	IN PDEVICE_OBJECT DeviceObject,
	IN ULONG UniqueId,
	IN NTSTATUS ErrorCode,
	IN NTSTATUS Status
);

NTSTATUS
DiskPerfRegisterDevice(
	IN PDEVICE_OBJECT DeviceObject
);

NTSTATUS
DiskPerfIrpCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
);

VOID
DiskPerfSyncFilterWithTarget(
	IN PDEVICE_OBJECT FilterDevice,
	IN PDEVICE_OBJECT TargetDevice
);

#if DBG

ULONG DiskPerfDebug = 0;

VOID
DiskPerfDebugPrint(
	ULONG DebugPrintLevel,
	PCCHAR DebugMessage,
	...
);

#define DebugPrint(x)   DiskPerfDebugPrint x

#else

#define DebugPrint(x)

#endif

//
// Define the sections that allow for discarding (i.e. paging) some of
// the code.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, DiskPerfCreate)
#pragma alloc_text (PAGE, DiskPerfAddDevice)
#pragma alloc_text (PAGE, DiskPerfDispatchPnp)
#pragma alloc_text (PAGE, DiskPerfStartDevice)
#pragma alloc_text (PAGE, DiskPerfRemoveDevice)
#pragma alloc_text (PAGE, DiskPerfUnload)
#pragma alloc_text (PAGE, DiskPerfRegisterDevice)
#pragma alloc_text (PAGE, DiskPerfSyncFilterWithTarget)
#endif

// add by tanwen
PDEVICE_OBJECT g_cdo = NULL;

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT DriverObject,
	IN PUNICODE_STRING RegistryPath
)

/*++

Routine Description:

	Installable driver initialization entry point.
	This entry point is called directly by the I/O manager to set up the disk
	performance driver. The driver object is set up and then the Pnp manager
	calls DiskPerfAddDevice to attach to the boot devices.

Arguments:

	DriverObject - The disk performance driver object.

	RegistryPath - pointer to a unicode string representing the path,
				   to driver-specific key in the registry.

Return Value:

	STATUS_SUCCESS if successful

--*/

{

	ULONG               ulIndex;
	PDRIVER_DISPATCH  * dispatch;

	//
	// Create dispatch points
	//
	for (ulIndex = 0, dispatch = DriverObject->MajorFunction;
		ulIndex <= IRP_MJ_MAXIMUM_FUNCTION;
		ulIndex++, dispatch++) {

		*dispatch = DiskPerfSendToNextDriver;
	}

	//
	// Set up the device driver entry points.
	//


	DriverObject->MajorFunction[IRP_MJ_CREATE] = DiskPerfCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DiskPerfClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = DiskPerfReadWrite;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = DiskPerfReadWrite;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DiskPerfDeviceControl;

	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = DiskPerfShutdownFlush;
	DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = DiskPerfShutdownFlush;
	DriverObject->MajorFunction[IRP_MJ_PNP] = DiskPerfDispatchPnp;
	DriverObject->MajorFunction[IRP_MJ_POWER] = DiskPerfDispatchPower;

	DriverObject->DriverExtension->AddDevice = DiskPerfAddDevice;
	//DriverObject->DriverUnload = DiskPerfUnload;

	g_cdo = OnDiskFilterInitialization(
		DriverObject, RegistryPath);

	return(STATUS_SUCCESS);

} // end DriverEntry()

#define FILTER_DEVICE_PROPOGATE_FLAGS            0
#define FILTER_DEVICE_PROPOGATE_CHARACTERISTICS (FILE_REMOVABLE_MEDIA |  \
                                                 FILE_READ_ONLY_DEVICE | \
                                                 FILE_FLOPPY_DISKETTE    \
                                                 )

VOID
DiskPerfSyncFilterWithTarget(
	IN PDEVICE_OBJECT FilterDeviceObject,
	IN PDEVICE_OBJECT TargetDeviceObject
)
{
	ULONG                   propFlags;

	PAGED_CODE();

	//
	// Propogate all useful flags from target to diskperf. MountMgr will look
	// at the diskperf object capabilities to figure out if the disk is
	// a removable and perhaps other things.
	//
	propFlags = TargetDeviceObject->Flags & FILTER_DEVICE_PROPOGATE_FLAGS;
	FilterDeviceObject->Flags |= propFlags;

	propFlags = TargetDeviceObject->Characteristics & FILTER_DEVICE_PROPOGATE_CHARACTERISTICS;
	FilterDeviceObject->Characteristics |= propFlags;


}

NTSTATUS
DiskPerfAddDevice(
	IN PDRIVER_OBJECT DriverObject,
	IN PDEVICE_OBJECT PhysicalDeviceObject
)
/*++
Routine Description:

	Creates and initializes a new filter device object FiDO for the
	corresponding PDO.  Then it attaches the device object to the device
	stack of the drivers for the device.

Arguments:

	DriverObject - Disk performance driver object.
	PhysicalDeviceObject - Physical Device Object from the underlying layered driver

Return Value:

	NTSTATUS
--*/

{
	NTSTATUS                status;
	PDEVICE_OBJECT          filterDeviceObject;
	PDEVICE_EXTENSION       deviceExtension;

	PAGED_CODE();

	//
	// Create a filter device object for this device (partition).
	//

	DebugPrint((2, "DiskPerfAddDevice: Driver %X Device %X\n",
		DriverObject, PhysicalDeviceObject));

	//建立一个过滤设备，这个设备是FILE_DEVICE_DISK类型的设备并且具有DEVICE_EXTENSION类型的设备扩展
	status = IoCreateDevice(DriverObject,
		DEVICE_EXTENSION_SIZE,
		NULL,
		FILE_DEVICE_DISK,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&filterDeviceObject);

	if (!NT_SUCCESS(status)) {
		DebugPrint((1, "DiskPerfAddDevice: Cannot create filterDeviceObject\n"));
		return status;
	}

	filterDeviceObject->Flags |= DO_DIRECT_IO;

	deviceExtension = (PDEVICE_EXTENSION)filterDeviceObject->DeviceExtension;

	RtlZeroMemory(deviceExtension, DEVICE_EXTENSION_SIZE);

	//
	// Attaches the device object to the highest device object in the chain and
	// return the previously highest device object, which is passed to
	// IoCallDriver when pass IRPs down the device stack
	//

	deviceExtension->PhysicalDeviceObject = PhysicalDeviceObject;

	//将刚刚建立的过滤设备附加到这个卷设备的物理设备上
	deviceExtension->TargetDeviceObject =
		IoAttachDeviceToDeviceStack(filterDeviceObject, PhysicalDeviceObject);

	if (deviceExtension->TargetDeviceObject == NULL) {
		IoDeleteDevice(filterDeviceObject);
		DebugPrint((1, "DiskPerfAddDevice: Unable to attach %X to target %X\n",
			filterDeviceObject, PhysicalDeviceObject));
		return STATUS_NO_SUCH_DEVICE;
	}

	//
	// Save the filter device object in the device extension
	//
	deviceExtension->DeviceObject = filterDeviceObject;

	deviceExtension->PhysicalDeviceName.Buffer
		= deviceExtension->PhysicalDeviceNameBuffer;

	KeInitializeEvent(&deviceExtension->PagingPathCountEvent,
		NotificationEvent, TRUE);


	//
	// default to DO_POWER_PAGABLE
	//

	filterDeviceObject->Flags |= DO_POWER_PAGABLE;

	//
	// Clear the DO_DEVICE_INITIALIZING flag
	//

	filterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;

} // end DiskPerfAddDevice()


NTSTATUS
DiskPerfDispatchPnp(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
/*++

Routine Description:

	Dispatch for PNP

Arguments:

	DeviceObject    - Supplies the device object.

	Irp             - Supplies the I/O request packet.

Return Value:

	NTSTATUS

--*/

{
	PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS            status;
	PDEVICE_EXTENSION   deviceExtension;

	PAGED_CODE();

	if (PreCheckRemovedDirectDisk(DeviceObject, Irp, STATUS_INVALID_DEVICE_REQUEST))
		return STATUS_INVALID_DEVICE_REQUEST;

	if (IsThawSpaceDevice(DeviceObject) || IsDirectDiskDevice(DeviceObject))
	{
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	DebugPrint((2, "DiskPerfDispatchPnp: Device %X Irp %X\n",
		DeviceObject, Irp));

	switch (irpSp->MinorFunction) {

	case IRP_MN_START_DEVICE:
		//
		// Call the Start Routine handler to schedule a completion routine
		//
		DebugPrint((3,
			"DiskPerfDispatchPnp: Schedule completion for START_DEVICE"));
		status = DiskPerfStartDevice(DeviceObject, Irp);
		break;

	case IRP_MN_REMOVE_DEVICE:
	{
		//
		// Call the Remove Routine handler to schedule a completion routine
		//
		DebugPrint((3,
			"DiskPerfDispatchPnp: Schedule completion for REMOVE_DEVICE"));
		status = DiskPerfRemoveDevice(DeviceObject, Irp);
		break;
	}
	case IRP_MN_DEVICE_USAGE_NOTIFICATION:
	{
		PIO_STACK_LOCATION irpStack;
		BOOLEAN setPagable;

		DebugPrint((3, "DiskPerfDispatchPnp: Processing DEVICE_USAGE_NOTIFICATION"));
		irpStack = IoGetCurrentIrpStackLocation(Irp);

		if (irpStack->Parameters.UsageNotification.Type != DeviceUsageTypePaging) {
			status = DiskPerfSendToNextDriver(DeviceObject, Irp);
			break; // out of case statement
		}

		deviceExtension = DeviceObject->DeviceExtension;

		//
		// wait on the paging path event
		//

		status = KeWaitForSingleObject(&deviceExtension->PagingPathCountEvent,
			Executive, KernelMode,
			FALSE, NULL);

		//
		// if removing last paging device, need to set DO_POWER_PAGABLE
		// bit here, and possible re-set it below on failure.
		//

		setPagable = FALSE;
		if (!irpStack->Parameters.UsageNotification.InPath &&
			deviceExtension->PagingPathCount == 1) {

			//
			// removing the last paging file
			// must have DO_POWER_PAGABLE bits set
			//

			if (DeviceObject->Flags & DO_POWER_INRUSH) {
				DebugPrint((3, "DiskPerfDispatchPnp: last paging file "
					"removed but DO_POWER_INRUSH set, so not "
					"setting PAGABLE bit "
					"for DO %p\n", DeviceObject));
			}
			else {
				DebugPrint((2, "DiskPerfDispatchPnp: Setting  PAGABLE "
					"bit for DO %p\n", DeviceObject));
				DeviceObject->Flags |= DO_POWER_PAGABLE;
				setPagable = TRUE;
			}

		}

		//
		// send the irp synchronously
		//

		status = DiskPerfForwardIrpSynchronous(DeviceObject, Irp);

		//
		// now deal with the failure and success cases.
		// note that we are not allowed to fail the irp
		// once it is sent to the lower drivers.
		//

		if (NT_SUCCESS(status)) {

			IoAdjustPagingPathCount(
				(PLONG)&deviceExtension->PagingPathCount,
				irpStack->Parameters.UsageNotification.InPath);

			if (irpStack->Parameters.UsageNotification.InPath) {
				if (deviceExtension->PagingPathCount == 1) {

					//
					// first paging file addition
					//

					DebugPrint((3, "DiskPerfDispatchPnp: Clearing PAGABLE bit "
						"for DO %p\n", DeviceObject));
					DeviceObject->Flags &= ~DO_POWER_PAGABLE;
				}
			}

		}
		else {

			//
			// cleanup the changes done above
			//

			if (setPagable == TRUE) {
				DeviceObject->Flags &= ~DO_POWER_PAGABLE;
				setPagable = FALSE;
			}

		}

		//
		// set the event so the next one can occur.
		//

		KeSetEvent(&deviceExtension->PagingPathCountEvent,
			IO_NO_INCREMENT, FALSE);

		//
		// and complete the irp
		//

		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
		break;

	}

	default:
		DebugPrint((3,
			"DiskPerfDispatchPnp: Forwarding irp"));
		//
		// Simply forward all other Irps
		//
		return DiskPerfSendToNextDriver(DeviceObject, Irp);

	}

	return status;

} // end DiskPerfDispatchPnp()


NTSTATUS
DiskPerfIrpCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
)

/*++

Routine Description:

	Forwarded IRP completion routine. Set an event and return
	STATUS_MORE_PROCESSING_REQUIRED. Irp forwarder will wait on this
	event and then re-complete the irp after cleaning up.

Arguments:

	DeviceObject is the device object of the WMI driver
	Irp is the WMI irp that was just completed
	Context is a PKEVENT that forwarder will wait on

Return Value:

	STATUS_MORE_PORCESSING_REQUIRED

--*/

{
	PKEVENT Event = (PKEVENT)Context;

	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

	return(STATUS_MORE_PROCESSING_REQUIRED);

} // end DiskPerfIrpCompletion()


NTSTATUS
DiskPerfStartDevice(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
/*++

Routine Description:

	This routine is called when a Pnp Start Irp is received.
	It will schedule a completion routine to initialize and register with WMI.

Arguments:

	DeviceObject - a pointer to the device object

	Irp - a pointer to the irp


Return Value:

	Status of processing the Start Irp

--*/
{
	PDEVICE_EXTENSION   deviceExtension;
	NTSTATUS            status;

	PAGED_CODE();

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	status = DiskPerfForwardIrpSynchronous(DeviceObject, Irp);

	DiskPerfSyncFilterWithTarget(DeviceObject,
		deviceExtension->TargetDeviceObject);

	//
	// Complete WMI registration
	//
	DiskPerfRegisterDevice(DeviceObject);

	//
	// Complete the Irp
	//
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}


NTSTATUS
DiskPerfRemoveDevice(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
/*++

Routine Description:

	This routine is called when the device is to be removed.
	It will de-register itself from WMI first, detach itself from the
	stack before deleting itself.

Arguments:

	DeviceObject - a pointer to the device object

	Irp - a pointer to the irp


Return Value:

	Status of removing the device

--*/
{
	NTSTATUS            status;
	PDEVICE_EXTENSION   deviceExtension;

	PAGED_CODE();

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	status = DiskPerfForwardIrpSynchronous(DeviceObject, Irp);

	IoDetachDevice(deviceExtension->TargetDeviceObject);
	IoDeleteDevice(DeviceObject);

	OnDiskFilterRemoveDisk(deviceExtension->TargetDeviceObject, &deviceExtension->PhysicalDeviceName);

	//
	// Complete the Irp
	//
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}


NTSTATUS
DiskPerfSendToNextDriver(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)

/*++

Routine Description:

	This routine sends the Irp to the next driver in line
	when the Irp is not processed by this driver.

Arguments:

	DeviceObject
	Irp

Return Value:

	NTSTATUS

--*/

{
	PDEVICE_EXTENSION   deviceExtension;
	NTSTATUS mystatus;
	// add by tanwen 
	if (DeviceObject == g_cdo && OnDiskFilterDispatchControl(DeviceObject, Irp, &mystatus))
		return mystatus;
	if (PreCheckRemovedDirectDisk(DeviceObject, Irp, STATUS_INVALID_DEVICE_REQUEST))
		return STATUS_INVALID_DEVICE_REQUEST;
	if (IsThawSpaceDevice(DeviceObject) || IsDirectDiskDevice(DeviceObject))
	{
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	IoSkipCurrentIrpStackLocation(Irp);
	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);

} // end DiskPerfSendToNextDriver()

NTSTATUS
DiskPerfDispatchPower(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	PDEVICE_EXTENSION deviceExtension;
	if (PreCheckRemovedDirectDisk(DeviceObject, Irp, STATUS_INVALID_DEVICE_REQUEST))
		return STATUS_INVALID_DEVICE_REQUEST;
	if (IsThawSpaceDevice(DeviceObject) || IsDirectDiskDevice(DeviceObject))
	{
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}

	PoStartNextPowerIrp(Irp);
	IoSkipCurrentIrpStackLocation(Irp);

	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	return PoCallDriver(deviceExtension->TargetDeviceObject, Irp);

} // end DiskPerfDispatchPower

NTSTATUS
DiskPerfForwardIrpSynchronous(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)

/*++

Routine Description:

	This routine sends the Irp to the next driver in line
	when the Irp needs to be processed by the lower drivers
	prior to being processed by this one.

Arguments:

	DeviceObject
	Irp

Return Value:

	NTSTATUS

--*/

{
	PDEVICE_EXTENSION   deviceExtension;
	KEVENT event;
	NTSTATUS status;

	KeInitializeEvent(&event, NotificationEvent, FALSE);
	deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	//
	// copy the irpstack for the next device
	//

	IoCopyCurrentIrpStackLocationToNext(Irp);

	//
	// set a completion routine
	//

	IoSetCompletionRoutine(Irp, DiskPerfIrpCompletion,
		&event, TRUE, TRUE, TRUE);

	//
	// call the next lower device
	//

	status = IoCallDriver(deviceExtension->TargetDeviceObject, Irp);

	//
	// wait for the actual completion
	//

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = Irp->IoStatus.Status;
	}

	return status;

} // end DiskPerfForwardIrpSynchronous()


NTSTATUS
DiskPerfCreate(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)

/*++

Routine Description:

	This routine services open commands. It establishes
	the driver's existance by returning status success.

Arguments:

	DeviceObject - Context for the activity.
	Irp          - The device control argument block.

Return Value:

	NT Status

--*/

{
	NTSTATUS mystatus;
	PAGED_CODE();

	// add by tanwen 
	if (DeviceObject == g_cdo && OnDiskFilterDispatchControl(DeviceObject, Irp, &mystatus))
		return mystatus;

	if (PreCheckRemovedDirectDisk(DeviceObject, Irp, STATUS_SUCCESS))
		return STATUS_SUCCESS;

	if (IsThawSpaceDevice(DeviceObject))
		return ThawSpaceCreateClose(DeviceObject, Irp);

	if (IsDirectDiskDevice(DeviceObject))
		return DirectDiskCreateClose(DeviceObject, Irp);

	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

} // end DiskPerfCreate()

NTSTATUS
DiskPerfClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)

{
	NTSTATUS mystatus;
	PAGED_CODE();

	// add by tanwen 
	if (DeviceObject == g_cdo && OnDiskFilterDispatchControl(DeviceObject, Irp, &mystatus))
		return mystatus;

	if (PreCheckRemovedDirectDisk(DeviceObject, Irp, STATUS_SUCCESS))
		return STATUS_SUCCESS;

	if (IsThawSpaceDevice(DeviceObject))
		return ThawSpaceCreateClose(DeviceObject, Irp);

	if (IsDirectDiskDevice(DeviceObject))
		return DirectDiskCreateClose(DeviceObject, Irp);

	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

} // end DiskPerfCreate()


NTSTATUS
DiskPerfReadWrite(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)

/*++

Routine Description:

	This is the driver entry point for read and write requests
	to disks to which the diskperf driver has attached.
	This driver collects statistics and then sets a completion
	routine so that it can collect additional information when
	the request completes. Then it calls the next driver below
	it.

Arguments:

	DeviceObject
	Irp

Return Value:

	NTSTATUS

--*/

{
	PDEVICE_EXTENSION  deviceExtension = DeviceObject->DeviceExtension;
	NTSTATUS mystatus;

	// add by tanwen 
	if (DeviceObject == g_cdo && OnDiskFilterDispatchControl(DeviceObject, Irp, &mystatus))
		return mystatus;

	if (PreCheckRemovedDirectDisk(DeviceObject, Irp, STATUS_NO_MEDIA_IN_DEVICE))
		return STATUS_NO_MEDIA_IN_DEVICE;

	if (IsThawSpaceDevice(DeviceObject))
		return ThawSpaceReadWrite(DeviceObject, Irp);

	if (IsDirectDiskDevice(DeviceObject))
		return DirectDiskReadWrite(DeviceObject, Irp);

	// add by tanwen
	if (OnDiskFilterReadWrite(
		&deviceExtension->PhysicalDeviceName,
		deviceExtension->StorageNumber.DeviceType,
		deviceExtension->StorageNumber.DeviceNumber,
		deviceExtension->StorageNumber.PartitionNumber,
		DeviceObject, Irp, &mystatus))
		return mystatus;

	return DiskPerfSendToNextDriver(DeviceObject, Irp);

} // end DiskPerfReadWrite()



NTSTATUS
DiskPerfDeviceControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)

/*++

Routine Description:

	This device control dispatcher handles only the disk performance
	device control. All others are passed down to the disk drivers.
	The disk performane device control returns a current snapshot of
	the performance data.

Arguments:

	DeviceObject - Context for the activity.
	Irp          - The device control argument block.

Return Value:

	Status is returned.

--*/

{
	PDEVICE_EXTENSION  deviceExtension = DeviceObject->DeviceExtension;

	// add by tanwen
	NTSTATUS mystatus;

	DebugPrint((2, "DiskPerfDeviceControl: DeviceObject %X Irp %X\n", DeviceObject, Irp));

	// add by tanwen 
	if (DeviceObject == g_cdo && OnDiskFilterDispatchControl(DeviceObject, Irp, &mystatus))
		return mystatus;

	if (PreCheckRemovedDirectDisk(DeviceObject, Irp, STATUS_NO_MEDIA_IN_DEVICE))
		return STATUS_NO_MEDIA_IN_DEVICE;

	if (IsThawSpaceDevice(DeviceObject))
		return ThawSpaceDeviceControl(DeviceObject, Irp);

	if (IsDirectDiskDevice(DeviceObject))
		return DirectDiskDeviceControl(DeviceObject, Irp);

	// add by tanwen
	if (OnDiskFilterDeviceControl(
		&deviceExtension->PhysicalDeviceName,
		deviceExtension->StorageNumber.DeviceType,
		deviceExtension->StorageNumber.DeviceNumber,
		deviceExtension->StorageNumber.PartitionNumber,
		DeviceObject, Irp, &mystatus))
		return mystatus;

	//
	// Set current stack back one.
	//

	Irp->CurrentLocation++,
		Irp->Tail.Overlay.CurrentStackLocation++;

	//
	// Pass unrecognized device control requests
	// down to next driver layer.
	//

	return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);
} // end DiskPerfDeviceControl()


NTSTATUS
DiskPerfShutdownFlush(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)

/*++

Routine Description:

	This routine is called for a shutdown and flush IRPs.  These are sent by the
	system before it actually shuts down or when the file system does a flush.

Arguments:

	DriverObject - Pointer to device object to being shutdown by system.
	Irp          - IRP involved.

Return Value:

	NT Status

--*/

{
	PDEVICE_EXTENSION  deviceExtension = DeviceObject->DeviceExtension;
	NTSTATUS mystatus;

	if (PreCheckRemovedDirectDisk(DeviceObject, Irp, STATUS_SUCCESS))
		return STATUS_SUCCESS;

	if (IsThawSpaceDevice(DeviceObject) || IsDirectDiskDevice(DeviceObject))
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	// add by tanwen 
	if (DeviceObject == g_cdo && OnDiskFilterDispatchShutdown(DeviceObject, Irp, &mystatus))
		return mystatus;

	//
	// Set current stack back one.
	//

	DebugPrint((2, "DiskPerfShutdownFlush: DeviceObject %X Irp %X\n",
		DeviceObject, Irp));
	Irp->CurrentLocation++,
		Irp->Tail.Overlay.CurrentStackLocation++;

	return IoCallDriver(deviceExtension->TargetDeviceObject, Irp);

} // end DiskPerfShutdownFlush()


VOID
DiskPerfUnload(
	IN PDRIVER_OBJECT DriverObject
)

/*++

Routine Description:

	Free all the allocated resources, etc.

Arguments:

	DriverObject - pointer to a driver object.

Return Value:

	VOID.

--*/
{
	PAGED_CODE();

	ThawSpaceUnload(DriverObject);

	DirectDiskUnload(DriverObject);

	OnDiskFilterUnload(DriverObject);

	return;
}


NTSTATUS
DiskPerfRegisterDevice(
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

	Routine to initialize a proper name for the device object, and
	register it with WMI

Arguments:

	DeviceObject - pointer to a device object to be initialized.

Return Value:

	Status of the initialization. NOTE: If the registration fails,
	the device name in the DeviceExtension will be left as empty.

--*/

{
	NTSTATUS                status;
	IO_STATUS_BLOCK         ioStatus;
	KEVENT                  event;
	PDEVICE_EXTENSION       deviceExtension;
	PIRP                    irp;
	STORAGE_DEVICE_NUMBER   number;

	PAGED_CODE();

	DebugPrint((2, "DiskPerfRegisterDevice: DeviceObject %X\n",
		DeviceObject));
	deviceExtension = DeviceObject->DeviceExtension;

	KeInitializeEvent(&event, NotificationEvent, FALSE);

	//
	// Request for the device number
	//
	irp = IoBuildDeviceIoControlRequest(
		IOCTL_STORAGE_GET_DEVICE_NUMBER,
		deviceExtension->TargetDeviceObject,
		NULL,
		0,
		&number,
		sizeof(number),
		FALSE,
		&event,
		&ioStatus);

	if (!irp) {
		DiskPerfLogError(
			DeviceObject,
			256,
			STATUS_SUCCESS,
			IO_ERR_INSUFFICIENT_RESOURCES);
		DebugPrint((3, "DiskPerfRegisterDevice: Fail to build irp\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = IoCallDriver(deviceExtension->TargetDeviceObject, irp);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = ioStatus.Status;
	}

	if (NT_SUCCESS(status)) {

		//
		// Remember the disk number for use as parameter in DiskIoNotifyRoutine
		//
		deviceExtension->StorageNumber = number;
		//
		// Create device name for each partition
		//

		swprintf(
			deviceExtension->PhysicalDeviceNameBuffer,
			L"\\Device\\Harddisk%d\\Partition%d",
			number.DeviceNumber, number.PartitionNumber);

		RtlInitUnicodeString(&deviceExtension->PhysicalDeviceName, &deviceExtension->PhysicalDeviceNameBuffer[0]);

		//
		// Set default name for physical disk
		//
		RtlCopyMemory(
			&(deviceExtension->StorageManagerName[0]),
			L"PhysDisk",
			8 * sizeof(WCHAR));
		DebugPrint((3, "DiskPerfRegisterDevice: Device name %ws\n",
			deviceExtension->PhysicalDeviceNameBuffer));

		OnDiskFilterNewDisk(
			deviceExtension->TargetDeviceObject,
			&deviceExtension->PhysicalDeviceName,
			number.DeviceType,
			number.DeviceNumber,
			number.PartitionNumber);

	}
	else {

		// request for partition's information failed, try volume

		ULONG           outputSize = sizeof(MOUNTDEV_NAME);
		PMOUNTDEV_NAME  output;
		VOLUME_NUMBER   volumeNumber;
		ULONG           nameSize;

		output = ExAllocatePool(PagedPool, outputSize);
		if (!output) {
			DiskPerfLogError(
				DeviceObject,
				257,
				STATUS_SUCCESS,
				IO_ERR_INSUFFICIENT_RESOURCES);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		KeInitializeEvent(&event, NotificationEvent, FALSE);
		irp = IoBuildDeviceIoControlRequest(
			IOCTL_MOUNTDEV_QUERY_DEVICE_NAME,
			deviceExtension->TargetDeviceObject, NULL, 0,
			output, outputSize, FALSE, &event, &ioStatus);
		if (!irp) {
			ExFreePool(output);
			DiskPerfLogError(
				DeviceObject,
				258,
				STATUS_SUCCESS,
				IO_ERR_INSUFFICIENT_RESOURCES);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = IoCallDriver(deviceExtension->TargetDeviceObject, irp);
		if (status == STATUS_PENDING) {
			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			status = ioStatus.Status;
		}

		if (status == STATUS_BUFFER_OVERFLOW) {
			outputSize = sizeof(MOUNTDEV_NAME) + output->NameLength;
			ExFreePool(output);
			output = ExAllocatePool(PagedPool, outputSize);

			if (!output) {
				DiskPerfLogError(
					DeviceObject,
					258,
					STATUS_SUCCESS,
					IO_ERR_INSUFFICIENT_RESOURCES);
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			KeInitializeEvent(&event, NotificationEvent, FALSE);
			irp = IoBuildDeviceIoControlRequest(
				IOCTL_MOUNTDEV_QUERY_DEVICE_NAME,
				deviceExtension->TargetDeviceObject, NULL, 0,
				output, outputSize, FALSE, &event, &ioStatus);
			if (!irp) {
				ExFreePool(output);
				DiskPerfLogError(
					DeviceObject, 259,
					STATUS_SUCCESS,
					IO_ERR_INSUFFICIENT_RESOURCES);
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			status = IoCallDriver(deviceExtension->TargetDeviceObject, irp);
			if (status == STATUS_PENDING) {
				KeWaitForSingleObject(
					&event,
					Executive,
					KernelMode,
					FALSE,
					NULL
				);
				status = ioStatus.Status;
			}
		}
		if (!NT_SUCCESS(status)) {
			ExFreePool(output);
			DiskPerfLogError(
				DeviceObject,
				260,
				STATUS_SUCCESS,
				IO_ERR_CONFIGURATION_ERROR);
			return status;
		}

		nameSize = min(output->NameLength, sizeof(deviceExtension->PhysicalDeviceNameBuffer) - sizeof(WCHAR));

		wcsncpy(deviceExtension->PhysicalDeviceNameBuffer, output->Name, nameSize / sizeof(WCHAR));

		RtlInitUnicodeString(&deviceExtension->PhysicalDeviceName, &deviceExtension->PhysicalDeviceNameBuffer[0]);

		ExFreePool(output);

		//
		// Now, get the VOLUME_NUMBER information
		//
		outputSize = sizeof(VOLUME_NUMBER);
		RtlZeroMemory(&volumeNumber, sizeof(VOLUME_NUMBER));

		KeInitializeEvent(&event, NotificationEvent, FALSE);
		irp = IoBuildDeviceIoControlRequest(
			IOCTL_VOLUME_QUERY_VOLUME_NUMBER,
			deviceExtension->TargetDeviceObject, NULL, 0,
			&volumeNumber,
			sizeof(VOLUME_NUMBER),
			FALSE, &event, &ioStatus);
		if (!irp) {
			DiskPerfLogError(
				DeviceObject,
				265,
				STATUS_SUCCESS,
				IO_ERR_INSUFFICIENT_RESOURCES);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		status = IoCallDriver(deviceExtension->TargetDeviceObject, irp);
		if (status == STATUS_PENDING) {
			KeWaitForSingleObject(&event, Executive,
				KernelMode, FALSE, NULL);
			status = ioStatus.Status;
		}
		if (!NT_SUCCESS(status) ||
			volumeNumber.VolumeManagerName[0] == (WCHAR)UNICODE_NULL) {

			RtlCopyMemory(
				&deviceExtension->StorageManagerName[0],
				L"LogiDisk",
				8 * sizeof(WCHAR));
		}
		else {
			RtlCopyMemory(
				&deviceExtension->StorageManagerName[0],
				&volumeNumber.VolumeManagerName[0],
				8 * sizeof(WCHAR));
		}
		DebugPrint((3, "DiskPerfRegisterDevice: Device name %ws\n",
			deviceExtension->PhysicalDeviceNameBuffer));
	}

	return status;
}


VOID
DiskPerfLogError(
	IN PDEVICE_OBJECT DeviceObject,
	IN ULONG UniqueId,
	IN NTSTATUS ErrorCode,
	IN NTSTATUS Status
)

/*++

Routine Description:

	Routine to log an error with the Error Logger

Arguments:

	DeviceObject - the device object responsible for the error
	UniqueId     - an id for the error
	Status       - the status of the error

Return Value:

	None

--*/

{
	PIO_ERROR_LOG_PACKET errorLogEntry;

	errorLogEntry = (PIO_ERROR_LOG_PACKET)
		IoAllocateErrorLogEntry(
			DeviceObject,
			sizeof(IO_ERROR_LOG_PACKET)//(UCHAR)(sizeof(IO_ERROR_LOG_PACKET) + sizeof(DEVICE_OBJECT))
		);

	if (errorLogEntry != NULL) {
		errorLogEntry->ErrorCode = ErrorCode;
		errorLogEntry->UniqueErrorValue = UniqueId;
		errorLogEntry->FinalStatus = Status;
		//
		// The following is necessary because DumpData is of type ULONG
		// and DeviceObject can be more than that
		//
		/*RtlCopyMemory(
			&errorLogEntry->DumpData[0],
			&DeviceObject,
			sizeof(DEVICE_OBJECT));
		errorLogEntry->DumpDataSize = sizeof(DEVICE_OBJECT);*/
		errorLogEntry->DumpDataSize = 0;
		IoWriteErrorLogEntry(errorLogEntry);
	}
}


#if DBG

VOID
DiskPerfDebugPrint(
	ULONG DebugPrintLevel,
	PCCHAR DebugMessage,
	...
)

/*++

Routine Description:

	Debug print for all DiskPerf

Arguments:

	Debug print level between 0 and 3, with 3 being the most verbose.

Return Value:

	None

--*/

{
	va_list ap;

	va_start(ap, DebugMessage);


	if ((DebugPrintLevel <= (DiskPerfDebug & 0x0000ffff)) ||
		((1 << (DebugPrintLevel + 15)) & DiskPerfDebug)) {

		DbgPrint(DebugMessage, ap);
	}

	va_end(ap);

}
#endif

