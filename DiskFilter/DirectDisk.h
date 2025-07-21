#pragma once

#include "Pch.h"
#include "DiskFilter.h"

EXTERN_C_START

NTSTATUS
DirectDiskInit(
	IN PDRIVER_OBJECT DriverObject
);

NTSTATUS
DirectDiskMount(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number,
	IN WCHAR            DriveLetter,
	IN PVOLUME_INFO     ProtectedVolume,
	IN BOOLEAN          ReadOnly
);

NTSTATUS
DirectDiskUnmount(
	IN PDEVICE_OBJECT   DeviceObject
);

VOID
DirectDiskUnload(
	IN PDRIVER_OBJECT DriverObject
);

NTSTATUS
DirectDiskCreateClose(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
DirectDiskReadWrite(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
DirectDiskDeviceControl(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

VOID
DirectDiskUnload(
	IN PDRIVER_OBJECT DriverObject
);

BOOLEAN
IsDirectDiskDevice(
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
PreCheckRemovedDirectDisk(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp,
	IN NTSTATUS			ReturnStatus
);

PDEVICE_OBJECT
FindDirectDiskDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number
);

PDEVICE_OBJECT
FindDirectDiskDeviceByPartition(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            DiskNumber,
	IN ULONG			PartitionNumber
);

NTSTATUS DirectDiskGetConfig(
	IN PDEVICE_OBJECT            DeviceObject,
	OUT PDISKFILTER_DIRECTDISK   Config
);

EXTERN_C_END
