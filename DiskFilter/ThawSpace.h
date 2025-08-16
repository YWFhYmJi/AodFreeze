#pragma once

#include "Pch.h"

EXTERN_C_START

typedef struct _OPEN_FILE_INFORMATION {
	LARGE_INTEGER       FileSize;
	BOOLEAN             ReadOnly;
	WCHAR               DriveLetter;
	USHORT              FileNameLength;
	WCHAR               FileName[1];
} OPEN_FILE_INFORMATION, *POPEN_FILE_INFORMATION;

NTSTATUS
ThawSpaceInit(
	IN PDRIVER_OBJECT DriverObject,
	IN ULONG NumberOfDevices
);

NTSTATUS
ThawSpaceCreateDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number
);

VOID
ThawSpaceUnload(
	IN PDRIVER_OBJECT DriverObject
);

NTSTATUS
ThawSpaceCreateClose(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
ThawSpaceReadWrite(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
ThawSpaceDeviceControl(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
);

NTSTATUS
ThawSpaceOpenFile(
	IN PDEVICE_OBJECT            DeviceObject,
	IN POPEN_FILE_INFORMATION    open_file_information
);

NTSTATUS
ThawSpaceCloseFile(
	IN PDEVICE_OBJECT DeviceObject
);

VOID
ThawSpaceUnload(
	IN PDRIVER_OBJECT DriverObject
);

BOOLEAN
IsThawSpaceDevice(
	IN PDEVICE_OBJECT DeviceObject
);

EXTERN_C_END
