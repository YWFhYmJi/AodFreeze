#pragma once

#include "Pch.h"

EXTERN_C_START
PDEVICE_OBJECT
OnDiskFilterInitialization(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
);

VOID
OnDiskFilterUnload(PDRIVER_OBJECT DriverObject);

BOOLEAN
OnDiskFilterDispatchControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	NTSTATUS *Status);

BOOLEAN
OnDiskFilterReadWrite(
	IN PUNICODE_STRING PhysicalDeviceName,
	IN ULONG DeviceType,
	IN ULONG DeviceNumber,
	IN ULONG PartitionNumber,
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN NTSTATUS *Status);

BOOLEAN
OnDiskFilterDeviceControl(
	IN PUNICODE_STRING PhysicalDeviceName,
	IN ULONG DeviceType,
	IN ULONG DeviceNumber,
	IN ULONG PartitionNumber,
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN NTSTATUS *Status);

VOID
OnDiskFilterNewDisk(
	IN PDEVICE_OBJECT DeviceObject,
	IN PUNICODE_STRING PhysicalDeviceName,
	IN ULONG DeviceType,
	IN ULONG DeviceNumber,
	IN ULONG PartitionNumber
);

VOID
OnDiskFilterRemoveDisk(
	IN PDEVICE_OBJECT DeviceObject,
	IN PUNICODE_STRING PhysicalDeviceName
);
EXTERN_C_END
