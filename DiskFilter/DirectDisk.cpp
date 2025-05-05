#include "DirectDisk.h"
#include <ntdddisk.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <mountmgr.h>
#include <ntddvol.h>
#include <ntddscsi.h>
#include "Utils.h"

#define DEVICE_BASE_NAME L"\\DirectDisk"
#define DEVICE_DIR_NAME L"\\Device" DEVICE_BASE_NAME
#define DEVICE_NAME_PREFIX DEVICE_DIR_NAME DEVICE_BASE_NAME

#define DIRECTDISK_MAGIC 0xD1573333D1573333
#define DIRECTDISK_MAGIC_REMOVED 0xD157FFFFD157FFFF

static HANDLE dir_handle;

typedef struct _DEVICE_EXTENSION {
	ULONG64                     magic;
	UNICODE_STRING              device_name;
	ULONG                       device_number;
	PVOLUME_INFO                protected_volume_info;
	BOOLEAN                     read_only;
	WCHAR                       drive_letter;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

NTSTATUS
DirectDiskInit(
	IN PDRIVER_OBJECT DriverObject
)
{
	NTSTATUS                    status;
	UNICODE_STRING              device_dir_name;
	OBJECT_ATTRIBUTES           object_attributes;

	RtlInitUnicodeString(&device_dir_name, DEVICE_DIR_NAME);

	InitializeObjectAttributes(
		&object_attributes,
		&device_dir_name,
		OBJ_PERMANENT,
		NULL,
		NULL
	);

	status = ZwCreateDirectoryObject(
		&dir_handle,
		DIRECTORY_ALL_ACCESS,
		&object_attributes
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	ZwMakeTemporaryObject(dir_handle);

	return STATUS_SUCCESS;
}

NTSTATUS
DirectDiskMount(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number,
	IN WCHAR            DriveLetter,
	IN PVOLUME_INFO     ProtectedVolume,
	IN BOOLEAN          ReadOnly
)
{
	UNICODE_STRING      device_name;
	NTSTATUS            status;
	PDEVICE_OBJECT      device_object;
	PDEVICE_EXTENSION   device_extension;
	HANDLE              thread_handle;
	UNICODE_STRING      sddl;

	ASSERT(DriverObject != NULL);

	device_name.Buffer = (PWCHAR)ExAllocatePool(PagedPool, MAXIMUM_FILENAME_LENGTH * 2);

	if (device_name.Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	device_name.Length = 0;
	device_name.MaximumLength = MAXIMUM_FILENAME_LENGTH * 2;

	RtlUnicodeStringPrintf(&device_name, DEVICE_NAME_PREFIX L"%u", Number);

	RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;BU)");

	status = IoCreateDeviceSecure(
		DriverObject,
		sizeof(DEVICE_EXTENSION),
		&device_name,
		FILE_DEVICE_DISK,
		0,
		FALSE,
		&sddl,
		NULL,
		&device_object
	);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_name.Buffer);
		return status;
	}

	device_object->Flags |= DO_DIRECT_IO;

	device_extension = (PDEVICE_EXTENSION)device_object->DeviceExtension;
	device_extension->magic = DIRECTDISK_MAGIC;
	device_extension->device_name.Length = device_name.Length;
	device_extension->device_name.MaximumLength = device_name.MaximumLength;
	device_extension->device_name.Buffer = device_name.Buffer;
	device_extension->device_number = Number;
	device_extension->drive_letter = DriveLetter;
	device_extension->protected_volume_info = ProtectedVolume;
	device_extension->read_only = ReadOnly;

	if (device_extension->read_only)
	{
		device_object->Characteristics |= FILE_READ_ONLY_DEVICE;
	}
	else
	{
		device_object->Characteristics &= ~FILE_READ_ONLY_DEVICE;
	}

	device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	MountVolume(&device_extension->device_name, device_extension->drive_letter);

	LogInfo("DirectDisk: Partition (%d,%d) mount on %c: ok.\n", device_extension->protected_volume_info->DiskNumber, device_extension->protected_volume_info->PartitionNumber, device_extension->drive_letter);

	return STATUS_SUCCESS;
}

NTSTATUS
DirectDiskUnmount(
	IN PDEVICE_OBJECT   DeviceObject
)
{
	PDEVICE_EXTENSION   device_extension;
	WCHAR				drive_letter;

	ASSERT(DeviceObject != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	drive_letter = device_extension->drive_letter;

	UnmountVolume(drive_letter);

	if (device_extension->device_name.Buffer != NULL)
	{
		ExFreePool(device_extension->device_name.Buffer);
	}

	device_extension->magic = DIRECTDISK_MAGIC_REMOVED;

	IoDeleteDevice(DeviceObject);

	LogInfo("DirectDisk: Unmount %c: ok.\n", drive_letter);

	return STATUS_SUCCESS;
}

VOID
DirectDiskUnload(
	IN PDRIVER_OBJECT DriverObject
)
{
	PDEVICE_OBJECT device_object;

	device_object = DriverObject->DeviceObject;

	while (device_object)
	{
		if (IsDirectDiskDevice(device_object))
		{
			PDEVICE_OBJECT next_device = device_object->NextDevice;
			DirectDiskUnmount(device_object);
			device_object = next_device;
		}
		else
		{
			device_object = device_object->NextDevice;
		}
	}

	ZwClose(dir_handle);
}

NTSTATUS
DirectDiskCreateClose(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = FILE_OPENED;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
DirectDiskReadWrite(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	PDEVICE_EXTENSION   device_extension;
	PIO_STACK_LOCATION  io_stack;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	io_stack = IoGetCurrentIrpStackLocation(Irp);

	if (io_stack->Parameters.Read.Length == 0)
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	if (io_stack->MajorFunction == IRP_MJ_WRITE && device_extension->read_only)
	{
		Irp->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_MEDIA_WRITE_PROTECTED;
	}

	IoMarkIrpPending(Irp);

	ExInterlockedInsertTailList(
		&device_extension->protected_volume_info->ListHead,
		&Irp->Tail.Overlay.ListEntry,
		&device_extension->protected_volume_info->ListLock
	);

	KeSetEvent(
		&device_extension->protected_volume_info->RequestEvent,
		(KPRIORITY)0,
		FALSE
	);

	return STATUS_PENDING;
}

NTSTATUS
DirectDiskDeviceControl(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	PDEVICE_EXTENSION   device_extension;
	PIO_STACK_LOCATION  io_stack;
	NTSTATUS            status;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	io_stack = IoGetCurrentIrpStackLocation(Irp);

	switch (io_stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DISK_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY:
	case IOCTL_STORAGE_CHECK_VERIFY2:
	{
		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;
	}

	case IOCTL_DISK_GET_DRIVE_GEOMETRY:
	{
		PDISK_GEOMETRY  disk_geometry;
		ULONGLONG       length;
		ULONG           sector_size;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(DISK_GEOMETRY))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		disk_geometry = (PDISK_GEOMETRY)Irp->AssociatedIrp.SystemBuffer;

		length = device_extension->protected_volume_info->BytesTotal;

		sector_size = device_extension->protected_volume_info->BytesPerSector;

		disk_geometry->Cylinders.QuadPart = length / sector_size / 32 / 2;
		disk_geometry->MediaType = FixedMedia;
		disk_geometry->TracksPerCylinder = 2;
		disk_geometry->SectorsPerTrack = 32;
		disk_geometry->BytesPerSector = sector_size;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);

		break;
	}

	case IOCTL_DISK_GET_LENGTH_INFO:
	{
		PGET_LENGTH_INFORMATION get_length_information;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(GET_LENGTH_INFORMATION))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		get_length_information = (PGET_LENGTH_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		get_length_information->Length.QuadPart = device_extension->protected_volume_info->BytesTotal;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);

		break;
	}

	case IOCTL_DISK_GET_PARTITION_INFO:
	{
		PPARTITION_INFORMATION  partition_information;
		ULONGLONG               length;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(PARTITION_INFORMATION))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		partition_information = (PPARTITION_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		length = device_extension->protected_volume_info->BytesTotal;

		partition_information->StartingOffset.QuadPart = 0;
		partition_information->PartitionLength.QuadPart = length;
		partition_information->HiddenSectors = 1;
		partition_information->PartitionNumber = 0;
		partition_information->PartitionType = 0;
		partition_information->BootIndicator = FALSE;
		partition_information->RecognizedPartition = FALSE;
		partition_information->RewritePartition = FALSE;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);

		break;
	}

	case IOCTL_DISK_GET_PARTITION_INFO_EX:
	{
		PPARTITION_INFORMATION_EX   partition_information_ex;
		ULONGLONG                   length;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(PARTITION_INFORMATION_EX))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		partition_information_ex = (PPARTITION_INFORMATION_EX)Irp->AssociatedIrp.SystemBuffer;

		length = device_extension->protected_volume_info->BytesTotal;

		partition_information_ex->PartitionStyle = PARTITION_STYLE_MBR;
		partition_information_ex->StartingOffset.QuadPart = 0;
		partition_information_ex->PartitionLength.QuadPart = length;
		partition_information_ex->PartitionNumber = 0;
		partition_information_ex->RewritePartition = FALSE;
		partition_information_ex->Mbr.PartitionType = 0;
		partition_information_ex->Mbr.BootIndicator = FALSE;
		partition_information_ex->Mbr.RecognizedPartition = FALSE;
		partition_information_ex->Mbr.HiddenSectors = 1;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION_EX);

		break;
	}

	case IOCTL_DISK_IS_WRITABLE:
	{
		if (!device_extension->read_only)
		{
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_MEDIA_WRITE_PROTECTED;
		}
		Irp->IoStatus.Information = 0;
		break;
	}

	case IOCTL_DISK_MEDIA_REMOVAL:
	case IOCTL_STORAGE_MEDIA_REMOVAL:
	{
		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;
	}

	case IOCTL_DISK_SET_PARTITION_INFO:
	{
		if (device_extension->read_only)
		{
			status = STATUS_MEDIA_WRITE_PROTECTED;
			Irp->IoStatus.Information = 0;
			break;
		}

		if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(SET_PARTITION_INFORMATION))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		break;
	}

	case IOCTL_DISK_VERIFY:
	{
		PVERIFY_INFORMATION verify_information;

		if (io_stack->Parameters.DeviceIoControl.InputBufferLength <
			sizeof(VERIFY_INFORMATION))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}

		verify_information = (PVERIFY_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = verify_information->Length;

		break;
	}

	case IOCTL_STORAGE_GET_DEVICE_NUMBER:
	{
		PSTORAGE_DEVICE_NUMBER number;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(STORAGE_DEVICE_NUMBER))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		number = (PSTORAGE_DEVICE_NUMBER)Irp->AssociatedIrp.SystemBuffer;

		number->DeviceType = FILE_DEVICE_DISK;
		number->DeviceNumber = device_extension->device_number;
		number->PartitionNumber = (ULONG)-1;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(STORAGE_DEVICE_NUMBER);

		break;
	}

	case IOCTL_STORAGE_GET_HOTPLUG_INFO:
	{
		PSTORAGE_HOTPLUG_INFO info;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(STORAGE_HOTPLUG_INFO))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		info = (PSTORAGE_HOTPLUG_INFO)Irp->AssociatedIrp.SystemBuffer;

		info->Size = sizeof(STORAGE_HOTPLUG_INFO);
		info->MediaRemovable = 0;
		info->MediaHotplug = 0;
		info->DeviceHotplug = 0;
		info->WriteCacheEnableOverride = 0;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(STORAGE_HOTPLUG_INFO);

		break;
	}

	case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
	{
		PVOLUME_GET_GPT_ATTRIBUTES_INFORMATION attr;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		attr = (PVOLUME_GET_GPT_ATTRIBUTES_INFORMATION)Irp->AssociatedIrp.SystemBuffer;

		attr->GptAttributes = 0;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(VOLUME_GET_GPT_ATTRIBUTES_INFORMATION);

		break;
	}

	case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
	{
		PVOLUME_DISK_EXTENTS ext;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(VOLUME_DISK_EXTENTS))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}
		/*
					// not needed since there is only one disk extent to return
					if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
						sizeof(VOLUME_DISK_EXTENTS) + ((NumberOfDiskExtents - 1) * sizeof(DISK_EXTENT)))
					{
						status = STATUS_BUFFER_OVERFLOW;
						Irp->IoStatus.Information = 0;
						break;
					}
		*/
		ext = (PVOLUME_DISK_EXTENTS)Irp->AssociatedIrp.SystemBuffer;

		ext->NumberOfDiskExtents = 1;
		ext->Extents[0].DiskNumber = device_extension->device_number;
		ext->Extents[0].StartingOffset.QuadPart = 0;
		ext->Extents[0].ExtentLength.QuadPart = device_extension->protected_volume_info->BytesTotal;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(VOLUME_DISK_EXTENTS) /*+ ((NumberOfDiskExtents - 1) * sizeof(DISK_EXTENT))*/;

		break;
	}

#if (NTDDI_VERSION < NTDDI_VISTA)
#define IOCTL_DISK_IS_CLUSTERED CTL_CODE(IOCTL_DISK_BASE, 0x003e, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif  // NTDDI_VERSION < NTDDI_VISTA

	case IOCTL_DISK_IS_CLUSTERED:
	{
		PBOOLEAN clus;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(BOOLEAN))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			Irp->IoStatus.Information = 0;
			break;
		}

		clus = (PBOOLEAN)Irp->AssociatedIrp.SystemBuffer;

		*clus = FALSE;

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(BOOLEAN);

		break;
	}

	case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
	{
		PMOUNTDEV_NAME name;

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			sizeof(MOUNTDEV_NAME))
		{
			status = STATUS_INVALID_PARAMETER;
			Irp->IoStatus.Information = 0;
			break;
		}

		name = (PMOUNTDEV_NAME)Irp->AssociatedIrp.SystemBuffer;
		name->NameLength = device_extension->device_name.Length * sizeof(WCHAR);

		if (io_stack->Parameters.DeviceIoControl.OutputBufferLength <
			name->NameLength + sizeof(USHORT))
		{
			status = STATUS_BUFFER_OVERFLOW;
			Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
			break;
		}

		RtlCopyMemory(name->Name, device_extension->device_name.Buffer, name->NameLength);

		status = STATUS_SUCCESS;
		Irp->IoStatus.Information = name->NameLength + sizeof(USHORT);

		break;
	}

#if (NTDDI_VERSION < NTDDI_VISTA)
#define IOCTL_VOLUME_QUERY_ALLOCATION_HINT CTL_CODE(IOCTL_VOLUME_BASE, 20, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#endif  // NTDDI_VERSION < NTDDI_VISTA

	case IOCTL_DISK_GET_MEDIA_TYPES:
	case 0x66001b: // FT_BALANCED_READ_MODE
	case IOCTL_SCSI_GET_CAPABILITIES:
	case IOCTL_SCSI_PASS_THROUGH:
	case IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES:
	case IOCTL_STORAGE_QUERY_PROPERTY:
	case IOCTL_VOLUME_QUERY_ALLOCATION_HINT:
	default:
	{
		LogWarn(
			"DirectDisk: Unknown IoControlCode %#x\n",
			io_stack->Parameters.DeviceIoControl.IoControlCode
		);

		status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
	}
	}

	if (status != STATUS_PENDING)
	{
		Irp->IoStatus.Status = status;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

	return status;
}

BOOLEAN
IsDirectDiskDevice(
	IN PDEVICE_OBJECT DeviceObject
)
{
	PDEVICE_EXTENSION device_extension;

	ASSERT(DeviceObject != NULL);

	if (DeviceObject->Size < sizeof(DEVICE_OBJECT) + sizeof(DEVICE_EXTENSION))
		return FALSE;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	return device_extension != NULL && device_extension->magic == DIRECTDISK_MAGIC;
}

NTSTATUS
PreCheckRemovedDirectDisk(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	PDEVICE_EXTENSION device_extension;

	ASSERT(DeviceObject != NULL);

	if (DeviceObject->Size < sizeof(DEVICE_OBJECT) + sizeof(DEVICE_EXTENSION))
		return STATUS_INVALID_PARAMETER;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	if (device_extension != NULL && device_extension->magic == DIRECTDISK_MAGIC_REMOVED)
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}
	return STATUS_INVALID_PARAMETER;
}

PDEVICE_OBJECT
FindDirectDiskDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number
)
{
	PDEVICE_OBJECT device_object;

	ASSERT(DriverObject != NULL);

	device_object = DriverObject->DeviceObject;

	while (device_object)
	{
		if (IsDirectDiskDevice(device_object) && ((PDEVICE_EXTENSION)device_object->DeviceExtension)->device_number == Number)
		{
			break;
		}
		else
		{
			device_object = device_object->NextDevice;
		}
	}
	return device_object;
}

PDEVICE_OBJECT
FindDirectDiskDeviceByPartition(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            DiskNumber,
	IN ULONG			PartitionNumber
)
{
	PDEVICE_OBJECT device_object;

	ASSERT(DriverObject != NULL);

	device_object = DriverObject->DeviceObject;

	while (device_object)
	{
		if (IsDirectDiskDevice(device_object))
		{
			PVOLUME_INFO volume_info = ((PDEVICE_EXTENSION)device_object->DeviceExtension)->protected_volume_info;
			if (volume_info->DiskNumber == DiskNumber && volume_info->PartitionNumber == PartitionNumber)
				break;
		}
		device_object = device_object->NextDevice;
	}
	return device_object;
}

NTSTATUS DirectDiskGetConfig(
	IN PDEVICE_OBJECT            DeviceObject,
	OUT PDISKFILTER_DIRECTDISK   Config
)
{
	PDEVICE_EXTENSION device_extension;

	ASSERT(DeviceObject != NULL);
	ASSERT(Config != NULL);

	if (!IsDirectDiskDevice(DeviceObject))
		return STATUS_INVALID_PARAMETER;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	Config->Number = device_extension->device_number;
	Config->DriveLetter = device_extension->drive_letter;
	Config->DiskNumber = device_extension->protected_volume_info->DiskNumber;
	Config->PartitionNumber = device_extension->protected_volume_info->PartitionNumber;
	Config->ReadOnly = device_extension->read_only;

	return STATUS_SUCCESS;
}