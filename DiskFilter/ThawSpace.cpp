#include "ThawSpace.h"
#include <ntdddisk.h>
#include <ntstrsafe.h>
#include <wdmsec.h>
#include <mountmgr.h>
#include <ntddvol.h>
#include <ntddscsi.h>
#include "Utils.h"

#define DEVICE_BASE_NAME L"\\ThawSpace"
#define DEVICE_DIR_NAME L"\\Device" DEVICE_BASE_NAME
#define DEVICE_NAME_PREFIX DEVICE_DIR_NAME DEVICE_BASE_NAME

#define THAWSPACE_MAGIC 0xD1572222D1572222

static HANDLE dir_handle = NULL;

typedef struct _DEVICE_EXTENSION {
	ULONG64                     magic;
	BOOLEAN                     media_in_device;
	UNICODE_STRING              device_name;
	ULONG                       device_number;
	HANDLE                      file_handle;
	UNICODE_STRING              file_name;
	LARGE_INTEGER               file_size;
	BOOLEAN                     read_only;
	LIST_ENTRY                  list_head;
	KSPIN_LOCK                  list_lock;
	KEVENT                      request_event;
	PVOID                       thread_pointer;
	BOOLEAN                     terminate_thread;
	WCHAR                       drive_letter;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

VOID
ThawSpaceThread(
	IN PVOID            Context
);

NTSTATUS
ThawSpaceInit(
	IN PDRIVER_OBJECT DriverObject,
	IN ULONG NumberOfDevices
)
{
	NTSTATUS                    status;
	UNICODE_STRING              device_dir_name;
	OBJECT_ATTRIBUTES           object_attributes;
	ULONG                       n;
	USHORT                      n_created_devices;

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
	
	for (n = 0, n_created_devices = 0; n < NumberOfDevices; n++)
	{
		status = ThawSpaceCreateDevice(DriverObject, n);

		if (NT_SUCCESS(status))
		{
			n_created_devices++;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS
ThawSpaceCreateDevice(
	IN PDRIVER_OBJECT   DriverObject,
	IN ULONG            Number
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
	device_extension->magic = THAWSPACE_MAGIC;

	device_extension->media_in_device = FALSE;

	device_extension->device_name.Length = device_name.Length;
	device_extension->device_name.MaximumLength = device_name.MaximumLength;
	device_extension->device_name.Buffer = device_name.Buffer;
	device_extension->device_number = Number;

	InitializeListHead(&device_extension->list_head);

	KeInitializeSpinLock(&device_extension->list_lock);

	KeInitializeEvent(
		&device_extension->request_event,
		SynchronizationEvent,
		FALSE
	);

	device_extension->terminate_thread = FALSE;

	status = PsCreateSystemThread(
		&thread_handle,
		(ACCESS_MASK)0L,
		NULL,
		NULL,
		NULL,
		ThawSpaceThread,
		device_object
	);

	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(device_object);
		ExFreePool(device_name.Buffer);
		return status;
	}

	status = ObReferenceObjectByHandle(
		thread_handle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&device_extension->thread_pointer,
		NULL
	);

	if (!NT_SUCCESS(status))
	{
		ZwClose(thread_handle);

		device_extension->terminate_thread = TRUE;

		KeSetEvent(
			&device_extension->request_event,
			(KPRIORITY)0,
			FALSE
		);

		IoDeleteDevice(device_object);

		ExFreePool(device_name.Buffer);

		return status;
	}

	ZwClose(thread_handle);
	device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

PDEVICE_OBJECT
ThawSpaceDeleteDevice(
	IN PDEVICE_OBJECT DeviceObject
)
{
	PDEVICE_EXTENSION   device_extension;
	PDEVICE_OBJECT      next_device_object;

	ASSERT(DeviceObject != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	device_extension->terminate_thread = TRUE;

	KeSetEvent(
		&device_extension->request_event,
		(KPRIORITY)0,
		FALSE
	);

	KeWaitForSingleObject(
		device_extension->thread_pointer,
		Executive,
		KernelMode,
		FALSE,
		NULL
	);

	ObDereferenceObject(device_extension->thread_pointer);

	if (device_extension->device_name.Buffer != NULL)
	{
		ExFreePool(device_extension->device_name.Buffer);
	}

	next_device_object = DeviceObject->NextDevice;

	IoDeleteDevice(DeviceObject);

	return next_device_object;
}

VOID
ThawSpaceUnload(
	IN PDRIVER_OBJECT DriverObject
)
{
	PDEVICE_OBJECT device_object;

	device_object = DriverObject->DeviceObject;

	while (device_object)
	{
		if (IsThawSpaceDevice(device_object))
		{
			ThawSpaceCloseFile(device_object);
			device_object = ThawSpaceDeleteDevice(device_object);
		}
		else
		{
			device_object = device_object->NextDevice;
		}
	}

	if (dir_handle != NULL)
		ZwClose(dir_handle);
}

NTSTATUS
ThawSpaceCreateClose(
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
ThawSpaceReadWrite(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	PDEVICE_EXTENSION   device_extension;
	PIO_STACK_LOCATION  io_stack;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	if (!device_extension->media_in_device)
	{
		Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_NO_MEDIA_IN_DEVICE;
	}

	io_stack = IoGetCurrentIrpStackLocation(Irp);

	if (io_stack->Parameters.Read.Length == 0)
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}

	IoMarkIrpPending(Irp);

	ExInterlockedInsertTailList(
		&device_extension->list_head,
		&Irp->Tail.Overlay.ListEntry,
		&device_extension->list_lock
	);

	KeSetEvent(
		&device_extension->request_event,
		(KPRIORITY)0,
		FALSE
	);

	return STATUS_PENDING;
}

NTSTATUS
ThawSpaceDeviceControl(
	IN PDEVICE_OBJECT   DeviceObject,
	IN PIRP             Irp
)
{
	PDEVICE_EXTENSION   device_extension;
	PIO_STACK_LOCATION  io_stack;
	NTSTATUS            status;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	io_stack = IoGetCurrentIrpStackLocation(Irp);

	if (!device_extension->media_in_device)
	{
		Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_NO_MEDIA_IN_DEVICE;
	}

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

		length = device_extension->file_size.QuadPart;

		sector_size = 512;

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

		get_length_information->Length.QuadPart = device_extension->file_size.QuadPart;

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

		length = device_extension->file_size.QuadPart;

		partition_information->StartingOffset.QuadPart = 0;
		partition_information->PartitionLength.QuadPart = length;
		partition_information->HiddenSectors = 0;
		partition_information->PartitionNumber = (ULONG)-1;
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

		length = device_extension->file_size.QuadPart;

		partition_information_ex->PartitionStyle = PARTITION_STYLE_MBR;
		partition_information_ex->StartingOffset.QuadPart = 0;
		partition_information_ex->PartitionLength.QuadPart = length;
		partition_information_ex->PartitionNumber = (ULONG)-1;
		partition_information_ex->RewritePartition = FALSE;
		partition_information_ex->Mbr.PartitionType = 0;
		partition_information_ex->Mbr.BootIndicator = FALSE;
		partition_information_ex->Mbr.RecognizedPartition = FALSE;
		partition_information_ex->Mbr.HiddenSectors = 0;

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
		ext->Extents[0].ExtentLength.QuadPart = device_extension->file_size.QuadPart;

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
			"ThawSpace: Unknown IoControlCode %#x\n",
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

VOID
ThawSpaceThread(
	IN PVOID Context
)
{
	PDEVICE_OBJECT      device_object;
	PDEVICE_EXTENSION   device_extension;
	PLIST_ENTRY         request;
	PIRP                irp;
	PIO_STACK_LOCATION  io_stack;
	PUCHAR              system_buffer;
	PUCHAR              buffer;

	ASSERT(Context != NULL);

	device_object = (PDEVICE_OBJECT)Context;

	device_extension = (PDEVICE_EXTENSION)device_object->DeviceExtension;

	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	AdjustPrivilege(SE_IMPERSONATE_PRIVILEGE, TRUE);

	for (;;)
	{
		KeWaitForSingleObject(
			&device_extension->request_event,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);

		if (device_extension->terminate_thread)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		while ((request = ExInterlockedRemoveHeadList(
			&device_extension->list_head,
			&device_extension->list_lock
		)) != NULL)
		{
			irp = CONTAINING_RECORD(request, IRP, Tail.Overlay.ListEntry);

			io_stack = IoGetCurrentIrpStackLocation(irp);

			switch (io_stack->MajorFunction)
			{
			case IRP_MJ_READ:
				system_buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
				if (system_buffer == NULL)
				{
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					irp->IoStatus.Information = 0;
					break;
				}
				buffer = (PUCHAR)ExAllocatePool(PagedPool, io_stack->Parameters.Read.Length);
				if (buffer == NULL)
				{
					irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					irp->IoStatus.Information = 0;
					break;
				}
				ZwReadFile(
					device_extension->file_handle,
					NULL,
					NULL,
					NULL,
					&irp->IoStatus,
					buffer,
					io_stack->Parameters.Read.Length,
					&io_stack->Parameters.Read.ByteOffset,
					NULL
				);
				RtlCopyMemory(system_buffer, buffer, io_stack->Parameters.Read.Length);
				ExFreePool(buffer);
				break;

			case IRP_MJ_WRITE:
				if ((io_stack->Parameters.Write.ByteOffset.QuadPart +
					io_stack->Parameters.Write.Length) >
					device_extension->file_size.QuadPart)
				{
					irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
					irp->IoStatus.Information = 0;
					break;
				}
				ZwWriteFile(
					device_extension->file_handle,
					NULL,
					NULL,
					NULL,
					&irp->IoStatus,
					MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority),
					io_stack->Parameters.Write.Length,
					&io_stack->Parameters.Write.ByteOffset,
					NULL
				);
				break;
			default:
				irp->IoStatus.Status = STATUS_DRIVER_INTERNAL_ERROR;
			}

			IoCompleteRequest(
				irp,
				(CCHAR)(NT_SUCCESS(irp->IoStatus.Status) ?
					IO_DISK_INCREMENT : IO_NO_INCREMENT)
			);
		}
	}
}

NTSTATUS
ThawSpaceOpenFile(
	IN PDEVICE_OBJECT            DeviceObject,
	IN POPEN_FILE_INFORMATION    open_file_information
)
{
	PDEVICE_EXTENSION               device_extension;
	NTSTATUS                        status;
	OBJECT_ATTRIBUTES               object_attributes;
	FILE_END_OF_FILE_INFORMATION    file_eof;
	FILE_BASIC_INFORMATION          file_basic;
	FILE_STANDARD_INFORMATION       file_standard;
	FILE_ALIGNMENT_INFORMATION      file_alignment;
	IO_STATUS_BLOCK                 io_status;

	ASSERT(DeviceObject != NULL);
	ASSERT(open_file_information != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	device_extension->read_only = open_file_information->ReadOnly;

	device_extension->file_name.Length = open_file_information->FileNameLength * sizeof(WCHAR);
	device_extension->file_name.MaximumLength = open_file_information->FileNameLength * sizeof(WCHAR);
	device_extension->file_name.Buffer = (PWCH)ExAllocatePool(PagedPool, open_file_information->FileNameLength * sizeof(WCHAR));

	if (device_extension->file_name.Buffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlCopyMemory(
		device_extension->file_name.Buffer,
		open_file_information->FileName,
		open_file_information->FileNameLength * sizeof(WCHAR)
	);

	InitializeObjectAttributes(
		&object_attributes,
		&device_extension->file_name,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);

	status = ZwCreateFile(
		&device_extension->file_handle,
		device_extension->read_only ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
		&object_attributes,
		&io_status,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		device_extension->read_only ? FILE_SHARE_READ : 0,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE |
		FILE_RANDOM_ACCESS |
		FILE_NO_INTERMEDIATE_BUFFERING |
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);

	if (NT_SUCCESS(status))
	{
		LogInfo("ThawSpace: File %wZ opened.\n", &device_extension->file_name);
	}
	else
	{
		LogErr("ThawSpace: File %wZ could not be opened. status=0x%.8X\n", &device_extension->file_name, status);
		ExFreePool(device_extension->file_name.Buffer);
		return status;
	}

	status = ZwQueryInformationFile(
		device_extension->file_handle,
		&io_status,
		&file_basic,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation
	);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_extension->file_name.Buffer);
		ZwClose(device_extension->file_handle);
		return status;
	}

	//
	// The NT cache manager can deadlock if a filesystem that is using the cache
	// manager is used in a virtual disk that stores its file on a filesystem
	// that is also using the cache manager, this is why we open the file with
	// FILE_NO_INTERMEDIATE_BUFFERING above, however if the file is compressed
	// or encrypted NT will not honor this request and cache it anyway since it
	// need to store the decompressed/unencrypted data somewhere, therefor we put
	// an extra check here and don't alow disk images to be compressed/encrypted.
	//
	if (file_basic.FileAttributes & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED))
	{
		LogWarn("ThawSpace: Warning: File is compressed or encrypted. File attributes: %#x.\n", file_basic.FileAttributes);
		/*
				ExFreePool(device_extension->file_name.Buffer);
				ZwClose(device_extension->file_handle);
				Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
				Irp->IoStatus.Information = 0;
				return STATUS_ACCESS_DENIED;
		*/
	}

	status = ZwQueryInformationFile(
		device_extension->file_handle,
		&io_status,
		&file_standard,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation
	);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_extension->file_name.Buffer);
		ZwClose(device_extension->file_handle);
		return status;
	}

	device_extension->file_size.QuadPart = file_standard.EndOfFile.QuadPart;

	status = ZwQueryInformationFile(
		device_extension->file_handle,
		&io_status,
		&file_alignment,
		sizeof(FILE_ALIGNMENT_INFORMATION),
		FileAlignmentInformation
	);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(device_extension->file_name.Buffer);
		ZwClose(device_extension->file_handle);
		return status;
	}

	DeviceObject->AlignmentRequirement = file_alignment.AlignmentRequirement;

	if (device_extension->read_only)
	{
		DeviceObject->Characteristics |= FILE_READ_ONLY_DEVICE;
	}
	else
	{
		DeviceObject->Characteristics &= ~FILE_READ_ONLY_DEVICE;
	}

	device_extension->media_in_device = TRUE;

	device_extension->drive_letter = open_file_information->DriveLetter;

	MountVolume(&device_extension->device_name, device_extension->drive_letter);

	LogInfo("ThawSpace: File %wZ mount on %c: ok.\n", &device_extension->file_name, device_extension->drive_letter);

	return STATUS_SUCCESS;
}

NTSTATUS
ThawSpaceCloseFile(
	IN PDEVICE_OBJECT DeviceObject
)
{
	PDEVICE_EXTENSION device_extension;

	ASSERT(DeviceObject != NULL);

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

	if (device_extension->media_in_device)
	{
		ExFreePool(device_extension->file_name.Buffer);

		ZwClose(device_extension->file_handle);

		device_extension->media_in_device = FALSE;

		UnmountVolume(device_extension->drive_letter);

		LogInfo("ThawSpace: Unmount %c: ok.\n", device_extension->drive_letter);
	}

	return STATUS_SUCCESS;
}

BOOLEAN
IsThawSpaceDevice(
	IN PDEVICE_OBJECT DeviceObject
)
{
	PDEVICE_EXTENSION device_extension;

	ASSERT(DeviceObject != NULL);

	if (DeviceObject->Size < sizeof(DEVICE_OBJECT) + sizeof(DEVICE_EXTENSION))
		return FALSE;

	device_extension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	return device_extension != NULL && device_extension->magic == THAWSPACE_MAGIC;
}