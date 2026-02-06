#include "diskfltlib.h"
#include "DiskFilter.h"
#include "Utils.h"
#include "IrpFile.h"
#include "mempool/mempool.h"
#include <wdmsec.h>
#include <ntimage.h>
#include <ntddscsi.h>
#include <wchar.h>
#include <ntdddisk.h>
#include <ntstrsafe.h>
#include "messages.h"
#include "ThawSpace.h"
#include "DirectDisk.h"

// 保护硬盘特定扇区所用到的信息
typedef struct _DISK_INFO
{
	ULONG		BytesPerSector;		// 每个扇区的大小
	ULONGLONG	SectorCount;		// 硬盘总扇区数
	PDP_BITMAP	BitmapDeny;			// 阻止写入的扇区位图(MBR,EBR)
} DISK_INFO, *PDISK_INFO;

// 保护配置文件路径、文件对象、所在盘符、所在扇区
UNICODE_STRING ConfigPath;
PFILE_OBJECT ConfigFileObject;
VOLUME_INFO ConfigVolume;
PRETRIEVAL_POINTERS_BUFFER ConfigVcnPairs;

// 不使用Inbv显示信息，兼容一些显卡驱动
DWORD DisableStartupMessage;
DWORD DisableShutdownMessage;

PDEVICE_OBJECT LowerDeviceObject[256]; // 硬盘的下层设备
PDEVICE_OBJECT FilterDevice; // 当前过滤器设备
DISKFILTER_PROTECTION_CONFIG Config, NewConfig; // 当前保护配置、新配置
ERESOURCE DriverListLock; // 驱动策略锁
VOLUME_INFO ProtectVolumeList[256]; // 保护卷列表
PVOLUME_INFO VolumeList[26]; // 盘符对应的保护卷
UINT ValidVolumeCount; // 保护卷数量
DISK_INFO ProtectDiskList[256]; // 硬盘保护信息
BOOLEAN IsProtect; // 是否在保护状态
BOOLEAN AllowLoadDriver; // 是否允许加载驱动
BOOLEAN AllowDirectMount; // 是否允许直接挂载
UINT DirectDiskCount; // 已挂载的直接读写卷数量

// 读写操作线程
void ThreadReadWrite(PVOID Context);

// 检查配置文件是否有效
BOOLEAN IsValidConfig(PDISKFILTER_PROTECTION_CONFIG Conf)
{
	// 头部不匹配
	if (Conf->Magic != DISKFILTER_CONFIG_MAGIC)
		return FALSE;

	// 版本不匹配
	if (Conf->Version != DISKFILTER_DRIVER_VERSION)
		return FALSE;

	// 保护卷个数无效
	if (Conf->ProtectVolumeCount > sizeof(Conf->ProtectVolume) / sizeof(Conf->ProtectVolume[0]))
		return FALSE;

	// 驱动白名单或黑名单个数无效
	if (Conf->DriverCount > sizeof(Conf->DriverList) / sizeof(Conf->DriverList[0]))
		return FALSE;

	// 解冻空间个数无效
	if (Conf->ThawSpaceCount > sizeof(Conf->ThawSpacePath) / sizeof(Conf->ThawSpacePath[0]))
		return FALSE;

	return TRUE;
}

// 获取卷信息
NTSTATUS GetVolumeInfo(ULONG DiskNum, DWORD PartitionNum, PVOLUME_INFO info)
{
	NTSTATUS status;
	HANDLE fileHandle;
	UNICODE_STRING fileName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK IoStatusBlock;

	WCHAR volumeDosName[MAX_PATH];

	RtlZeroMemory(info, sizeof(VOLUME_INFO));

	info->DiskNumber = DiskNum;
	info->PartitionNumber = PartitionNum;

	swprintf_s(volumeDosName, MAX_PATH, L"\\Device\\Harddisk%d\\Partition%d", DiskNum, PartitionNum);

	RtlInitUnicodeString(&fileName, volumeDosName);

	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	if (NT_SUCCESS(status))
	{
		IO_STATUS_BLOCK				ioBlock;
		FILE_FS_SIZE_INFORMATION	sizeoInfo;

		// 得到此卷的一类型，在物理硬盘的上的偏移等信息
		// 新版操作系统不支持IOCTL_DISK_GET_PARTITION_INFO，改用IOCTL_DISK_GET_PARTITION_INFO_EX
		PARTITION_INFORMATION_EX	partitionInfo;
		status = ZwDeviceIoControlFile(fileHandle,
			NULL,
			NULL,
			NULL,
			&ioBlock,
			IOCTL_DISK_GET_PARTITION_INFO_EX,
			NULL,
			0,
			&partitionInfo,
			sizeof(partitionInfo)
		);


		if (NT_SUCCESS(status))
		{
			info->StartOffset = partitionInfo.StartingOffset.QuadPart;
			info->BytesTotal = partitionInfo.PartitionLength.QuadPart;
			info->FirstDataSector = 0;

			if (partitionInfo.PartitionStyle == PARTITION_STYLE_MBR)
			{
				info->PartitionType = partitionInfo.Mbr.PartitionType;

				// FAT分区，获取LBR, 得到第一个簇的偏移
				if ((PARTITION_FAT_12 == info->PartitionType) ||
					(PARTITION_FAT_16 == info->PartitionType) ||
					(PARTITION_HUGE == info->PartitionType) ||
					(PARTITION_FAT32 == info->PartitionType) ||
					(PARTITION_FAT32_XINT13 == info->PartitionType) ||
					(PARTITION_XINT13 == info->PartitionType))
				{
					status = GetFatFirstSectorOffset(fileHandle, &info->FirstDataSector);
				}
			}
			else
			{
				// 不知道分区是否是FAT类型的，尝试获取第一个簇的偏移
				GetFatFirstSectorOffset(fileHandle, &info->FirstDataSector);
				info->PartitionType = PARTITION_IFS;
			}
		}
		else
		{
			LogWarn("Failed to read the volume information, error code=0x%.8X\n", status);
		}
		
		if (!NT_SUCCESS(status))
		{
			ZwClose(fileHandle);
			return status;
		}

		// 得到簇，扇区等大小
		status = ZwQueryVolumeInformationFile(fileHandle,
			&IoStatusBlock,
			&sizeoInfo,
			sizeof(sizeoInfo),
			FileFsSizeInformation);

		if (NT_SUCCESS(status))
		{
			info->BytesPerSector = sizeoInfo.BytesPerSector;
			info->BytesPerCluster = sizeoInfo.BytesPerSector * sizeoInfo.SectorsPerAllocationUnit;
			info->VolumeDevice = GetVolumeDeviceByFileHandle(fileHandle);
		}
		else
		{
			LogWarn("Failed to read the volume size, error code=0x%.8X\n", status);
		}

		ZwClose(fileHandle);
	}
	else
	{
		LogWarn("Failed to open the volume %wZ, error code = 0x%.8X\n", &fileName, status);
	}

	return status;
}

// 读取保护配置
NTSTATUS ReadProtectionConfig(PUNICODE_STRING ConfigFilePath, PDISKFILTER_PROTECTION_CONFIG RetConfig)
{
	NTSTATUS status;
	PDISKFILTER_PROTECTION_CONFIG Conf = NULL;
	IO_STATUS_BLOCK IoStatus = { 0 };
	HANDLE ConfigHandle;
	PFILE_OBJECT ConfigFile;

	LogInfo("Reading config file (%wZ)\n", ConfigFilePath);

	if (!RetConfig)
		return STATUS_UNSUCCESSFUL;

	Conf = (PDISKFILTER_PROTECTION_CONFIG)__malloc(sizeof(DISKFILTER_PROTECTION_CONFIG));
	if (!Conf)
		return STATUS_INSUFFICIENT_RESOURCES;

	WCHAR prefix[] = L"\\??\\";
	PWCHAR TempPath = (PWCHAR)__malloc(ConfigFilePath->Length + (wcslen(prefix) + 10) * sizeof(WCHAR));
	if (TempPath)
	{
		swprintf(TempPath, L"%ls%wZ", prefix, ConfigFilePath);
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, TempPath);
		if (NT_SUCCESS(GetFileHandleReadOnly(&ConfigHandle, &uniPath)))
		{
			if (NT_SUCCESS(ObReferenceObjectByHandle(ConfigHandle, 0, NULL, KernelMode, (PVOID *)&ConfigFile, NULL)))
			{
				UNICODE_STRING	uniDosName;
				// 得到类似C:这样的盘符，为了获取VolumeInfo
				if (NT_SUCCESS(IoVolumeDeviceToDosName(ConfigFile->DeviceObject, &uniDosName)) && uniDosName.Buffer)
				{
					WCHAR ConfigVolumeLetter = towupper(*(WCHAR *)uniDosName.Buffer);
					ULONG ConfigDiskNum, ConfigPartNum;
					if (NT_SUCCESS(GetPartNumFromVolLetter(ConfigVolumeLetter, &ConfigDiskNum, &ConfigPartNum)))
					{
						LogInfo("Config volume %c -> (%lu,%lu)\n", ConfigVolumeLetter, ConfigDiskNum, ConfigPartNum);
						if (NT_SUCCESS(GetVolumeInfo(ConfigDiskNum, ConfigPartNum, &ConfigVolume)))
						{
							ConfigVolume.Volume = ConfigVolumeLetter;
						}
						else
						{
							LogWarn("Failed to get config volume info\n");
							ConfigVolume.Volume = 0; // 获取失败，标记为无效
						}
					}
					else
					{
						LogWarn("Failed to read partition number for config volume %c\n", ConfigVolume.Volume);
					}

					ExFreePool(uniDosName.Buffer);
				}
				ObDereferenceObject(ConfigFile);
			}
			ConfigVcnPairs = (PRETRIEVAL_POINTERS_BUFFER)GetFileClusterList(ConfigHandle);
			ZwClose(ConfigHandle);
		}
		__free(TempPath);
	}

	// 打开配置文件，发送IRP独占配置文件，避免配置文件被其他程序修改或删除
	status = IrpCreateFile(&ConfigFileObject, FILE_ALL_ACCESS, ConfigFilePath, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NO_INTERMEDIATE_BUFFERING, NULL, 0);
	if (!NT_SUCCESS(status))
		return status;

	status = IrpReadFile(ConfigFileObject, &IoStatus, Conf, sizeof(DISKFILTER_PROTECTION_CONFIG), NULL);
	if (!NT_SUCCESS(status))
		return status;

	// 不需要关闭配置文件对象

	if (!IsValidConfig(Conf))
	{
		LogErr("Config file is invalid! Magic=0x%.4X, Version=0x%.4X, Flags=%.2X\n", Conf->Magic, Conf->Version, Conf->ProtectionFlags);
		return STATUS_UNSUCCESSFUL;
	}

	RtlCopyMemory(RetConfig, Conf, sizeof(DISKFILTER_PROTECTION_CONFIG));
	return STATUS_SUCCESS;
}

// 写入保护配置
NTSTATUS WriteProtectionConfig(PDISKFILTER_PROTECTION_CONFIG ConfigData)
{
	if (ConfigVolume.Volume == 0 || ConfigVolume.DiskNumber >= sizeof(LowerDeviceObject) / sizeof(*LowerDeviceObject) || !ConfigVcnPairs || ConfigVcnPairs->Extents[0].Lcn.QuadPart == -1) // 配置文件不支持压缩
		return STATUS_UNSUCCESSFUL;

	ULONG sectorsPerCluster = ConfigVolume.BytesPerCluster / ConfigVolume.BytesPerSector;
	NTSTATUS status = STATUS_SUCCESS;

	ULONG	Cls, r;
	LARGE_INTEGER	PrevVCN = ConfigVcnPairs->StartingVcn;
	ULONG SectorOffset = 0;
	for (r = 0, Cls = 0; r < ConfigVcnPairs->ExtentCount; r++)
	{
		ULONG	CnCount;
		LARGE_INTEGER Lcn = ConfigVcnPairs->Extents[r].Lcn;

		for (CnCount = (ULONG)(ConfigVcnPairs->Extents[r].NextVcn.QuadPart - PrevVCN.QuadPart);
			CnCount; CnCount--, Cls++, Lcn.QuadPart++)
		{
			ULONGLONG	i = 0;
			ULONGLONG	base = ConfigVolume.FirstDataSector + (Lcn.QuadPart * sectorsPerCluster);
			for (i = 0; i < sectorsPerCluster; i++)
			{
				ULONG CurOffset = SectorOffset * ConfigVolume.BytesPerSector;
				if (CurOffset > sizeof(DISKFILTER_PROTECTION_CONFIG))
					continue;
				ULONGLONG DiskOffset = ConfigVolume.StartOffset + (base + i) * ConfigVolume.BytesPerSector;
				status = FastFsdRequest(LowerDeviceObject[ConfigVolume.DiskNumber], IRP_MJ_WRITE, DiskOffset, (PUCHAR)ConfigData + CurOffset, min(ConfigVolume.BytesPerSector, sizeof(DISKFILTER_PROTECTION_CONFIG) - CurOffset), TRUE);
				if (!NT_SUCCESS(status))
					return status;
				SectorOffset++;
			}
		}
		PrevVCN = ConfigVcnPairs->Extents[r].NextVcn;
	}
	return status;
}

// 初始化卷的位图信息
NTSTATUS InitVolumeLogicBitmap(PVOLUME_INFO volumeInfo)
{
	NTSTATUS status;
	PVOLUME_BITMAP_BUFFER Bitmap = NULL;

	// 逻辑位图大小
	ULONGLONG logicBitMapMaxSize = 0;

	ULONG SectorsPerCluster = 0;

	ULONGLONG i = 0;

	SectorsPerCluster = volumeInfo->BytesPerCluster / volumeInfo->BytesPerSector;

	// 获取此卷上有多少个扇区, 用bytesTotal这个比较准确，如果用其它的比如fsinfo,会少几个扇区发现
	volumeInfo->SectorCount = volumeInfo->BytesTotal / volumeInfo->BytesPerSector;

	// 得到逻辑位图的大小bytes
	logicBitMapMaxSize = (volumeInfo->SectorCount / 8) + 1;

	// 上次扫描的空闲簇的位置
	volumeInfo->LastScanIndex = 0;

	// 以扇区为单位的位图
	if (!NT_SUCCESS(DPBitmap_Create(&volumeInfo->BitmapRedirect, volumeInfo->SectorCount, BITMAP_SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto out;
	}

	// 以扇区为单位的位图
	if (!NT_SUCCESS(DPBitmap_Create(&volumeInfo->BitmapRedirectUsed, volumeInfo->SectorCount, BITMAP_SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto out;
	}

	// 以扇区为单位的位图
	if (!NT_SUCCESS(DPBitmap_Create(&volumeInfo->BitmapAllow, volumeInfo->SectorCount, BITMAP_SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto out;
	}

	// 以扇区为单位的位图, 如果一次申请内存过大，会失败，用dpbitmap申请不连续的内存
	if (!NT_SUCCESS(DPBitmap_Create(&volumeInfo->BitmapUsed, volumeInfo->SectorCount, BITMAP_SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto out;
	}

	// 正式簇开始前的簇都标记为已使用
	for (i = 0; i < volumeInfo->FirstDataSector; i++)
	{
		DPBitmap_Set(volumeInfo->BitmapUsed, i, TRUE);
	}

	// 获取位图
	status = GetVolumeBitmapInfo(volumeInfo->DiskNumber, volumeInfo->PartitionNumber, &Bitmap);

	if (!NT_SUCCESS(status))
	{
		goto out;
	}

	// 初始化位图
	for (i = 0; i < (ULONGLONG)Bitmap->BitmapSize.QuadPart; i++)
	{
		if (bitmap_test((PULONG)Bitmap->Buffer, i))
		{
			ULONGLONG j = 0;
			ULONGLONG base = volumeInfo->FirstDataSector + (i * SectorsPerCluster);
			for (j = 0; j < SectorsPerCluster; j++)
			{
				status = DPBitmap_Set(volumeInfo->BitmapUsed, base + j, TRUE);
				if (!NT_SUCCESS(status))
				{
					goto out;
				}
			}
		}
	}

	// 初始化重定向列表
	RedirectTable_Init(&volumeInfo->RedirectMap);

	if (AllowDirectMount)
	{
		// 初始化反向重定向列表
		RedirectTable_Init(&volumeInfo->ReverseRedirectMap);
	}

	status = STATUS_SUCCESS;

out:

	if (!NT_SUCCESS(status))
	{
		DPBitmap_Free(volumeInfo->BitmapRedirect);
		volumeInfo->BitmapRedirect = NULL;
		DPBitmap_Free(volumeInfo->BitmapRedirectUsed);
		volumeInfo->BitmapRedirectUsed = NULL;
		DPBitmap_Free(volumeInfo->BitmapAllow);
		volumeInfo->BitmapAllow = NULL;
		DPBitmap_Free(volumeInfo->BitmapUsed);
		volumeInfo->BitmapUsed = NULL;
	}
	if (Bitmap)
		__free(Bitmap);

	return status;
}

// 设置文件数据直接读写
NTSTATUS SetDirectReadWriteFile(PVOLUME_INFO volume, PWCHAR path)
{
	if (volume == NULL)
		return STATUS_UNSUCCESSFUL;

	WCHAR tempBuffer[MAX_PATH];
	swprintf_s(tempBuffer, MAX_PATH, L"\\Device\\Harddisk%d\\Partition%d%ls", volume->DiskNumber, volume->PartitionNumber, path);
	UNICODE_STRING target;
	RtlInitUnicodeString(&target, tempBuffer);
	HANDLE fileHandle = (HANDLE)-1;
	NTSTATUS status = GetFileHandleReadOnly(&fileHandle, &target);
	if (!NT_SUCCESS(status))
	{
		goto out;
	}

	ULONG sectorsPerCluster = volume->BytesPerCluster / volume->BytesPerSector;

	PRETRIEVAL_POINTERS_BUFFER pVcnPairs = (PRETRIEVAL_POINTERS_BUFFER)GetFileClusterList(fileHandle);

	if (!pVcnPairs || pVcnPairs->Extents[0].Lcn.QuadPart == -1) // 不支持被压缩的文件
	{
		LogInfo("Failed to get file cluster list, file compressed?\n");
		status = STATUS_UNSUCCESSFUL;
		goto out;
	}

	ULONGLONG PrevVCN = pVcnPairs->StartingVcn.QuadPart;
	for (ULONG r = 0; r < pVcnPairs->ExtentCount; r++)
	{
		ULONGLONG NextVCN = pVcnPairs->Extents[r].NextVcn.QuadPart;
		ULONG CnCount = (ULONG)(NextVCN - PrevVCN);
		ULONGLONG Lcn = pVcnPairs->Extents[r].Lcn.QuadPart;
		ULONGLONG EndLcn = Lcn + CnCount - 1;
		LogInfo("Cluster %llu -> %llu (Sector %llu -> %llu) is allowed to direct write.\n", Lcn, EndLcn, volume->FirstDataSector + Lcn * sectorsPerCluster, volume->FirstDataSector + EndLcn * sectorsPerCluster);

		for (; CnCount; CnCount--, Lcn++)
		{
			ULONGLONG base = volume->FirstDataSector + (Lcn * sectorsPerCluster);
			for (ULONG i = 0; i < sectorsPerCluster; i++)
			{
				// 设置位图
				DPBitmap_Set(volume->BitmapAllow, base + i, TRUE);
				DPBitmap_Set(volume->BitmapUsed, base + i, TRUE);
			}
		}

		PrevVCN = NextVCN;
	}

	__free(pVcnPairs);

out:
	if ((HANDLE)-1 != fileHandle)
		ZwClose(fileHandle);

	if (!NT_SUCCESS(status))
	{
		LogWarn("Failed to set direct read/write for file (%d,%d):%ls. Status=0x%.8X\n", volume->DiskNumber, volume->PartitionNumber, path, status);
	}
	else
	{
		LogInfo("Successfully set direct read/write for file (%d,%d):%ls.\n", volume->DiskNumber, volume->PartitionNumber, path);
	}
	return status;
}

// 初始化卷的直接读写列表
void InitVolumeAllowList(PVOLUME_INFO volumeInfo)
{
	// 放过这几个文件的直接读写

	// bootstat.dat如果不让写，下次启动会显示非正常启动
	SetDirectReadWriteFile(volumeInfo, L"\\Windows\\bootstat.dat");

	// 分页文件
	SetDirectReadWriteFile(volumeInfo, L"\\pagefile.sys");

	// 交换文件
	SetDirectReadWriteFile(volumeInfo, L"\\swapfile.sys");

	// 解冻空间
	if (Config.ProtectionFlags & PROTECTION_ENABLE_THAWSPACE)
	{
		for (UCHAR i = 0; i < Config.ThawSpaceCount; i++)
		{
			if (!(Config.ThawSpacePath[i][MAX_PATH] & DISKFILTER_THAWSPACE_HIDE) && toupper(Config.ThawSpacePath[i][0]) == volumeInfo->Volume)
			{
				if (!NT_SUCCESS(SetDirectReadWriteFile(volumeInfo, Config.ThawSpacePath[i] + 2)))
				{
					LogErrorMessageWithString(FilterDevice, MSG_THAWSPACE_LOAD_FAILED, Config.ThawSpacePath[i], (ULONG)wcslen(Config.ThawSpacePath[i]));
				}
			}
		}
	}
}

// 根据硬盘号和分区号获取保护卷
PVOLUME_INFO FindProtectVolume(ULONG DiskNum, DWORD PartitionNum)
{
	for (UINT i = 0; i < ValidVolumeCount; i++)
	{
		if (ProtectVolumeList[i].DiskNumber == DiskNum && ProtectVolumeList[i].PartitionNumber == PartitionNum)
			return &(ProtectVolumeList[i]);
	}
	return NULL;
}

// 根据设备对象获取保护卷
PVOLUME_INFO FindProtectVolumeByDevice(PDEVICE_OBJECT VolumeDevice)
{
	for (UINT i = 0; i < ValidVolumeCount; i++)
	{
		if (ProtectVolumeList[i].VolumeDevice == VolumeDevice)
			return &(ProtectVolumeList[i]);
	}
	return NULL;
}

// 初始化盘符（更改保护卷图标、初始化卷的允许直接读写列表）
void InitVolumeLetter()
{
	for (WCHAR i = L'C'; i <= L'Z'; i++)
	{
		ULONG DiskNum = 0;
		DWORD PartitionNum = 0;
		if (NT_SUCCESS(GetPartNumFromVolLetter(i, &DiskNum, &PartitionNum)))
		{
			LogInfo("%c -> disk %lu partition %lu\n", i, DiskNum, PartitionNum);
			PVOLUME_INFO VolInfo = FindProtectVolume(DiskNum, PartitionNum);
			if (VolInfo)
			{
				if (VolInfo->Volume)
				{
					// 已经初始化过的卷就不用再初始化了
					LogInfo("Is a initialized partition\n");
					ChangeDriveIconProtect(i);
					continue;
				}
				VolInfo->Volume = i;
				VolumeList[i - L'A'] = VolInfo;
				InitVolumeAllowList(VolInfo);
				ChangeDriveIconProtect(i);
			}
			else
			{
				LogInfo("Is not a protected volume\n");
			}
		}
	}
	LogInfo("Volume letter initialization finished\n");
}

// 获取硬盘信息
NTSTATUS GetDiskInfo(ULONG DiskNum, PDISK_INFO info)
{
	NTSTATUS status;
	HANDLE fileHandle;
	UNICODE_STRING fileName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK IoStatusBlock;

	WCHAR diskName[MAX_PATH];

	RtlZeroMemory(info, sizeof(DISK_INFO));

	swprintf_s(diskName, MAX_PATH, L"\\Device\\Harddisk%d\\Partition0", DiskNum);

	RtlInitUnicodeString(&fileName, diskName);

	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	if (NT_SUCCESS(status))
	{
		IO_STATUS_BLOCK				ioBlock;
		DISK_GEOMETRY				diskGeometry;
		GET_LENGTH_INFORMATION		diskLength;
		PDRIVE_LAYOUT_INFORMATION_EX pInfo;
		ULONG InfoSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX);

		status = ZwDeviceIoControlFile(fileHandle,
			NULL,
			NULL,
			NULL,
			&ioBlock,
			IOCTL_DISK_GET_DRIVE_GEOMETRY,
			NULL,
			0,
			&diskGeometry,
			sizeof(diskGeometry)
		);

		if (!NT_SUCCESS(status))
		{
			ZwClose(fileHandle);
			LogWarn("Failed to read disk geometry for disk %lu, error code = 0x%.8X\n", DiskNum, status);
			return status;
		}

		status = ZwDeviceIoControlFile(fileHandle,
			NULL,
			NULL,
			NULL,
			&ioBlock,
			IOCTL_DISK_GET_LENGTH_INFO,
			NULL,
			0,
			&diskLength,
			sizeof(diskLength)
		);

		if (!NT_SUCCESS(status))
		{
			ZwClose(fileHandle);
			LogWarn("Failed to read disk length for disk %lu, error code = 0x%.8X\n", DiskNum, status);
			return status;
		}

		do
		{
			InfoSize += sizeof(PARTITION_INFORMATION_EX);

			pInfo = (PDRIVE_LAYOUT_INFORMATION_EX)__malloc(InfoSize);
			if (!pInfo)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			status = ZwDeviceIoControlFile(fileHandle,
				NULL,
				NULL,
				NULL,
				&ioBlock,
				IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
				NULL,
				0,
				pInfo,
				InfoSize
			);

			if (status == STATUS_BUFFER_TOO_SMALL)
				__free(pInfo);
		} while (status == STATUS_BUFFER_TOO_SMALL);

		ZwClose(fileHandle);

		if (!NT_SUCCESS(status))
		{
			if (pInfo)
				__free(pInfo);

			LogWarn("Failed to get drive layout for disk %lu, error code = 0x%.8X\n", DiskNum, status);
			return status;
		}

		info->BytesPerSector = diskGeometry.BytesPerSector;
		info->SectorCount = diskLength.Length.QuadPart / diskGeometry.BytesPerSector;
		// 以扇区为单位的位图
		if (!NT_SUCCESS(DPBitmap_Create(&info->BitmapDeny, info->SectorCount, BITMAP_SLOT_SIZE)))
		{
			if (pInfo)
				__free(pInfo);

			return STATUS_UNSUCCESSFUL;
		}
		DPBitmap_Set(info->BitmapDeny, 0, TRUE);
		if (pInfo->PartitionStyle == PARTITION_STYLE_MBR)
		{
			LogInfo("Disk %lu is MBR style\n", DiskNum);
			ULONGLONG FirstSector = (ULONGLONG)-1;
			for (ULONG i = 0; i < pInfo->PartitionCount; i++)
			{
				if (pInfo->PartitionEntry[i].Mbr.PartitionType == PARTITION_ENTRY_UNUSED)
					continue;
				DWORD PartitionNum = pInfo->PartitionEntry[i].PartitionNumber;
				ULONGLONG StartSector = pInfo->PartitionEntry[i].StartingOffset.QuadPart / diskGeometry.BytesPerSector;
				FirstSector = min(FirstSector, StartSector);
				if (PartitionNum != 0)
					continue;
				if (IsContainerPartition(pInfo->PartitionEntry[i].Mbr.PartitionType))
				{
					LogInfo("Found extend partition in sector %llu\n", StartSector);
					DPBitmap_Set(info->BitmapDeny, StartSector, TRUE);
				}
			}
			if (FirstSector != -1)
			{
				LogInfo("First partition start sector %llu\n", FirstSector);
				for (ULONGLONG i = 0; i < FirstSector; i++)
				{
					DPBitmap_Set(info->BitmapDeny, i, TRUE);
				}
			}
		}
		else if (pInfo->PartitionStyle == PARTITION_STYLE_GPT)
		{
			LogInfo("Disk %lu is GPT style\n", DiskNum);
			for (ULONGLONG i = 0; i < 34; i++)
			{
				DPBitmap_Set(info->BitmapDeny, i, TRUE);
				DPBitmap_Set(info->BitmapDeny, info->SectorCount - i - 1, TRUE);
			}
		}
		else
		{
			LogInfo("Unknown disk %lu style\n", DiskNum);
		}

		if (pInfo)
			__free(pInfo);
	}
	else
	{
		LogWarn("Failed to open the disk %wZ, error code = 0x%.8X\n", &fileName, status);
	}

	return status;
}

// 初始化保护硬盘
void InitProtectDisks()
{
	for (UCHAR i = 0; i < Config.ProtectVolumeCount; i++)
	{
		USHORT DiskNum = DISKFILTER_DISKNUM_FROM_VOLNUM(Config.ProtectVolume[i]);
		if (DiskNum >= sizeof(ProtectDiskList) / sizeof(*ProtectDiskList))
			continue;
		if (ProtectDiskList[DiskNum].BitmapDeny)
			continue;
		LogInfo("Protected disk: %hu\n", DiskNum);
		if (NT_SUCCESS(GetDiskInfo(DiskNum, &ProtectDiskList[DiskNum])))
		{
			LogInfo("Found valid disk %hu\n", DiskNum);
		}
	}
}

// 初始化保护卷（获取保护卷信息、获取位图）
void InitProtectVolumes()
{
	WCHAR strMsg[512]; // 临时变量，放在此处缩小栈空间
	for (UCHAR i = 0; i < Config.ProtectVolumeCount; i++)
	{
		USHORT DiskNum = DISKFILTER_DISKNUM_FROM_VOLNUM(Config.ProtectVolume[i]);
		USHORT PartitionNum = DISKFILTER_PARTNUM_FROM_VOLNUM(Config.ProtectVolume[i]);
		LogInfo("Protected volume: disk %hu partition %hu\n", DiskNum, PartitionNum);

		PVOLUME_INFO VolInfo = FindProtectVolume(DiskNum, PartitionNum);
		if (VolInfo)
		{
			LogInfo("Is a initialized volume\n");
			continue;
		}

		UINT Cur = ValidVolumeCount;
		memset(&ProtectVolumeList[Cur], 0, sizeof(ProtectVolumeList[Cur]));
		if (NT_SUCCESS(GetVolumeInfo(DiskNum, PartitionNum, &ProtectVolumeList[Cur])))
		{
			LogInfo("Found valid volume on disk %hu partition %hu\n", DiskNum, PartitionNum);
			//初始化这个卷的请求处理队列
			InitializeListHead(&ProtectVolumeList[Cur].ListHead);
			//初始化请求处理队列的锁
			KeInitializeSpinLock(&ProtectVolumeList[Cur].ListLock);
			//初始化请求处理队列的同步事件
			KeInitializeEvent(
				&ProtectVolumeList[Cur].RequestEvent,
				SynchronizationEvent,
				FALSE
			);
			//初始化终止处理线程标志
			ProtectVolumeList[Cur].ThreadTerminate = FALSE;
			//初始化保存数据相关变量
			KeInitializeEvent(&ProtectVolumeList[Cur].FinishSaveDataEvent, SynchronizationEvent, FALSE);
			ProtectVolumeList[Cur].CanSaveData = FALSE;
			ProtectVolumeList[Cur].ShutdownSaveData = FALSE;
			ProtectVolumeList[Cur].SavingData = FALSE;
			//建立用来处理这个卷的请求的处理线程，线程函数的参数则是指向卷信息的指针
			HANDLE ThreadHandle = NULL;
			NTSTATUS status = PsCreateSystemThread(
				&ThreadHandle,
				(ACCESS_MASK)0L,
				NULL,
				NULL,
				&ProtectVolumeList[Cur].ReadWriteThreadId,
				ThreadReadWrite,
				&ProtectVolumeList[Cur]
			);
			if (NT_SUCCESS(status))
			{
				if (NT_SUCCESS(InitVolumeLogicBitmap(&ProtectVolumeList[Cur])))
				{
					LogInfo("Successfully get volume logic bitmap\n");
					// 只有在成功获取位图之后，才认为这个卷有效
					ProtectVolumeList[Cur].CanSaveData = TRUE;
					InterlockedExchange8((PCHAR)&ProtectVolumeList[Cur].Protect, TRUE);
					InterlockedIncrement((PLONG)&ValidVolumeCount);
					swprintf_s(strMsg, 512, L"(%hu,%hu)", DiskNum, PartitionNum);
					LogErrorMessageWithString(FilterDevice, MSG_PROTECT_VOLUME_LOAD_OK, strMsg, (ULONG)wcslen(strMsg));
				}
				else
				{
					ProtectVolumeList[Cur].ThreadTerminate = TRUE;
					KeSetEvent(
						&ProtectVolumeList[Cur].RequestEvent,
						(KPRIORITY)0,
						FALSE
					);
					// 等待线程结束以防止初始化下一个卷时覆盖数据导致蓝屏
					KeWaitForSingleObject(
						&ProtectVolumeList[Cur].FinishSaveDataEvent,
						Executive,
						KernelMode,
						FALSE,
						NULL
					);
					LogInfo("Failed to get volume logic bitmap\n");
					swprintf_s(strMsg, 512, L"(%hu,%hu)", DiskNum, PartitionNum);
					LogErrorMessageWithString(FilterDevice, MSG_PROTECT_VOLUME_LOAD_FAILED, strMsg, (ULONG)wcslen(strMsg));
				}

				if (NULL != ThreadHandle)
					ZwClose(ThreadHandle);
			}
			else
			{
				LogInfo("Failed to create handler thread\n");
				swprintf_s(strMsg, 512, L"(%hu,%hu)", DiskNum, PartitionNum);
				LogErrorMessageWithString(FilterDevice, MSG_PROTECT_VOLUME_LOAD_FAILED, strMsg, (ULONG)wcslen(strMsg));
			}
		}
	}
	LogInfo("ValidVolumeCount = %u\n", ValidVolumeCount);

	InitVolumeLetter();
}

// 开始保护
void StartProtect()
{
	LogInfo("Starting protect\n");
	InterlockedExchange8((PCHAR)&IsProtect, TRUE);
}

// 挂载解冻空间
void InitThawSpace()
{
	PDRIVER_OBJECT DriverObject = FilterDevice->DriverObject;
	PDEVICE_OBJECT CurDevice = DriverObject->DeviceObject;
	for (UCHAR i = 0; i < Config.ThawSpaceCount; i++)
	{
		while (CurDevice != NULL && !IsThawSpaceDevice(CurDevice))
			CurDevice = CurDevice->NextDevice;

		if (CurDevice == NULL)
			break;

		ThawSpaceCloseFile(CurDevice);
		Config.ThawSpacePath[i][MAX_PATH - 1] = L'\0';
		WCHAR TCfg = Config.ThawSpacePath[i][MAX_PATH];
		const WCHAR prefix[] = L"\\??\\";
		if (!(TCfg & DISKFILTER_THAWSPACE_HIDE))
		{
			BOOL Success = FALSE;
			POPEN_FILE_INFORMATION ofn = (POPEN_FILE_INFORMATION)__malloc(sizeof(OPEN_FILE_INFORMATION) + sizeof(Config.ThawSpacePath[i]) + wcslen(prefix) * sizeof(WCHAR));
			if (ofn)
			{
				ofn->DriveLetter = TCfg;
				RtlCopyMemory(ofn->FileName, prefix, wcslen(prefix) * sizeof(WCHAR));
				RtlCopyMemory(ofn->FileName + wcslen(prefix), Config.ThawSpacePath[i], MAX_PATH * sizeof(WCHAR));
				ofn->FileNameLength = (USHORT)wcslen(ofn->FileName);
				ofn->FileSize.QuadPart = *(ULONGLONG*)&Config.ThawSpacePath[i][MAX_PATH + 1];
				ofn->ReadOnly = FALSE;
				if (NT_SUCCESS(ThawSpaceOpenFile(CurDevice, ofn)))
				{
					Success = TRUE;
				}
				__free(ofn);
				CurDevice = CurDevice->NextDevice;
			}
			if (Success)
			{
				LogErrorMessageWithString(FilterDevice, MSG_THAWSPACE_LOAD_OK, Config.ThawSpacePath[i], (ULONG)wcslen(Config.ThawSpacePath[i]));
			}
			else
			{
				LogErrorMessageWithString(FilterDevice, MSG_THAWSPACE_LOAD_FAILED, Config.ThawSpacePath[i], (ULONG)wcslen(Config.ThawSpacePath[i]));
			}
		}
		else
		{
			PFILE_OBJECT FileObject;
			IO_STATUS_BLOCK IoStatus;
			UNICODE_STRING FilePath;
			RtlInitUnicodeString(&FilePath, Config.ThawSpacePath[i]);
			IrpCreateFile(&FileObject, FILE_ALL_ACCESS, &FilePath, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NO_INTERMEDIATE_BUFFERING, NULL, 0);
			LogErrorMessageWithString(FilterDevice, MSG_THAWSPACE_HIDE, Config.ThawSpacePath[i], (ULONG)wcslen(Config.ThawSpacePath[i]));
		}
	}
}

// 检查解冻空间是否需要被初始化
void CheckThawSpace()
{
	if (Config.ProtectionFlags & PROTECTION_ENABLE_THAWSPACE)
	{
		BOOL FileChanged = FALSE;
		BOOL ConfigChanged = FALSE;
		BOOL NeedInit = FALSE;
		for (UCHAR i = 0; i < Config.ThawSpaceCount; i++)
		{
			// 检查上次初始化标记
			if (Config.ThawSpacePath[i][0] & DISKFILTER_THAWSPACE_HIDE)
			{
				Config.ThawSpacePath[i][0] &= ~DISKFILTER_THAWSPACE_HIDE;
				ConfigChanged = TRUE;
				continue;
			}
			const WCHAR prefix[] = L"\\??\\";
			PWCHAR FileName = (PWCHAR)__malloc((wcslen(prefix) + MAX_PATH + 1) * sizeof(WCHAR));
			if (FileName)
			{
				RtlCopyMemory(FileName, prefix, wcslen(prefix) * sizeof(WCHAR));
				RtlCopyMemory(FileName + wcslen(prefix), Config.ThawSpacePath[i], MAX_PATH * sizeof(WCHAR));
				UNICODE_STRING file_name;
				RtlInitUnicodeString(&file_name, FileName);
				ULONGLONG FileSize = *(ULONGLONG*)&Config.ThawSpacePath[i][MAX_PATH + 1];
				OBJECT_ATTRIBUTES object_attributes;
				InitializeObjectAttributes(
					&object_attributes,
					&file_name,
					OBJ_CASE_INSENSITIVE,
					NULL,
					NULL
				);

				HANDLE file_handle;
				IO_STATUS_BLOCK io_status;
				NTSTATUS status = ZwCreateFile(
					&file_handle,
					GENERIC_READ | GENERIC_WRITE,
					&object_attributes,
					&io_status,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					0,
					FILE_OPEN,
					FILE_NON_DIRECTORY_FILE |
					/*FILE_RANDOM_ACCESS |
					FILE_NO_INTERMEDIATE_BUFFERING |
					*/FILE_SYNCHRONOUS_IO_NONALERT,
					NULL,
					0
				);
				if (NT_SUCCESS(status))
				{
					ZwClose(file_handle);
				}
				else if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_NO_SUCH_FILE)
				{
					if (!NeedInit)
					{
						if (!DisableStartupMessage)
							InitDisplay();
						DisplayString(L"DiskFilter is initializing ThawSpace...\nPlease do not shut down or restart the computer.\n");
						NeedInit = TRUE;
					}
					status = ZwCreateFile(
						&file_handle,
						GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
						&object_attributes,
						&io_status,
						NULL,
						FILE_ATTRIBUTE_NORMAL,
						0,
						FILE_OPEN_IF,
						FILE_NON_DIRECTORY_FILE |
						/*FILE_RANDOM_ACCESS |*/
						FILE_NO_INTERMEDIATE_BUFFERING |
						FILE_SYNCHRONOUS_IO_NONALERT,
						NULL,
						0
					);
					if (NT_SUCCESS(status))
					{
						if (io_status.Information == FILE_CREATED)
						{
							LogInfo("ThawSpace %wZ: File not found, initializing disk file.\n", &file_name);
							WCHAR VolumeLetter = (WCHAR)(((USHORT)Config.ThawSpacePath[i][MAX_PATH]) & ~DISKFILTER_THAWSPACE_HIDE);
							// 写入初始化标记，防止因为错误导致无限重启初始化
							Config.ThawSpacePath[i][0] |= DISKFILTER_THAWSPACE_HIDE;
							WCHAR Buf[256];
							swprintf_s(Buf, 256, L"Initializing ThawSpace volume %lc", VolumeLetter);
							DisplayString(Buf);
							{
								LogInfo("Initializating disk file with size %llu\n", FileSize);
								// TODO: 修改初始化方式，不要填充磁盘
								FILE_END_OF_FILE_INFORMATION file_eof;
								file_eof.EndOfFile.QuadPart = FileSize;
								status = ZwSetInformationFile(
									file_handle,
									&io_status,
									&file_eof,
									sizeof(FILE_END_OF_FILE_INFORMATION),
									FileEndOfFileInformation
								);
								LARGE_INTEGER Offset = { 0 };
								ULONG BufferSize = 20 * 1024 * 1024; // 20MB
								PUCHAR Buffer = (PUCHAR)__malloc(BufferSize);
								memset(Buffer, 0, BufferSize);
								ULONGLONG Cur = 0;
								int LastProgress = -1;
								while (Cur < FileSize)
								{
									ULONG WriteSize = (ULONG)min(BufferSize, FileSize - Cur);
									Offset.QuadPart = Cur;
									ZwWriteFile(file_handle, NULL, NULL, NULL, &io_status, Buffer, WriteSize, &Offset, NULL);
									Cur += WriteSize;
									int CurProgress = int(100 * Cur / FileSize);
									if (LastProgress != CurProgress)
									{
										LastProgress = CurProgress;
										swprintf_s(Buf, 256, L"\rInitializing ThawSpace volume %c... Progress: %d%%", VolumeLetter, CurProgress);
										DisplayString(Buf);
									}
								}
								__free(Buffer);
								LogInfo("Fill file ok\n");

								FormatFAT32FileSystem(file_handle, FileSize, "ThawSpace");
								wcscpy(Buf, L"\rFinished initializing ThawSpace volume ?          \n");
								*wcsrchr(Buf, L'?') = VolumeLetter;
								DisplayString(Buf);
							}
							FileChanged = TRUE;
							ConfigChanged = TRUE;
						}
						ZwClose(file_handle);
					}
				}
			}
		}

		if (ConfigChanged)
		{
			WriteProtectionConfig(&Config);
			RtlCopyMemory(&NewConfig, &Config, sizeof(Config));
		}

		if (FileChanged)
		{
			DisplayString(L"Initialization finished.\n");
			if (*NtBuildNumber <= 3790) // 直接重新启动会在Windows XP上提示未正常关闭，删除bootstat.dat文件后再重新启动
				SafeReboot();
			else
				NtShutdownSystem(1);
		}
	}
}

// 判断扇区是否允许直接操作
__inline BOOL IsSectorAllow(PVOLUME_INFO volumeInfo, ULONGLONG index)
{
	if (index < volumeInfo->FirstDataSector)
	{
		return FALSE;
	}

	return DPBitmap_Test(volumeInfo->BitmapAllow, index);
}

// 判断文件是否可信（文件扇区是否未被重定向）
NTSTATUS IsFileCreditable(PUNICODE_STRING filePath)
{
	PRETRIEVAL_POINTERS_BUFFER	pVcnPairs = NULL;
	PVOLUME_INFO	volumeInfo = NULL;
	ULONG	sectorsPerCluster;

	BOOLEAN	IsCreditable = FALSE;

	HANDLE fileHandle = (HANDLE)-1;
	NTSTATUS status = GetFileHandleReadOnly(&fileHandle, filePath);

	if (!NT_SUCCESS(status))
	{
		LogWarn("Failed to open file: %wZ, error code 0x%.8X\n", filePath, status);
		goto out;
	}

	volumeInfo = FindProtectVolumeByDevice(GetVolumeDeviceByFileHandle(fileHandle));

	if (!volumeInfo)
	{
		LogWarn("Failed to get the volume information for file: %wZ\n", filePath);
		goto out;
	}

	sectorsPerCluster = volumeInfo->BytesPerCluster / volumeInfo->BytesPerSector;
	
	pVcnPairs = (PRETRIEVAL_POINTERS_BUFFER)GetFileClusterList(fileHandle);
	ZwClose(fileHandle);

	if (NULL == pVcnPairs)
	{
		LogWarn("Failed to get the cluster list for file: %wZ\n", filePath);
		goto out;
	}
	
	if (pVcnPairs->Extents[0].Lcn.QuadPart == -1) // 最新版win11上的驱动都被压缩了，需要打开文件的压缩数据
	{
		LogInfo("Compressed file: %wZ, trying to get WofCompressedData\n", filePath);
		__free(pVcnPairs);
		fileHandle = (HANDLE)-1;
		WCHAR append[] = L":WofCompressedData:$DATA";
		UNICODE_STRING filePathNew = { 0 };
		if (NT_SUCCESS(RtlAllocateUnicodeString(&filePathNew, filePath->Length + sizeof(append))))
		{
			if (NT_SUCCESS(RtlAppendUnicodeStringToString(&filePathNew, filePath)) &&
				NT_SUCCESS(RtlAppendUnicodeToString(&filePathNew, append))
				)
			{
				AdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE);
				OBJECT_ATTRIBUTES oa;
				IO_STATUS_BLOCK IoStatusBlock;

				InitializeObjectAttributes(&oa,
					&filePathNew,
					OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
					NULL,
					NULL);

				status = ZwCreateFile(&fileHandle,
					FILE_READ_ATTRIBUTES | SYNCHRONIZE,
					&oa,
					&IoStatusBlock,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ,
					FILE_OPEN,
					FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
					NULL,
					0);

				if (!NT_SUCCESS(status))
				{
					LogWarn("Failed to open file: %wZ, error code 0x%.8X\n", &filePathNew, status);
					__free(filePathNew.Buffer);
					goto out;
				}
			}
			__free(filePathNew.Buffer);
		}
		if (fileHandle == (HANDLE)-1)
		{
			LogWarn("Compressed file: %wZ, failed to get WofCompressedData\n", filePath);
			goto out;
		}
		pVcnPairs = (PRETRIEVAL_POINTERS_BUFFER)GetFileClusterList(fileHandle);
		ZwClose(fileHandle);
		if (NULL == pVcnPairs)
		{
			LogWarn("Failed to get the cluster list for file: %wZ\n", filePath);
			goto out;
		}
	}

	ULONGLONG PrevVCN = pVcnPairs->StartingVcn.QuadPart;
	for (ULONG r = 0; r < pVcnPairs->ExtentCount; r++)
	{
		ULONGLONG NextVCN = pVcnPairs->Extents[r].NextVcn.QuadPart;
		ULONG CnCount = (ULONG)(NextVCN - PrevVCN);
		ULONGLONG Lcn = pVcnPairs->Extents[r].Lcn.QuadPart;

		for (; CnCount; CnCount--, Lcn++)
		{
			ULONGLONG base = volumeInfo->FirstDataSector + (Lcn * sectorsPerCluster);
			for (ULONG i = 0; i < sectorsPerCluster; i++)
			{
				// 此扇区被重定向了或允许直接写入（例如覆盖bootstat.dat）, 不可信文件, 终止认证
				if (base + i >= volumeInfo->SectorCount || DPBitmap_Test(volumeInfo->BitmapRedirect, base + i) || IsSectorAllow(volumeInfo, base + i))
				{
					LogInfo("File %wZ sector %llu has been redirected or allow direct write\n", filePath, base + i);
					goto __exit;
				}
			}
		}
		PrevVCN = NextVCN;
	}

	// 经过考验
	IsCreditable = TRUE;

__exit:
	__free(pVcnPairs);

out:
	return IsCreditable ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

// 获取真实需要读取的扇区
ULONGLONG GetRealSectorForRead(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex, PULONGLONG nextCount)
{
	ULONGLONG	mapIndex = orgIndex;

	if (nextCount)
		*nextCount = 0;

	// 此扇区是否允许直接操作
	if (IsSectorAllow(volumeInfo, orgIndex))
	{
		return orgIndex;
	}

	// 此扇区是否已经被重定向
	if (DPBitmap_Test(volumeInfo->BitmapRedirect, orgIndex))
	{
		// 找到重定向到哪里, 并返回
		RedirectTable_Lookup(&volumeInfo->RedirectMap, orgIndex, &mapIndex, nextCount, NULL);
	}
	return mapIndex;
}

// 添加重定向记录
__inline void AddRedirectRecord(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex, ULONGLONG realIndex, ULONGLONG sectorCount)
{
	RedirectTable_Insert(&volumeInfo->RedirectMap, orgIndex, realIndex, sectorCount, NULL);
	if (AllowDirectMount)
		RedirectTable_Insert(&volumeInfo->ReverseRedirectMap, realIndex, orgIndex, sectorCount, NULL);
}

// 更新重定向记录 把重定向到orgIndex的记录修改为realIndex（realIndex等于-1时删除记录）
void UpdateRedirectRecord(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex, ULONGLONG realIndex, ULONG sectorCount)
{
	ULONGLONG prevStart = (ULONGLONG)-1;
	ULONGLONG prevSector = (ULONGLONG)-1;
	ULONGLONG sectorOffset = 0;
	for (ULONG i = 0; i < sectorCount; i++)
	{
		ULONGLONG mapIndex = (ULONGLONG)-1;
		RedirectTable_Lookup(&volumeInfo->ReverseRedirectMap, orgIndex + i, &mapIndex, NULL, NULL);
		if (mapIndex != -1)
		{
			if (prevSector == -1 || mapIndex != prevSector + 1)
			{
				if (prevStart != -1 && prevSector != -1)
				{
					RedirectTable_Delete(&volumeInfo->RedirectMap, prevStart, prevSector - prevStart + 1);
					if (realIndex != -1)
						AddRedirectRecord(volumeInfo, prevStart, realIndex + sectorOffset, prevSector - prevStart + 1);
				}
				prevStart = mapIndex;
				sectorOffset = i;
			}
		}
		prevSector = mapIndex;
	}
	if (prevStart != -1 && prevSector != -1)
	{
		RedirectTable_Delete(&volumeInfo->RedirectMap, prevStart, prevSector - prevStart + 1);
		if (realIndex != -1)
			AddRedirectRecord(volumeInfo, prevStart, realIndex + sectorOffset, prevSector - prevStart + 1);
	}
	RedirectTable_Delete(&volumeInfo->ReverseRedirectMap, orgIndex, sectorCount);
}

// 获取真实需要写入的扇区
ULONGLONG GetRealSectorForWrite(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex, PULONGLONG nextCount, PBOOLEAN needRedirect)
{
	ULONGLONG	mapIndex = (ULONGLONG)-1;

	if (nextCount)
		*nextCount = 0;

	*needRedirect = FALSE; // 默认不修改重定向表

	// 此扇区是否允许直接写
	if (IsSectorAllow(volumeInfo, orgIndex))
	{
		return orgIndex;
	}

	// 此扇区是否空闲
	if (!DPBitmap_Test(volumeInfo->BitmapUsed, orgIndex))
	{
		// 不重定向, 直接标记为可直接写入
		DPBitmap_Set(volumeInfo->BitmapUsed, orgIndex, TRUE);
		DPBitmap_Set(volumeInfo->BitmapAllow, orgIndex, TRUE);
		return orgIndex;
	}

	// 此扇区是否已经被重定向
	if (DPBitmap_Test(volumeInfo->BitmapRedirect, orgIndex))
	{
		// 找到重定向到哪里, 并返回
		RedirectTable_Lookup(&volumeInfo->RedirectMap, orgIndex, &mapIndex, nextCount, NULL);
	}
	else
	{
		// 查找下一个可用的空闲扇区
		mapIndex = DPBitmap_FindNext(volumeInfo->BitmapUsed, volumeInfo->LastScanIndex, FALSE);

		if (mapIndex != -1)
		{
			// lastScan = 当前用到的 + 1
			volumeInfo->LastScanIndex = mapIndex + 1;

			// 标记为非空闲
			DPBitmap_Set(volumeInfo->BitmapUsed, mapIndex, TRUE);

			// 标记此扇区已被重定向(orgIndex)
			DPBitmap_Set(volumeInfo->BitmapRedirect, orgIndex, TRUE);

			// 标记被重定向使用的扇区
			DPBitmap_Set(volumeInfo->BitmapRedirectUsed, mapIndex, TRUE);
			
			// 优化：此处不加入重定向列表，重定向列表存储连续扇区，在最终操作时存入重定向列表
			*needRedirect = TRUE;
		}
	}

	return mapIndex;
}

// 处理对硬盘的读写操作
NTSTATUS HandleDiskRequest(
	PVOLUME_INFO volumeInfo,
	ULONG majorFunction,
	ULONGLONG logicOffset,
	void * buff,
	ULONG length)
{
	NTSTATUS	status = STATUS_SUCCESS;

	// 当前操作的物理偏移
	ULONGLONG	physicalOffset = 0;
	ULONGLONG	sectorIndex;
	ULONGLONG	realIndex;
	ULONG		bytesPerSector = volumeInfo->BytesPerSector;

	// 以下几个参数为判断为处理的扇区是连续的扇区而设
	BOOLEAN		isFirstBlock = TRUE;
	ULONGLONG	prevStart = (ULONGLONG)-1;
	ULONGLONG	prevIndex = (ULONGLONG)-1;
	ULONGLONG	prevOffset = (ULONGLONG)-1;
	PVOID		prevBuffer = NULL;
	ULONG		totalProcessBytes = 0;

	BOOLEAN		prevNeedRedirect = FALSE; // 判断是否修改重定向表
	BOOLEAN		needRedirect = FALSE;

	ULONGLONG	curCount = 0; // 一次性能处理的连续扇区数量

	// 判断上次要处理的扇区跟这次要处理的扇区是否连续，连续了就一起处理，否则单独处理, 加快速度
	while (length)
	{
		sectorIndex = logicOffset / bytesPerSector;

		if (IRP_MJ_READ == majorFunction)
		{
			realIndex = GetRealSectorForRead(volumeInfo, sectorIndex, &curCount);
		}
		else
		{
			realIndex = GetRealSectorForWrite(volumeInfo, sectorIndex, &curCount, &needRedirect);
		}

		if (-1 == realIndex)
		{
			volumeInfo->CanSaveData = FALSE;
			if (!isFirstBlock)
			{
				status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], majorFunction, volumeInfo->StartOffset + prevOffset,
					prevBuffer, totalProcessBytes, TRUE);

				// 判断是否要加入重定向列表
				if (prevNeedRedirect)
				{
					AddRedirectRecord(volumeInfo, prevStart, prevOffset / bytesPerSector, totalProcessBytes / bytesPerSector);
				}
			}
			return STATUS_DISK_FULL;
		}

		physicalOffset = realIndex * bytesPerSector;

		curCount = min(curCount + 1, length / bytesPerSector);

	__reInit:
		// 初始prevIndex
		if (isFirstBlock)
		{
			prevStart = sectorIndex;
			prevIndex = realIndex;
			prevOffset = physicalOffset;
			prevBuffer = buff;
			totalProcessBytes = bytesPerSector * (ULONG)curCount;
			prevNeedRedirect = needRedirect;

			isFirstBlock = FALSE;

			goto __next;
		}

		// 测试是否连继,  如果连续，跳到下个判断
		if (prevIndex != -1 && realIndex == prevIndex + 1 && needRedirect == prevNeedRedirect)
		{
			prevIndex = realIndex + curCount - 1;
			totalProcessBytes += bytesPerSector * (ULONG)curCount;
			goto __next;
		}
		// 处理上次连续需要处理的簇, 重置isFirstBlock
		else
		{
			isFirstBlock = TRUE;
			status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], majorFunction, volumeInfo->StartOffset + prevOffset,
				prevBuffer, totalProcessBytes, TRUE);

			// 判断是否要加入重定向列表
			if (prevNeedRedirect)
			{
				AddRedirectRecord(volumeInfo, prevStart, prevOffset / bytesPerSector, totalProcessBytes / bytesPerSector);
			}

			// 重新初始化
			goto __reInit;
		}
	__next:
		// 最后一个扇区
		if (bytesPerSector * curCount >= length)
		{
			status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], majorFunction, volumeInfo->StartOffset + prevOffset,
				prevBuffer, totalProcessBytes, TRUE);

			// 判断是否要加入重定向列表
			if (prevNeedRedirect)
			{
				AddRedirectRecord(volumeInfo, prevStart, prevOffset / bytesPerSector, totalProcessBytes / bytesPerSector);
			}

			// 中断退出
			break;
		}

		// 跳到下一个扇区, 处理剩余的数据
		logicOffset += (ULONGLONG)bytesPerSector * curCount;
		buff = (char *)buff + bytesPerSector * curCount;
		length -= bytesPerSector * (ULONG)curCount;
	}

	return status;
}

// 直接写入时获取真实需要写入的备份扇区
ULONGLONG GetRealSectorForDirectWrite(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex, PULONGLONG nextCount, PUCHAR modifyType)
{
	ULONGLONG	mapIndex = (ULONGLONG)-1;

	if (nextCount)
		*nextCount = 0;

	*modifyType = 0; // 默认不修改重定向表

	// 此扇区是否允许直接写
	if (IsSectorAllow(volumeInfo, orgIndex))
	{
		// 标记为不允许直接写并重定向
		DPBitmap_Set(volumeInfo->BitmapAllow, orgIndex, FALSE);
		DPBitmap_Set(volumeInfo->BitmapUsed, orgIndex, TRUE);
		goto redirect;
	}

	// 此扇区是否是空闲扇区
	if (!DPBitmap_Test(volumeInfo->BitmapUsed, orgIndex))
	{
		// 标记为非空闲
		DPBitmap_Set(volumeInfo->BitmapUsed, orgIndex, TRUE);
		DPBitmap_Set(volumeInfo->BitmapRedirectUsed, orgIndex, TRUE);
		*modifyType = 1; // 向反向重定向表添加一条orgIndex到-1的映射
		return (ULONGLONG)-1;
	}

	// 此扇区是否被重定向使用
	if (DPBitmap_Test(volumeInfo->BitmapRedirectUsed, orgIndex))
	{
		ULONGLONG oldSector = (ULONGLONG)-1; // 原扇区
		RedirectTable_Lookup(&volumeInfo->ReverseRedirectMap, orgIndex, &oldSector, nextCount, NULL);
		if (oldSector == -1) // 之前是空闲状态，无需处理
		{
			return (ULONGLONG)-1;
		}
		if (nextCount)
			*nextCount = 0;

		// 查找下一个可用的空闲扇区
		mapIndex = DPBitmap_FindNext(volumeInfo->BitmapUsed, volumeInfo->LastScanIndex, FALSE);

		if (mapIndex != -1)
		{
			// lastScan = 当前用到的 + 1
			volumeInfo->LastScanIndex = mapIndex + 1;

			// 标记为非空闲
			DPBitmap_Set(volumeInfo->BitmapUsed, mapIndex, TRUE);

			// 标记重定向使用的扇区
			DPBitmap_Set(volumeInfo->BitmapRedirectUsed, mapIndex, TRUE);
		}

		// 删除原有反向重定向记录
		DPBitmap_Set(volumeInfo->BitmapRedirectUsed, orgIndex, FALSE);

		*modifyType = 2; // 将重定向表中oldSector到orgIndex的记录修改为mapIndex
	}
	// 否则，此扇区是原来就使用的扇区，如果还没有被重定向，那么就进行重定向
	else if (!DPBitmap_Test(volumeInfo->BitmapRedirect, orgIndex))
	{
redirect:
		BOOLEAN needModify = FALSE;
		mapIndex = GetRealSectorForWrite(volumeInfo, orgIndex, NULL, &needModify);
		if (needModify)
		{
			*modifyType = 3; // 向重定向表中添加一条orgIndex到mapIndex的记录
		}
	}

	return mapIndex;
}

// 准备对硬盘的直接写操作，备份直接读写要覆盖的扇区并修改重定向表，以保证直接读写不会影响保护卷
NTSTATUS PrepareForDirectWriteRequest(
	PVOLUME_INFO volumeInfo,
	ULONGLONG logicOffset,
	ULONG length)
{
	NTSTATUS status;

	// 当前操作的物理偏移
	ULONGLONG	physicalOffset = 0;
	ULONGLONG	sectorIndex;
	ULONGLONG	realIndex;
	ULONG		bytesPerSector = volumeInfo->BytesPerSector;

	// 以下几个参数为判断为处理的扇区是连续的扇区而设
	BOOLEAN		isFirstBlock = TRUE;
	ULONGLONG	prevStart = (ULONGLONG)-1;
	ULONGLONG	prevIndex = (ULONGLONG)-1;
	ULONGLONG	prevOffset = (ULONGLONG)-1;
	PVOID		prevBuffer = NULL;
	ULONG		totalProcessBytes = 0;

	UCHAR		prevModifyType = 0; // 判断是否修改重定向表
	UCHAR		modifyType = 0;

	ULONGLONG	curCount = 0; // 一次性能处理的连续扇区数量

	void * buff_mem;
	void * buff;

	buff_mem = __malloc(length);
	if (!buff_mem)
		return STATUS_INSUFFICIENT_RESOURCES;

	buff = buff_mem;

	status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], IRP_MJ_READ, volumeInfo->StartOffset + logicOffset, buff, length, TRUE);
	if (!NT_SUCCESS(status))
		return status;

	// 判断上次要处理的扇区跟这次要处理的扇区是否连续，连续了就一起处理，否则单独处理, 加快速度
	while (length)
	{
		sectorIndex = logicOffset / bytesPerSector;

		realIndex = GetRealSectorForDirectWrite(volumeInfo, sectorIndex, &curCount, &modifyType);

		physicalOffset = realIndex * bytesPerSector;

		curCount = min(curCount + 1, length / bytesPerSector);

	__reInit:
		// 初始prevIndex
		if (isFirstBlock)
		{
			prevStart = sectorIndex;
			prevIndex = realIndex;
			prevOffset = physicalOffset;
			prevBuffer = buff;
			totalProcessBytes = bytesPerSector * (ULONG)curCount;
			prevModifyType = modifyType;

			isFirstBlock = FALSE;

			goto __next;
		}

		// 测试是否连继,  如果连续，跳到下个判断
		if (((realIndex != -1 && prevIndex != -1 && realIndex == prevIndex + 1) || (realIndex == -1 && prevIndex == -1)) && modifyType == prevModifyType)
		{
			if (realIndex == -1)
				prevIndex = realIndex;
			else
				prevIndex = realIndex + curCount - 1;
			totalProcessBytes += bytesPerSector * (ULONG)curCount;
			goto __next;
		}
		// 处理上次连续需要处理的簇, 重置isFirstBlock
		else
		{
			isFirstBlock = TRUE;
			if (prevIndex != -1)
				status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], IRP_MJ_WRITE, volumeInfo->StartOffset + prevOffset,
					prevBuffer, totalProcessBytes, TRUE);

			// 判断是否要加入重定向列表和反向重定向列表
			if (prevModifyType == 1)
			{
				RedirectTable_Insert(&volumeInfo->ReverseRedirectMap, prevStart, (ULONGLONG)-1, totalProcessBytes / bytesPerSector, NULL);
			}
			else if (prevModifyType == 2)
			{
				if (prevIndex != -1)
					UpdateRedirectRecord(volumeInfo, prevStart, prevOffset / bytesPerSector, totalProcessBytes / bytesPerSector);
				else
					UpdateRedirectRecord(volumeInfo, prevStart, (ULONGLONG)-1, totalProcessBytes / bytesPerSector);
			}
			else if (prevModifyType == 3)
			{
				AddRedirectRecord(volumeInfo, prevStart, prevOffset / bytesPerSector, totalProcessBytes / bytesPerSector);
			}

			// 重新初始化
			goto __reInit;
		}
	__next:
		// 最后一个扇区
		if (bytesPerSector * curCount >= length)
		{
			if (prevIndex != -1)
				status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], IRP_MJ_WRITE, volumeInfo->StartOffset + prevOffset,
					prevBuffer, totalProcessBytes, TRUE);

			// 判断是否要加入重定向列表和反向重定向列表
			if (prevModifyType == 1)
			{
				RedirectTable_Insert(&volumeInfo->ReverseRedirectMap, prevStart, (ULONGLONG)-1, totalProcessBytes / bytesPerSector, NULL);
			}
			else if (prevModifyType == 2)
			{
				if (prevIndex != -1)
					UpdateRedirectRecord(volumeInfo, prevStart, prevOffset / bytesPerSector, totalProcessBytes / bytesPerSector);
				else
					UpdateRedirectRecord(volumeInfo, prevStart, (ULONGLONG)-1, totalProcessBytes / bytesPerSector);
			}
			else if (prevModifyType == 3)
			{
				AddRedirectRecord(volumeInfo, prevStart, prevOffset / bytesPerSector, totalProcessBytes / bytesPerSector);
			}

			// 中断退出
			break;
		}

		// 跳到下一个扇区, 处理剩余的数据
		logicOffset += (ULONGLONG)bytesPerSector * curCount;
		buff = (char *)buff + bytesPerSector * curCount;
		length -= bytesPerSector * (ULONG)curCount;
	}
	__free(buff_mem);
	return status;
}

// 处理对硬盘的直接读写操作
NTSTATUS HandleDirectDiskRequest(
	PVOLUME_INFO volumeInfo,
	ULONG majorFunction,
	ULONGLONG logicOffset,
	void * buff,
	ULONG length)
{
	NTSTATUS	status;

	//未对齐读写操作，返回错误不处理
	if (logicOffset % volumeInfo->BytesPerSector || length % volumeInfo->BytesPerSector)
	{
		LogWarn("Unaligned direct write to disk %lu partition %lu, offset %llu length %lu\n", volumeInfo->DiskNumber, volumeInfo->PartitionNumber, logicOffset, length);
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	// 只处理对硬盘直接写的操作
	if (IRP_MJ_WRITE == majorFunction)
	{
		status = PrepareForDirectWriteRequest(volumeInfo, logicOffset, length);
	}
	status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], majorFunction, volumeInfo->StartOffset + logicOffset, buff, length, TRUE);

	return status;
}

// 处理保存数据的操作
BOOLEAN SaveVolumeData(PVOLUME_INFO volumeInfo)
{
	if (!volumeInfo->CanSaveData)
	{
		LogWarn("Cannot save data on volume (%lu,%lu)\n", volumeInfo->DiskNumber, volumeInfo->PartitionNumber);
		return FALSE;
	}
	WCHAR VolName[50];
	if (volumeInfo->Volume)
	{
		VolName[0] = volumeInfo->Volume;
		VolName[1] = L'\0';
	}
	else
	{
		swprintf_s(VolName, 50, L"(%lu,%lu)", volumeInfo->DiskNumber, volumeInfo->PartitionNumber);
	}
	LogInfo("Saving data on volume %ls...\n", VolName);
	WCHAR Buf[256];
	swprintf_s(Buf, 256, L"Saving data on volume %ls", VolName);
	DisplayString(Buf);
	PDP_BITMAP BitmapDepends = NULL;
	NTSTATUS status = DPBitmap_Create(&BitmapDepends, volumeInfo->SectorCount, BITMAP_SLOT_SIZE);
	if (!NT_SUCCESS(status))
	{
		LogWarn("Failed to create bitmap, error code=0x%.8X\n", status);
		swprintf_s(Buf, 256, L"\rFailed to save data on volume %ls. Error code=0x%.8X\n", VolName, status);
		DisplayString(Buf);
		return FALSE;
	}
	for (PREDIRECT_TABLE_NODE Iterator = RedirectTable_NextIterator(&volumeInfo->RedirectMap, NULL);
		Iterator;
		Iterator = RedirectTable_NextIterator(&volumeInfo->RedirectMap, Iterator))
	{
		for (ULONG i = 0; i < Iterator->Length; i++)
		{
			if (DPBitmap_Test(volumeInfo->BitmapRedirect, Iterator->NewStart + i))
				DPBitmap_Set(BitmapDepends, Iterator->NewStart + i, TRUE);
		}
	}
	typedef struct
	{
		PREDIRECT_TABLE_NODE Iterator;
		LIST_ENTRY ListEntry;
	} REDIRECT_QUEUE_ITEM;
	LIST_ENTRY RedirectQueue;
	InitializeListHead(&RedirectQueue);
	for (PREDIRECT_TABLE_NODE Iterator = RedirectTable_NextIterator(&volumeInfo->RedirectMap, NULL);
		Iterator;
		Iterator = RedirectTable_NextIterator(&volumeInfo->RedirectMap, Iterator))
	{
		BOOLEAN Flag = TRUE;
		for (ULONG Index = 0; Index < Iterator->Length; Index++)
		{
			if (DPBitmap_Test(BitmapDepends, Iterator->OrigStart + Index))
			{
				Flag = FALSE;
				break;
			}
		}
		if (Flag)
		{
			REDIRECT_QUEUE_ITEM *item = (REDIRECT_QUEUE_ITEM *)__malloc(sizeof(REDIRECT_QUEUE_ITEM));
			if (!item)
			{
				LogWarn("Failed to allocate memory for queue item\n");
				DPBitmap_Free(BitmapDepends);
				while (!IsListEmpty(&RedirectQueue))
				{
					PLIST_ENTRY Entry = RemoveHeadList(&RedirectQueue);
					REDIRECT_QUEUE_ITEM *tmpItem = CONTAINING_RECORD(Entry, REDIRECT_QUEUE_ITEM, ListEntry);
					__free(tmpItem);
				}
				swprintf_s(Buf, 256, L"\rFailed to save data on volume %ls. Failed to allocate memory.\n", VolName);
				DisplayString(Buf);
				return FALSE;
			}
			item->Iterator = Iterator;
			InitializeListHead(&item->ListEntry);
			InsertTailList(&RedirectQueue, &item->ListEntry);
		}
	}
	ULONGLONG TotalRedirectSectors = DPBitmap_Count(volumeInfo->BitmapRedirect, TRUE);
	int LastProgress = -1;
	BOOLEAN IsDirty = FALSE;
	while (!IsListEmpty(&RedirectQueue))
	{
		PLIST_ENTRY Entry = RemoveHeadList(&RedirectQueue);
		REDIRECT_QUEUE_ITEM *Item = CONTAINING_RECORD(Entry, REDIRECT_QUEUE_ITEM, ListEntry);
		ULONG Length = (ULONG)Item->Iterator->Length * volumeInfo->BytesPerSector;
		char * buff = (char *)__malloc(Length);
		if (buff)
		{
			status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], IRP_MJ_READ, volumeInfo->StartOffset + Item->Iterator->NewStart * volumeInfo->BytesPerSector, buff, Length, TRUE);
			if (NT_SUCCESS(status))
			{
				status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], IRP_MJ_WRITE, volumeInfo->StartOffset + Item->Iterator->OrigStart * volumeInfo->BytesPerSector, buff, Length, TRUE);
				if (!NT_SUCCESS(status))
				{
					LogErr("Write sector failed (StartOffset=%llu,Length=%llu), error code=0x%.8X\n", volumeInfo->StartOffset / volumeInfo->BytesPerSector + Item->Iterator->OrigStart, Item->Iterator->Length, status);
				}
			}
			else
			{
				LogErr("Read sector failed (StartOffset=%llu,Length=%llu), error code=0x%.8X\n", volumeInfo->StartOffset / volumeInfo->BytesPerSector + Item->Iterator->NewStart, Item->Iterator->Length, status);
			}
			__free(buff);
		}
		else
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		if (!NT_SUCCESS(status))
		{
			IsDirty = TRUE;
			swprintf_s(Buf, 256, L"\rSave sector %llu->%llu (%lu) on volume %ls failed. Error code=0x%.8X\n", Item->Iterator->NewStart, Item->Iterator->OrigStart, Item->Iterator->Length, VolName, status);
			DisplayString(Buf);
		}
		for (ULONG i = 0; i < Item->Iterator->Length; i++)
		{
			DPBitmap_Set(volumeInfo->BitmapRedirect, Item->Iterator->OrigStart + i, FALSE);
			ULONGLONG NewIndex = Item->Iterator->NewStart + i;
			if (DPBitmap_Test(volumeInfo->BitmapRedirect, NewIndex))
				DPBitmap_Set(BitmapDepends, NewIndex, FALSE);
		}
		for (ULONGLONG i = 0; i < Item->Iterator->Length; i++)
		{
			ULONGLONG NewIndex = Item->Iterator->NewStart + i;
			if (DPBitmap_Test(volumeInfo->BitmapRedirect, NewIndex))
			{
				ULONGLONG MapIndex = (ULONGLONG)-1;
				ULONGLONG NextCount = 0;
				PREDIRECT_TABLE_NODE NewIterator = NULL;
				RedirectTable_Lookup(&volumeInfo->RedirectMap, NewIndex, &MapIndex, &NextCount, &NewIterator);
				if (NewIterator)
				{
					BOOLEAN Flag = TRUE;
					for (ULONG Index = 0; Index < NewIterator->Length; Index++)
					{
						if (DPBitmap_Test(BitmapDepends, NewIterator->OrigStart + Index))
						{
							Flag = FALSE;
							break;
						}
					}
					if (Flag)
					{
						REDIRECT_QUEUE_ITEM *item = (REDIRECT_QUEUE_ITEM *)__malloc(sizeof(REDIRECT_QUEUE_ITEM));
						if (item)
						{
							item->Iterator = NewIterator;
							InitializeListHead(&item->ListEntry);
							InsertTailList(&RedirectQueue, &item->ListEntry);
						}
						else
						{
							LogErr("Failed to allocate memory for queue item\n");
							IsDirty = TRUE;
						}
					}
				}
				else
				{
					LogErr("No redirect matched with sector %llu\n", NewIndex);
					IsDirty = TRUE;
				}
				i += NextCount;
			}
		}
		RedirectTable_DeleteIterator(&volumeInfo->RedirectMap, Item->Iterator);
		__free(Item);
		ULONGLONG CurrentCount = DPBitmap_Count(volumeInfo->BitmapRedirect, TRUE);
		int CurProgress = int(100 * (TotalRedirectSectors - CurrentCount) / TotalRedirectSectors);
		if (CurProgress != LastProgress)
		{
			LastProgress = CurProgress;
			swprintf_s(Buf, 256, L"\rSaving data on volume %ls... Progress: %d%%", VolName, CurProgress);
			DisplayString(Buf);
		}
	}
	if (IsDirty)
		DisplayString(L"\rVolume is dirty, please run chkdsk.        \n");
	DPBitmap_Free(BitmapDepends);
	DPBitmap_Free(volumeInfo->BitmapUsed);
	DPBitmap_Free(volumeInfo->BitmapRedirect);
	DPBitmap_Free(volumeInfo->BitmapRedirectUsed);
	DPBitmap_Free(volumeInfo->BitmapAllow);
	RedirectTable_Free(&volumeInfo->RedirectMap);
	RedirectTable_Free(&volumeInfo->ReverseRedirectMap);
	// InterlockedExchange8((PCHAR)&volumeInfo->Protect, FALSE);
	swprintf_s(Buf, 256, L"\rFinished saving data on volume %ls         \n", VolName);
	DisplayString(Buf);
	return TRUE;
}

// 读写操作线程
void ThreadReadWrite(PVOID Context)
{
	//NTSTATUS类型的函数返回值
	NTSTATUS			status = STATUS_SUCCESS;
	//用来指向过滤设备的设备扩展的指针
	PVOLUME_INFO		volume_info = (PVOLUME_INFO)Context;
	//请求队列的入口
	PLIST_ENTRY			ReqEntry = NULL;
	//irp指针
	PIRP				Irp = NULL;
	//irp stack指针
	PIO_STACK_LOCATION	io_stack = NULL;
	//irp中包括的数据地址
	PVOID				buffer = NULL;
	//irp中的数据长度
	ULONG				length = 0;
	//irp要处理的偏移量
	LARGE_INTEGER		offset = { 0 };
	//irp要处理的偏移量
	LARGE_INTEGER		cacheOffset = { 0 };
	//是否停止保护
	BOOLEAN				StopProtect = FALSE;

	//设置这个线程的优先级
	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

	//下面是线程的实现部分，这个循环永不退出
	for (;;)
	{
		//先等待请求队列同步事件，如果队列中没有irp需要处理，我们的线程就等待在这里，让出cpu时间给其它线程
		KeWaitForSingleObject(
			&volume_info->RequestEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL
		);
		//如果有了线程结束标志，那么就在线程内部自己结束自己
		if (volume_info->ThreadTerminate)
		{
			KeSetEvent(&volume_info->FinishSaveDataEvent, (KPRIORITY)0, FALSE);
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}
		//保存数据
		if (volume_info->SavingData)
		{
			if (SaveVolumeData(volume_info))
				StopProtect = TRUE;
			volume_info->SavingData = FALSE;
			volume_info->CanSaveData = FALSE;
			KeSetEvent(&volume_info->FinishSaveDataEvent, (KPRIORITY)0, FALSE);
		}
		//从请求队列的首部拿出一个请求来准备处理，这里使用了自旋锁机制，所以不会有冲突
		while ((ReqEntry = ExInterlockedRemoveHeadList(
			&volume_info->ListHead,
			&volume_info->ListLock
		)) != NULL)
		{
			void * newbuff = NULL, *bufaddr = NULL;

			//从队列的入口里找到实际的irp的地址
			Irp = CONTAINING_RECORD(ReqEntry, IRP, Tail.Overlay.ListEntry);

			//取得irp stack
			io_stack = IoGetCurrentIrpStackLocation(Irp);

			if (IRP_MJ_READ == io_stack->MajorFunction)
			{
				//如果是读的irp请求，我们在irp stack中取得相应的参数作为offset和length
				offset = io_stack->Parameters.Read.ByteOffset;
				length = io_stack->Parameters.Read.Length;
			}
			else if (IRP_MJ_WRITE == io_stack->MajorFunction)
			{
				//如果是写的irp请求，我们在irp stack中取得相应的参数作为offset和length
				offset = io_stack->Parameters.Write.ByteOffset;
				length = io_stack->Parameters.Write.Length;
			}
			else
			{
				//除此之外，offset和length都是0
				offset.QuadPart = 0;
				length = 0;
			}

			// 如果长度为0，就直接完成请求
			if (!length)
			{
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_SUCCESS;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				continue;
			}

			if (Irp->MdlAddress)
			{
				buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
			}
			else if (Irp->UserBuffer)
			{
				buffer = Irp->UserBuffer;
			}
			else
			{
				buffer = Irp->AssociatedIrp.SystemBuffer;
			}

			if (!buffer)
			{
				goto __failed;
			}

			// 不能和上次传来的buffer用同一个缓冲区，不然
			// 会出现 PFN_LIST_CORRUPT (0x99, ...) A PTE or PFN is corrupt 错误
			// 频繁申请内存也不是办法，用缓冲池吧
			newbuff = bufaddr = __malloc(length);

			if (bufaddr)
			{
				// 停止保护状态或直接读写
				if (StopProtect || IsDirectDiskDevice(io_stack->DeviceObject))
				{
					status = STATUS_SUCCESS;
					if (IsDirectDiskDevice(io_stack->DeviceObject))
					{
						if (!AllowDirectMount)
							status = STATUS_INVALID_DEVICE_REQUEST;
						else if (StopProtect)
							offset.QuadPart += volume_info->StartOffset;
					}
					if (NT_SUCCESS(status))
					{
						if (IRP_MJ_READ == io_stack->MajorFunction)
						{
							if (StopProtect)
								status = FastFsdRequest(LowerDeviceObject[volume_info->DiskNumber], io_stack->MajorFunction, offset.QuadPart,
									newbuff, length, TRUE);
							else
								status = HandleDirectDiskRequest(volume_info, io_stack->MajorFunction, offset.QuadPart,
									newbuff, length);
							RtlCopyMemory(buffer, newbuff, length);
						}
						else
						{
							RtlCopyMemory(newbuff, buffer, length);
							if (StopProtect)
								status = FastFsdRequest(LowerDeviceObject[volume_info->DiskNumber], io_stack->MajorFunction, offset.QuadPart,
									newbuff, length, TRUE);
							else
								status = HandleDirectDiskRequest(volume_info, io_stack->MajorFunction, offset.QuadPart,
									newbuff, length);
						}
					}
				}
				else
				{
					ULONG tempLength = length;
					//读写操作不被分区完整包含，特殊处理
					if (offset.QuadPart < volume_info->StartOffset && offset.QuadPart + tempLength > volume_info->StartOffset)
					{
						LogInfo("Outbound read/write to disk %lu partition %lu, offset %llu length %lu\n", volume_info->DiskNumber, volume_info->PartitionNumber, offset.QuadPart, length);
						ULONG BufferLength = (ULONG)(volume_info->StartOffset - offset.QuadPart);
						if (IRP_MJ_READ == io_stack->MajorFunction)
						{
							status = FastFsdRequest(io_stack->DeviceObject, io_stack->MajorFunction, offset.QuadPart,
								newbuff, BufferLength, TRUE, FALSE);
							RtlCopyMemory(buffer, newbuff, BufferLength);
						}
						else
						{
							RtlCopyMemory(newbuff, buffer, BufferLength);
							status = FastFsdRequest(io_stack->DeviceObject, io_stack->MajorFunction, offset.QuadPart,
								newbuff, BufferLength, TRUE, io_stack->Flags & SL_FORCE_DIRECT_WRITE);
						}
						offset.QuadPart += BufferLength;
						buffer = (PUCHAR)buffer + BufferLength;
						newbuff = (PUCHAR)newbuff + BufferLength;
						tempLength -= BufferLength;
					}
					// 得到在卷中的偏移 磁盘偏移-卷逻辑偏移
					cacheOffset.QuadPart = offset.QuadPart - volume_info->StartOffset;
					ULONG curLength = (ULONG)min(tempLength, volume_info->BytesTotal - cacheOffset.QuadPart);
					if (IRP_MJ_READ == io_stack->MajorFunction)
					{
						status = HandleDiskRequest(volume_info, io_stack->MajorFunction, cacheOffset.QuadPart,
							newbuff, curLength);
						RtlCopyMemory(buffer, newbuff, curLength);
					}
					else
					{
						RtlCopyMemory(newbuff, buffer, curLength);
						status = HandleDiskRequest(volume_info, io_stack->MajorFunction, cacheOffset.QuadPart,
							newbuff, curLength);
					}
					//读写操作不被分区完整包含，特殊处理
					if (cacheOffset.QuadPart + tempLength > volume_info->BytesTotal)
					{
						LogInfo("Outbound read/write to disk %lu partition %lu, offset %llu length %lu\n", volume_info->DiskNumber, volume_info->PartitionNumber, offset.QuadPart, length);
						ULONGLONG NewOffset = volume_info->StartOffset + volume_info->BytesTotal;
						ULONG BufferOffset = (ULONG)(NewOffset - offset.QuadPart);
						ULONG NewLength = tempLength - BufferOffset;
						if (IRP_MJ_READ == io_stack->MajorFunction)
						{
							status = FastFsdRequest(io_stack->DeviceObject, io_stack->MajorFunction, NewOffset,
								(PUCHAR)newbuff + BufferOffset, NewLength, TRUE, FALSE);
							RtlCopyMemory((PUCHAR)buffer + BufferOffset, (PUCHAR)newbuff + BufferOffset, NewLength);
						}
						else
						{
							RtlCopyMemory((PUCHAR)newbuff + BufferOffset, (PUCHAR)buffer + BufferOffset, NewLength);
							status = FastFsdRequest(io_stack->DeviceObject, io_stack->MajorFunction, NewOffset,
								(PUCHAR)newbuff + BufferOffset, NewLength, TRUE, io_stack->Flags & SL_FORCE_DIRECT_WRITE);
						}
					}
				}
				__free(bufaddr);
			}
			else
			{
				LogErr("Failed to allocate memory for %u bytes! System will be unstable!!!\n", length);
				status = STATUS_INSUFFICIENT_RESOURCES;
			}

			// 赋值Information
			if (NT_SUCCESS(status))
			{
				Irp->IoStatus.Information = length;
			}
			else
			{
				Irp->IoStatus.Information = 0;
			}

			Irp->IoStatus.Status = status;
			IoCompleteRequest(Irp, IO_DISK_INCREMENT);
			continue;
		// 处理请求失败，将请求直接交给下层设备处理
		__failed:
			if (IsDirectDiskDevice(io_stack->DeviceObject))
			{
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
			}
			else
			{
				IoSkipCurrentIrpStackLocation(Irp);
				IoCallDriver(LowerDeviceObject[volume_info->DiskNumber], Irp);
			}
			continue;
		}
		// 停止保护标志
		if (StopProtect)
		{
			InterlockedExchange8((PCHAR)&volume_info->Protect, FALSE);
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}
	}
}

// 处理IRP_MJ_READ和IRP_MJ_WRITE
BOOLEAN
OnDiskFilterReadWrite(
	IN PUNICODE_STRING PhysicalDeviceName,
	IN ULONG DeviceType,
	IN ULONG DeviceNumber,
	IN ULONG PartitionNumber,
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN NTSTATUS *Status)
{
	UNREFERENCED_PARAMETER(PhysicalDeviceName);
	UNREFERENCED_PARAMETER(DeviceType);
	UNREFERENCED_PARAMETER(PartitionNumber);
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

	//irp中的数据长度
	ULONG				length = 0;
	//irp要处理的偏移量
	LARGE_INTEGER		offset = { 0 };

	if (!IsProtect)
	{
		return FALSE;
	}

	if (IRP_MJ_WRITE == irpStack->MajorFunction)
	{
		offset = irpStack->Parameters.Write.ByteOffset;
		length = irpStack->Parameters.Write.Length;
	}
	else if (IRP_MJ_READ == irpStack->MajorFunction)
	{
		offset = irpStack->Parameters.Read.ByteOffset;
		length = irpStack->Parameters.Read.Length;
	}
	else
	{
		return FALSE;
	}

	for (UINT i = 0; i < ValidVolumeCount; i++)
	{
		// 卷是否在受保护的硬盘上
		if (ProtectVolumeList[i].DiskNumber != DeviceNumber || !ProtectVolumeList[i].Protect)
			continue;

		if ((offset.QuadPart >= ProtectVolumeList[i].StartOffset &&
			offset.QuadPart - ProtectVolumeList[i].StartOffset < ProtectVolumeList[i].BytesTotal) || //读写操作头部被分区完整包含
			(offset.QuadPart < ProtectVolumeList[i].StartOffset && offset.QuadPart + length > ProtectVolumeList[i].StartOffset) //读写操作尾部被分区完整包含
			)
		{
			//未对齐读写操作，返回错误不处理
			if (offset.QuadPart % ProtectVolumeList[i].BytesPerSector || length % ProtectVolumeList[i].BytesPerSector)
			{
				*Status = Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				LogWarn("Unaligned read/write to disk %lu, offset %llu length %lu\n", DeviceNumber, offset.QuadPart, length);
				return TRUE;
			}
			/*//读写操作不被分区完整包含，返回错误不处理
			if (offset.QuadPart - ProtectVolumeList[i].StartOffset + length > ProtectVolumeList[i].BytesTotal)
			{
				*Status = Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				LogWarn("Outbound read/write to disk %lu partition %lu, offset %llu length %lu\n", DeviceNumber, ProtectVolumeList[i].PartitionNumber, offset.QuadPart, length);
				return TRUE;
			}*/
			//这个卷在保护状态，
			//我们首先把这个irp设为pending状态
			IoMarkIrpPending(Irp);

			//然后将这个irp放进相应的请求队列里
			ExInterlockedInsertTailList(
				&ProtectVolumeList[i].ListHead,
				&Irp->Tail.Overlay.ListEntry,
				&ProtectVolumeList[i].ListLock
			);
			//设置队列的等待事件，通知队列对这个irp进行处理
			KeSetEvent(
				&ProtectVolumeList[i].RequestEvent,
				(KPRIORITY)0,
				FALSE);
			//返回pending状态，这个irp就算处理完了
			*Status = STATUS_PENDING;

			// TRUE表始IPR被拦截
			return TRUE;
		}
		/*//读写操作不被分区完整包含，返回错误不处理
		if (offset.QuadPart < ProtectVolumeList[i].StartOffset && (offset.QuadPart + length) > ProtectVolumeList[i].StartOffset)
		{
			*Status = Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			LogWarn("Outbound read/write to disk %lu partition %lu, offset %llu length %lu\n", DeviceNumber, ProtectVolumeList[i].PartitionNumber, offset.QuadPart, length);
			return TRUE;
		}*/
	}

	// 保护硬盘上的特定扇区（MBR和GPT分区表,保留扇区,EBR）
	if (IRP_MJ_WRITE == irpStack->MajorFunction && DeviceNumber < sizeof(ProtectDiskList) / sizeof(*ProtectDiskList) && ProtectDiskList[DeviceNumber].BitmapDeny)
	{
		ULONG cacheLength = length;
		ULONGLONG cacheOffset = offset.QuadPart;
		ULONG bytesPerSector = ProtectDiskList[DeviceNumber].BytesPerSector;
		PDP_BITMAP bitmap = ProtectDiskList[DeviceNumber].BitmapDeny;
		//未对齐读写操作，返回错误不处理
		if (offset.QuadPart % bytesPerSector || length % bytesPerSector)
		{
			*Status = Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			LogWarn("Unaligned write to disk %lu, offset %llu length %lu\n", DeviceNumber, offset.QuadPart, length);
			return TRUE;
		}
		while (cacheLength)
		{
			ULONGLONG sectorIndex = cacheOffset / bytesPerSector;
			if (DPBitmap_Test(bitmap, sectorIndex))
			{
				*Status = Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				LogInfo("Denied write sector %llu on disk %d\n", sectorIndex, DeviceNumber);
				return TRUE;
			}
			cacheOffset += bytesPerSector;
			cacheLength -= bytesPerSector;
		}
	}

	//这个卷不在保护状态，直接交给下层设备进行处理
	//if (IRP_MJ_WRITE == irpStack->MajorFunction)
	//	LogInfo("Disk %lu not protect area, passed write request down: offset=%lld, length=%ld\n", DeviceNumber, irpStack->Parameters.Write.ByteOffset.QuadPart, irpStack->Parameters.Write.Length);

	return FALSE;
}

// 处理IRP_MJ_DEVICE_CONTROL
BOOLEAN
OnDiskFilterDeviceControl(
	IN PUNICODE_STRING PhysicalDeviceName,
	IN ULONG DeviceType,
	IN ULONG DeviceNumber,
	IN ULONG PartitionNumber,
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN NTSTATUS *Status)
{
	UNREFERENCED_PARAMETER(DeviceType);
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(PartitionNumber);
	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;

	if (!IsProtect)
	{
		return FALSE;
	}

	if (DeviceNumber >= sizeof(ProtectDiskList) / sizeof(*ProtectDiskList) || !ProtectDiskList[DeviceNumber].BitmapDeny)
	{
		return FALSE;
	}

	switch (ControlCode)
	{
	// 防止通过发送SCSI指令绕过还原
	case IOCTL_SCSI_PASS_THROUGH:
	case IOCTL_SCSI_PASS_THROUGH_DIRECT:
		*Status = Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		LogInfo("Denied SCSI passthrough request to %wZ on disk %d\n", PhysicalDeviceName, DeviceNumber);
		return TRUE;
	// 防止修改分区表
	case IOCTL_DISK_SET_DRIVE_LAYOUT:
	case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
	case IOCTL_DISK_DELETE_DRIVE_LAYOUT:
	case IOCTL_DISK_SET_PARTITION_INFO:
	case IOCTL_DISK_SET_PARTITION_INFO_EX:
	case IOCTL_DISK_GROW_PARTITION:
		*Status = Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		LogInfo("Denied set partition information request to %wZ on disk %d\n", PhysicalDeviceName, DeviceNumber);
		return TRUE;
	// 防止格式化硬盘
	case IOCTL_DISK_COPY_DATA:
	case IOCTL_DISK_CREATE_DISK:
	case IOCTL_DISK_FORMAT_TRACKS:
	case IOCTL_DISK_FORMAT_TRACKS_EX:
	case IOCTL_DISK_VERIFY:
	case IOCTL_DISK_REASSIGN_BLOCKS:
	case IOCTL_DISK_REASSIGN_BLOCKS_EX:
	case IOCTL_STORAGE_FIRMWARE_DOWNLOAD:
	case IOCTL_STORAGE_PROTOCOL_COMMAND:
		*Status = Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		LogInfo("Denied IOCTL 0x%.8X request to %wZ on disk %d\n", ControlCode, PhysicalDeviceName, DeviceNumber);
		return TRUE;
	default:
		break;
	}

	return FALSE;
}

// 处理对过滤器设备的IRP
BOOLEAN
OnDiskFilterDispatchControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	NTSTATUS *Status)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	*Status = STATUS_SUCCESS;
	ULONG info = 0;
	if (StackLocation->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG InBufferLength = StackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG OutBufferLength = StackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		ULONG ControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;

		*Status = STATUS_INVALID_DEVICE_REQUEST;
		switch (ControlCode)
		{
		case DISKFILTER_IOCTL_DRIVER_CONTROL:
			if (InBufferLength == sizeof(DISKFILTER_CONTROL))
			{
				PDISKFILTER_CONTROL Data = (PDISKFILTER_CONTROL)SystemBuffer;
				if (RtlEqualMemory(Data->AuthorizationContext, DiskFilter_AuthorizationContext, 128))
				{
					if (Data->ControlCode == DISKFILTER_CONTROL_GET_BUFFER_STATUS)
					{
						if (OutBufferLength >= sizeof(DISKFILTER_BUFFER_STATUS))
						{
							UINT VolNum = *(UINT *)Data->Password;
							USHORT DiskNum = DISKFILTER_DISKNUM_FROM_VOLNUM(VolNum);
							USHORT PartNum = DISKFILTER_PARTNUM_FROM_VOLNUM(VolNum);
							PVOLUME_INFO Volume = FindProtectVolume(DiskNum, PartNum);
							if (Volume != NULL)
							{
								ULONGLONG SectorUsed = DPBitmap_Count(Volume->BitmapRedirectUsed, TRUE);
								ULONGLONG SectorFree = DPBitmap_Count(Volume->BitmapUsed, FALSE);
								DISKFILTER_BUFFER_STATUS BufferStatus;
								BufferStatus.BytesVolumeTotal = Volume->BytesTotal;
								BufferStatus.BytesBufferTotal = (SectorUsed + SectorFree) * Volume->BytesPerSector;
								BufferStatus.BytesUsed = SectorUsed * Volume->BytesPerSector;
								BufferStatus.BytesFree = SectorFree * Volume->BytesPerSector;
								RtlCopyMemory(SystemBuffer, &BufferStatus, sizeof(BufferStatus));
								info = sizeof(BufferStatus);
								*Status = STATUS_SUCCESS;
							}
							else
							{
								*Status = STATUS_NOT_FOUND;
							}
						}
						else
						{
							*Status = STATUS_BUFFER_TOO_SMALL;
						}
						break;
					}
					Data->Password[sizeof(Data->Password) / sizeof(Data->Password[0]) - 1] = L'\0';
					UCHAR Password[32];
					RtlZeroMemory(Password, 32);
					SHA256(Data->Password, wcslen(Data->Password) * sizeof(WCHAR), Password);
					BOOLEAN NewConfigValid = IsValidConfig(&NewConfig);
					BOOLEAN CurConfigValid = IsValidConfig(&Config);
					if (!NewConfigValid && !CurConfigValid)
					{
						*Status = STATUS_UNSUCCESSFUL;
						break;
					}
					if ((NewConfigValid && !RtlEqualMemory(Password, NewConfig.Password, 32)) || (!NewConfigValid && CurConfigValid && !RtlEqualMemory(Password, Config.Password, 32)))
					{
						*Status = STATUS_ACCESS_DENIED;
						if (IsProtect)
							LogErrorMessageWithString(FilterDevice, MSG_FAILED_LOGIN_ATTEMPT, Data->Password, (ULONG)wcslen(Data->Password));
						break;
					}
					switch (Data->ControlCode)
					{
					case DISKFILTER_CONTROL_GETCONFIG:
						if (OutBufferLength >= sizeof(NewConfig))
						{
							RtlCopyMemory(SystemBuffer, &NewConfig, sizeof(NewConfig));
							info = sizeof(NewConfig);
							*Status = STATUS_SUCCESS;
						}
						else
						{
							*Status = STATUS_BUFFER_TOO_SMALL;
						}
						break;
					case DISKFILTER_CONTROL_SETCONFIG:
					{
						RtlCopyMemory(&NewConfig, &Data->Config, sizeof(NewConfig));
						if (IsValidConfig(&NewConfig))
						{
							UCHAR Mask = (UCHAR)(PROTECTION_ALLOW_DRIVER_LOAD | PROTECTION_DRIVER_WHITELIST | PROTECTION_DRIVER_BLACKLIST);
							UCHAR NewFlags = (Config.ProtectionFlags & ~Mask) | (NewConfig.ProtectionFlags & Mask);
							InterlockedExchange8((PCHAR)&Config.ProtectionFlags, NewFlags);
							ExAcquireResourceExclusiveLite(&DriverListLock, TRUE);
							InterlockedExchange8((PCHAR)&Config.DriverCount, NewConfig.DriverCount);
							RtlCopyMemory(Config.DriverList, NewConfig.DriverList, sizeof(Config.DriverList));
							ExReleaseResourceLite(&DriverListLock);
						}
						*Status = WriteProtectionConfig(&NewConfig);
						break;
					}
					case DISKFILTER_CONTROL_GETSTATUS:
						if (OutBufferLength >= sizeof(DISKFILTER_STATUS))
						{
							DISKFILTER_STATUS CurStatus;
							RtlZeroMemory(&CurStatus, sizeof(CurStatus));
							CurStatus.AllowDriverLoad = AllowLoadDriver;
							CurStatus.ProtectEnabled = IsProtect;
							CurStatus.DirectMountEnabled = AllowDirectMount;
							CurStatus.ProtectVolumeCount = (UCHAR)ValidVolumeCount;
							for (UCHAR i = 0; i < ValidVolumeCount; i++)
							{
								CurStatus.ProtectVolume[i] = DISKFILTER_MAKE_VOLNUM(ProtectVolumeList[i].DiskNumber, ProtectVolumeList[i].PartitionNumber);
							}
							RtlCopyMemory(SystemBuffer, &CurStatus, sizeof(CurStatus));
							info = sizeof(CurStatus);
							*Status = STATUS_SUCCESS;
						}
						else
						{
							*Status = STATUS_BUFFER_TOO_SMALL;
						}
						break;
					case DISKFILTER_CONTROL_ALLOW_DRIVER_LOAD:
						InterlockedExchange8((PCHAR)&AllowLoadDriver, TRUE);
						*Status = STATUS_SUCCESS;
						break;
					case DISKFILTER_CONTROL_DENY_DRIVER_LOAD:
						InterlockedExchange8((PCHAR)&AllowLoadDriver, FALSE);
						*Status = STATUS_SUCCESS;
						break;
					case DISKFILTER_CONTROL_MOUNT_DIRECT_DISK:
					{
						if (!AllowDirectMount)
						{
							*Status = STATUS_INVALID_DEVICE_REQUEST;
							break;
						}
						DISKFILTER_DIRECTDISK DirectDiskInfo;
						RtlCopyMemory(&DirectDiskInfo, &Data->Config, sizeof(DirectDiskInfo));
						if (FindDirectDiskDeviceByPartition(FilterDevice->DriverObject, DirectDiskInfo.DiskNumber, DirectDiskInfo.PartitionNumber))
						{
							*Status = STATUS_OBJECT_NAME_COLLISION;
							break;
						}
						PVOLUME_INFO ProtectedVolume = FindProtectVolume(DirectDiskInfo.DiskNumber, DirectDiskInfo.PartitionNumber);
						if (ProtectedVolume == NULL)
						{
							*Status = STATUS_NOT_FOUND;
							break;
						}
						*Status = DirectDiskMount(FilterDevice->DriverObject, DirectDiskCount, DirectDiskInfo.DriveLetter, ProtectedVolume, DirectDiskInfo.ReadOnly);
						if (NT_SUCCESS(*Status))
						{
							InterlockedIncrement((PLONG)&DirectDiskCount);
							WCHAR strMsg[512];
							swprintf_s(strMsg, 512, L"(%lu,%lu)", DirectDiskInfo.DiskNumber, DirectDiskInfo.PartitionNumber);
							LogErrorMessageWithString(FilterDevice, MSG_DIRECT_MOUNT_OK, strMsg, (ULONG)wcslen(strMsg));
						}
						break;
					}
					case DISKFILTER_CONTROL_UNMOUNT_DIRECT_DISK:
					{
						if (!AllowDirectMount)
						{
							*Status = STATUS_INVALID_DEVICE_REQUEST;
							break;
						}
						ULONG Number;
						RtlCopyMemory(&Number, &Data->Config, sizeof(Number));
						PDEVICE_OBJECT DirectDiskDev = FindDirectDiskDevice(FilterDevice->DriverObject, Number);
						if (DirectDiskDev == NULL)
						{
							*Status = STATUS_NOT_FOUND;
							break;
						}
						DISKFILTER_DIRECTDISK DirectDiskCfg;
						DirectDiskCfg.DiskNumber = (ULONG)-1;
						DirectDiskCfg.PartitionNumber = (ULONG)-1;
						DirectDiskGetConfig(DirectDiskDev, &DirectDiskCfg);
						*Status = DirectDiskUnmount(DirectDiskDev);
						if (NT_SUCCESS(*Status))
						{
							WCHAR strMsg[512];
							swprintf_s(strMsg, 512, L"(%lu,%lu)", DirectDiskCfg.DiskNumber, DirectDiskCfg.PartitionNumber);
							LogErrorMessageWithString(FilterDevice, MSG_DIRECT_UNMOUNT_OK, strMsg, (ULONG)wcslen(strMsg));
						}
						break;
					}
					case DISKFILTER_CONTROL_GET_DIRECTDISK_STATUS:
						if (OutBufferLength >= sizeof(DISKFILTER_DIRECTDISK_STATUS))
						{
							DISKFILTER_DIRECTDISK_STATUS CurStatus;
							RtlZeroMemory(&CurStatus, sizeof(CurStatus));
							PDEVICE_OBJECT CurDeviceObject;
							ULONG TotalCount = 0;
							CurDeviceObject = FilterDevice->DriverObject->DeviceObject;
							while (CurDeviceObject)
							{
								if (IsDirectDiskDevice(CurDeviceObject))
								{
									if (TotalCount < sizeof(CurStatus.MountVolume) / sizeof(*CurStatus.MountVolume))
									{
										DirectDiskGetConfig(CurDeviceObject, &CurStatus.MountVolume[TotalCount]);
										TotalCount++;
									}
								}
								CurDeviceObject = CurDeviceObject->NextDevice;
							}
							CurStatus.MountVolumeCount = (UCHAR)TotalCount;
							RtlCopyMemory(SystemBuffer, &CurStatus, sizeof(CurStatus));
							info = sizeof(CurStatus);
							*Status = STATUS_SUCCESS;
						}
						else
						{
							*Status = STATUS_BUFFER_TOO_SMALL;
						}
						break;
					case DISKFILTER_CONTROL_SET_SAVE_DATA:
					{
						DISKFILTER_SAVEDATA SaveDataInfo;
						RtlCopyMemory(&SaveDataInfo, &Data->Config, sizeof(SaveDataInfo));
						PVOLUME_INFO ProtectedVolume = FindProtectVolume(SaveDataInfo.DiskNumber, SaveDataInfo.PartitionNumber);
						if (ProtectedVolume == NULL || !ProtectedVolume->CanSaveData)
						{
							*Status = STATUS_NOT_FOUND;
							break;
						}
						if (ProtectedVolume->ShutdownSaveData || ProtectedVolume->SavingData)
						{
							*Status = STATUS_OBJECT_NAME_COLLISION;
							break;
						}
						InterlockedExchange8((PCHAR)&ProtectedVolume->ShutdownSaveData, TRUE);
						*Status = STATUS_SUCCESS;
						WCHAR strMsg[512];
						swprintf_s(strMsg, 512, L"(%lu,%lu)", SaveDataInfo.DiskNumber, SaveDataInfo.PartitionNumber);
						LogErrorMessageWithString(FilterDevice, MSG_SET_SAVEDATA_OK, strMsg, (ULONG)wcslen(strMsg));
						break;
					}
					case DISKFILTER_CONTROL_CANCEL_SAVE_DATA:
					{
						DISKFILTER_SAVEDATA SaveDataInfo;
						RtlCopyMemory(&SaveDataInfo, &Data->Config, sizeof(SaveDataInfo));
						PVOLUME_INFO ProtectedVolume = FindProtectVolume(SaveDataInfo.DiskNumber, SaveDataInfo.PartitionNumber);
						if (ProtectedVolume == NULL || !ProtectedVolume->CanSaveData)
						{
							*Status = STATUS_NOT_FOUND;
							break;
						}
						InterlockedExchange8((PCHAR)&ProtectedVolume->ShutdownSaveData, FALSE);
						*Status = STATUS_SUCCESS;
						WCHAR strMsg[512];
						swprintf_s(strMsg, 512, L"(%lu,%lu)", SaveDataInfo.DiskNumber, SaveDataInfo.PartitionNumber);
						LogErrorMessageWithString(FilterDevice, MSG_CANCEL_SAVEDATA_OK, strMsg, (ULONG)wcslen(strMsg));
						break;
					}
					case DISKFILTER_CONTROL_GET_SAVE_DATA:
						if (OutBufferLength >= sizeof(DISKFILTER_SAVEDATA_STATUS))
						{
							DISKFILTER_SAVEDATA_STATUS CurStatus;
							RtlZeroMemory(&CurStatus, sizeof(CurStatus));
							ULONG TotalCount = 0;
							for (UINT i = 0; i < ValidVolumeCount; i++)
							{
								if (ProtectVolumeList[i].ShutdownSaveData && ProtectVolumeList[i].CanSaveData)
								{
									if (TotalCount < sizeof(CurStatus.SaveDataVolume) / sizeof(*CurStatus.SaveDataVolume))
									{
										CurStatus.SaveDataVolume[TotalCount].DiskNumber = ProtectVolumeList[i].DiskNumber;
										CurStatus.SaveDataVolume[TotalCount].PartitionNumber = ProtectVolumeList[i].PartitionNumber;
										TotalCount++;
									}
								}
							}
							CurStatus.SaveDataCount = (UCHAR)TotalCount;
							RtlCopyMemory(SystemBuffer, &CurStatus, sizeof(CurStatus));
							info = sizeof(CurStatus);
							*Status = STATUS_SUCCESS;
						}
						else
						{
							*Status = STATUS_BUFFER_TOO_SMALL;
						}
						break;
					default:
						break;
					}
				}
			}
		default:
			break;
		}
	}
	Irp->IoStatus.Status = *Status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return TRUE;
}

// 处理关机事件
BOOLEAN
OnDiskFilterDispatchShutdown(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	NTSTATUS *Status)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	if (StackLocation->MajorFunction == IRP_MJ_SHUTDOWN)
	{
		BOOLEAN NeedSaveData = FALSE;
		for (UINT i = 0; i < ValidVolumeCount; i++)
		{
			if (ProtectVolumeList[i].ShutdownSaveData)
			{
				if (!NeedSaveData)
				{
					LogInfo("Enter data saving process...\n");
					if (!DisableShutdownMessage)
						InitDisplay();
					DisplayString(L"DiskFilter is saving data...\nPlease do not shut down or restart the computer.\n");
					NeedSaveData = TRUE;
				}
				InterlockedExchange8((PCHAR)&ProtectVolumeList[i].SavingData, TRUE);
				KeSetEvent(
					&ProtectVolumeList[i].RequestEvent,
					(KPRIORITY)0,
					FALSE);
				KeWaitForSingleObject(
					&ProtectVolumeList[i].FinishSaveDataEvent,
					Executive,
					KernelMode,
					FALSE,
					NULL
				);
			}
		}
	}
	Irp->IoStatus.Status = *Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return TRUE;
}

// 加载驱动回调
void LoadDriverNotify(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	UNREFERENCED_PARAMETER(ProcessId);
	static BOOL IsInit = FALSE;

	if (!IsInit && FullImageName && wcsstr_n(FullImageName->Buffer, FullImageName->Length / sizeof(WCHAR), L"winlogon.exe"))
	{
		// 在winlogon启动之前重新找一遍保护卷，并启动驱动防护
		if (Config.ProtectionFlags & PROTECTION_ENABLE)
		{
			LogInfo("Reinit volume information\n");
			InitProtectVolumes();
		}
		IsInit = TRUE;

		if (Config.ProtectionFlags & PROTECTION_ALLOW_DRIVER_LOAD) // 直接允许驱动加载
			AllowLoadDriver = TRUE;
		else if (Config.ProtectionFlags & PROTECTION_DRIVER_BLACKLIST) // 启用黑名单防护
			AllowLoadDriver = FALSE;
		else if ((Config.ProtectionFlags & PROTECTION_DRIVER_WHITELIST) && FindProtectVolumeByDevice(GetVolumeDeviceByFileName(FullImageName))) // 启用白名单防护，且系统分区被保护
			AllowLoadDriver = FALSE;
		else // 未启用防护或系统分区不被保护
			AllowLoadDriver = TRUE;
		return;
	}

	if (!IsInit || AllowLoadDriver || !ImageInfo->SystemModeImage || FullImageName == NULL || FullImageName->Length == 0 || FullImageName->Buffer == NULL)
	{
		return;
	}

	// 启用白名单防护时允许加载已经在硬盘上的驱动
	if ((Config.ProtectionFlags & PROTECTION_DRIVER_WHITELIST) && NT_SUCCESS(IsFileCreditable(FullImageName)))
	{
		return;
	}

	// 对驱动文件进行哈希比对
	UCHAR ImageHash[32];
	if (NT_SUCCESS(GetImageHash(FullImageName, ImageHash)))
	{
		UINT *hash = (UINT*)ImageHash;
		LogInfo("File %wZ Hash %.8X%.8X%.8X%.8X%.8X%.8X%.8X%.8X\n", FullImageName, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
		ExAcquireResourceSharedLite(&DriverListLock, TRUE);
		BOOL HashInList = IsHashInList(Config.DriverList, Config.DriverCount, ImageHash);
		ExReleaseResourceLite(&DriverListLock);
		if ((Config.ProtectionFlags & PROTECTION_DRIVER_WHITELIST) && HashInList)
		{
			LogInfo("In white list\n");
			return;
		}
		else if ((Config.ProtectionFlags & PROTECTION_DRIVER_BLACKLIST) && !HashInList)
		{
			LogInfo("Not in black list\n");
			return;
		}
	}

	// 禁止加载驱动
#if defined(i386) || defined(AMD64)
#ifdef AMD64
	/*
	B8 220000C0    mov     eax, C0000022h // STATUS_ACCESS_DENIED
	C3             ret
	*/
	BYTE PatchCode[] = "\xB8\x22\x00\x00\xC0\xC3";
#else
	/*
	B8 220000C0    mov     eax, C0000022h // STATUS_ACCESS_DENIED
	C2 0800        retn    8
	*/
	BYTE PatchCode[] = "\xB8\x22\x00\x00\xC0\xC2\x08\x00";
#endif
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;

	if (ImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageInfo->ImageBase + ImageDosHeader->e_lfanew);
		if (ImageNtHeaders->Signature == IMAGE_NT_SIGNATURE)
		{
			LogInfo("Denied driver %wZ\n", FullImageName);
			LogErrorMessageWithString(FilterDevice, MSG_DRIVER_LOAD_DENIED, FullImageName->Buffer, FullImageName->Length / 2);
			WriteReadOnlyMemory((PUCHAR)ImageInfo->ImageBase + ImageNtHeaders->OptionalHeader.AddressOfEntryPoint, PatchCode, sizeof(PatchCode) - 1);
		}
	}
#endif
}

// 卸载驱动时被调用，由于是硬盘过滤驱动，此驱动不能被卸载
VOID
OnDiskFilterUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNICODE_STRING dosDeviceName;

	RtlInitUnicodeString(&dosDeviceName, DISKFILTER_DOS_DEVICE_NAME_W);

	IoDeleteSymbolicLink(&dosDeviceName);

	if (FilterDevice)
		IoDeleteDevice(FilterDevice);

	LogInfo("Driver unloaded\n");
	KeBugCheck(SYSTEM_SERVICE_EXCEPTION);
}

// 启动驱动加载完毕时被调用
void DriverReinit(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count)
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Count);
	NTSTATUS status;

	status = ReadProtectionConfig(&ConfigPath, &Config);
	if (!NT_SUCCESS(status))
	{
		LogErr("Failed to read protection config file (%wZ) ! status=0x%.8X\n", &ConfigPath, status);
		LogErrorMessageWithString(FilterDevice, MSG_FAILED_TO_LOAD_CONFIG, ConfigPath.Buffer, ConfigPath.Length);
		return;
	}
	// 让“不允许加载驱动”的选项在重启后失效，自动变为驱动白名单
	if ((Config.ProtectionFlags & (PROTECTION_ALLOW_DRIVER_LOAD | PROTECTION_DRIVER_WHITELIST | PROTECTION_DRIVER_BLACKLIST)) == 0)
	{
		Config.ProtectionFlags |= PROTECTION_DRIVER_WHITELIST;
	}
	RtlCopyMemory(&NewConfig, &Config, sizeof(Config));

	CheckThawSpace();

	if (Config.ProtectionFlags & PROTECTION_ALLOW_DIRECT_MOUNT)
	{
		AllowDirectMount = TRUE;
	}

	if (Config.ProtectionFlags & PROTECTION_ENABLE)
	{
		InitProtectDisks();
		StartProtect();
		InitProtectVolumes();
		IoRegisterLastChanceShutdownNotification(FilterDevice);

		LogErrorMessage(FilterDevice, MSG_PROTECTION_ENABLED);
	}
	else
	{
		LogErrorMessage(FilterDevice, MSG_PROTECTION_DISABLED);
	}

	if (Config.ProtectionFlags & PROTECTION_ALLOW_DRIVER_LOAD)
	{
		LogErrorMessage(FilterDevice, MSG_DRIVER_ALLOW_LOAD);
	}
	else if (Config.ProtectionFlags & PROTECTION_DRIVER_WHITELIST)
	{
		LogErrorMessage(FilterDevice, MSG_DRIVER_WHITELIST);
	}
	else if (Config.ProtectionFlags & PROTECTION_DRIVER_BLACKLIST)
	{
		LogErrorMessage(FilterDevice, MSG_DRIVER_BLACKLIST);
	}
	else
	{
		LogErrorMessage(FilterDevice, MSG_DRIVER_DENY_LOAD);
	}

	if (Config.ProtectionFlags & PROTECTION_ENABLE_THAWSPACE)
	{
		if (NT_SUCCESS(ThawSpaceInit(DriverObject, Config.ThawSpaceCount)))
		{
			LogErrorMessage(FilterDevice, MSG_THAWSPACE_ENABLED);
		}
		else
		{
			LogErrorMessage(FilterDevice, MSG_FAILED_TO_INIT_THAWSPACE);
		}
	}

	InitThawSpace();

	DirectDiskInit(DriverObject);

	PsSetLoadImageNotifyRoutine(&LoadDriverNotify);

	LogInfo("Initialize success\n");
	LogErrorMessage(FilterDevice, MSG_INIT_SUCCESS);
}

PDEVICE_OBJECT
OnDiskFilterInitialization(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS			status;
	PDEVICE_OBJECT		deviceObject = NULL;
	UNICODE_STRING		ntDeviceName;
	UNICODE_STRING		dosDeviceName;
	UNICODE_STRING		sddl;

	LogInfo("Driver loaded\n");

	mempool_init();

	FilterDevice = NULL;
	ValidVolumeCount = 0;
	ConfigFileObject = NULL;
	memset(LowerDeviceObject, 0, sizeof(LowerDeviceObject));
	memset(&Config, 0, sizeof(Config));
	memset(&NewConfig, 0, sizeof(NewConfig));
	ExInitializeResourceLite(&DriverListLock);
	memset(ProtectVolumeList, 0, sizeof(ProtectVolumeList));
	memset(VolumeList, 0, sizeof(VolumeList));
	ValidVolumeCount = 0;
	memset(ProtectDiskList, 0, sizeof(ProtectDiskList));
	memset(&ConfigVolume, 0, sizeof(ConfigVolume));
	ConfigVcnPairs = NULL;
	IsProtect = FALSE;
	AllowLoadDriver = TRUE;
	AllowDirectMount = FALSE;
	DirectDiskCount = 0;
	DisableStartupMessage = 0;
	DisableShutdownMessage = 0;

	RtlInitUnicodeString(&ntDeviceName, DISKFILTER_DEVICE_NAME_W);

	RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

	status = IoCreateDeviceSecure(
		DriverObject,
		0,								// DeviceExtensionSize
		&ntDeviceName,					// DeviceName
		FILE_DEVICE_DISKFLT,			// DeviceType
		0,								// DeviceCharacteristics
		TRUE,							// Exclusive
		&sddl,							// DefaultSDDLString
		NULL,							// DeviceClassGuid
		&deviceObject					// [OUT]
	);

	if (!NT_SUCCESS(status))
	{
		LogErr("IoCreateDevice failed. status = 0x%.8X\n", status);
		return NULL;
	}

	RtlInitUnicodeString(&dosDeviceName, DISKFILTER_DOS_DEVICE_NAME_W);

	status = IoCreateSymbolicLink(&dosDeviceName, &ntDeviceName);
	if (!NT_SUCCESS(status))
	{
		LogErr("IoCreateSymbolicLink failed. status = 0x%.8X\n", status);
		LogErrorMessage(deviceObject, MSG_FAILED_TO_INIT);
		goto failed;
	}

	WCHAR strAppend[] = L"\\Parameters";
	SIZE_T TotalLen = RegistryPath->Length / 2 + wcslen(strAppend) + 10;
	PWCHAR strRegPath = (PWCHAR)__malloc(TotalLen * sizeof(WCHAR));
	if (strRegPath)
	{
		UNICODE_STRING uniRegPath;
		swprintf_s(strRegPath, TotalLen, L"%wZ%ls", RegistryPath, strAppend);
		RtlInitUnicodeString(&uniRegPath, strRegPath);
		ULONG NeedSize = 0;
		status = ReadRegString(&uniRegPath, L"ConfigPath", NULL, 0, &NeedSize);
		if (NeedSize > 0)
		{
			ULONG CurSize = 0;
			PWCHAR strBuf = (PWCHAR)__malloc(NeedSize);
			if (strBuf)
			{
				status = ReadRegString(&uniRegPath, L"ConfigPath", strBuf, NeedSize, &CurSize);
				RtlInitUnicodeString(&ConfigPath, strBuf);
			}
			else
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
			}
		}
		ReadRegDword(&uniRegPath, L"DisableStartupMessage", &DisableStartupMessage);
		ReadRegDword(&uniRegPath, L"DisableShutdownMessage", &DisableShutdownMessage);
		__free(strRegPath);
	}
	else
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	if (!NT_SUCCESS(status))
	{
		LogErr("Failed to read config file path! status=0x%.8X\n", status);
		LogErrorMessage(deviceObject, MSG_FAILED_TO_INIT);
		goto failed;
	}

	FilterDevice = deviceObject;

	IoRegisterBootDriverReinitialization(DriverObject, DriverReinit, NULL);

	if (NT_SUCCESS(status))
		return deviceObject;

failed:
	IoDeleteSymbolicLink(&dosDeviceName);

	if (deviceObject)
		IoDeleteDevice(deviceObject);
	return NULL;
}

// 发现硬盘设备时被调用
VOID
OnDiskFilterNewDisk(
	IN PDEVICE_OBJECT DeviceObject,
	IN PUNICODE_STRING PhysicalDeviceName,
	IN ULONG DeviceType,
	IN ULONG DeviceNumber,
	IN ULONG PartitionNumber
)
{
	// 保存设备
	if (DeviceNumber < sizeof(LowerDeviceObject) / sizeof(*LowerDeviceObject))
	{
		LowerDeviceObject[DeviceNumber] = DeviceObject;
	}
	LogInfo("New disk found: %wZ type is %d on disk %d partition %d\n", PhysicalDeviceName, DeviceType, DeviceNumber, PartitionNumber);
}

// 设备被移除时调用
VOID
OnDiskFilterRemoveDisk(
	IN PDEVICE_OBJECT DeviceObject,
	IN PUNICODE_STRING PhysicalDeviceName
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	LogInfo("Disk %wZ removed\n", PhysicalDeviceName);
}