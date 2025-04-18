#include "diskfltlib.h"
#include "DPBitmap.h"
#include "Utils.h"
#include "IrpFile.h"
#include "mempool/mempool.h"
#include <ntimage.h>
#include <ntddscsi.h>
#include <wchar.h>
#include <ntdddisk.h>
#include "messages.h"
#include "ThawSpace.h"

// 引入函数，用于在屏幕上显示文字
EXTERN_C VOID InbvAcquireDisplayOwnership(VOID);
EXTERN_C VOID InbvResetDisplay(VOID);
EXTERN_C INT InbvSetTextColor(INT color); //IRBG
EXTERN_C VOID InbvDisplayString(PSZ text);
EXTERN_C VOID InbvSolidColorFill(ULONG left, ULONG top, ULONG width, ULONG height, ULONG color);
EXTERN_C VOID InbvSetScrollRegion(ULONG left, ULONG top, ULONG width, ULONG height);
EXTERN_C VOID InbvInstallDisplayStringFilter(ULONG b);
EXTERN_C VOID InbvEnableDisplayString(ULONG b);

// 扇区重定向信息
typedef struct
{
	ULONGLONG	OriginalIndex;		// 原始簇地址
	ULONGLONG	MappedIndex;		// 重定向后的地址
} REDIRECT_INFO, *PREDIRECT_INFO;

// 保护卷所用到的信息
typedef struct _VOLUME_INFO
{
	WCHAR		Volume;				// 盘符

	ULONG		DiskNumber;			// 此卷所在的硬盘号

	DWORD		PartitionNumber;	// 分区索引
	BYTE		PartitionType;		// 分区类型

	LONGLONG	StartOffset;		// 分区在磁盘里的偏移也就是开始地址

	LONGLONG	BytesTotal;			// 这个卷的总大小，以byte为单位
	ULONG		BytesPerSector;		// 每个扇区的大小
	ULONG		BytesPerCluster;	// 每簇大小
	ULONGLONG	FirstDataSector;	// 第一个扇区的开始地址，也指位图上第一个簇的开始地址,NTFS固定为0,FAT专有

	// 此卷逻辑上有多少个扇区
	ULONGLONG		SectorCount;

	// 标记空闲扇区 空扇区bit为0, 初始化的时候复制bitMap_OR
	PDP_BITMAP		BitmapUsed;
	// 标记扇区是否重定向
	PDP_BITMAP		BitmapRedirect;
	// 直接放过读写的扇区(force write)，如pagefile.sys hiberfil.sys, 位图跟是磁盘逻辑位图的一小部分
	PDP_BITMAP		BitmapAllow;

	// 上次扫描的空闲扇区的位置
	ULONGLONG		LastScanIndex;

	// 扇区重定向表
	RTL_GENERIC_TABLE	RedirectMap;

	//这个卷上的保护系统使用的请求队列
	LIST_ENTRY				ListHead;
	//这个卷上的保护系统使用的请求队列的锁
	KSPIN_LOCK				ListLock;
	//这个卷上的保护系统使用的请求队列的同步事件
	KEVENT					RequestEvent;
	//这个卷上的保护系统使用的请求队列的处理线程之线程句柄
	PVOID					ReadWriteThread;
	CLIENT_ID				ReadWriteThreadId;
	//请求队列的处理线程结束标志
	BOOLEAN					ThreadTerminate;

} VOLUME_INFO, *PVOLUME_INFO;

// 保护配置文件路径、文件对象、所在盘符、所在扇区
UNICODE_STRING ConfigPath;
PFILE_OBJECT ConfigFileObject;
VOLUME_INFO ConfigVolume;
PRETRIEVAL_POINTERS_BUFFER ConfigVcnPairs;

PDEVICE_OBJECT LowerDeviceObject[256]; // 硬盘的下层设备
PDEVICE_OBJECT FilterDevice; // 当前过滤器设备
DISKFILTER_PROTECTION_CONFIG Config, NewConfig; // 当前保护配置、新配置
VOLUME_INFO ProtectVolumeList[256]; // 保护卷列表
PVOLUME_INFO VolumeList[26]; // 盘符对应的保护卷
UINT VaildVolumeCount; // 保护卷数量
BOOLEAN IsProtect; // 是否在保护状态
BOOLEAN AllowLoadDriver; // 是否允许加载驱动

// 读写操作线程
void ThreadReadWrite(PVOID Context);

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
NTSTATUS ReadProtectionConfig(PUNICODE_STRING ConfigPath, PDISKFILTER_PROTECTION_CONFIG RetConfig)
{
	NTSTATUS status;
	PDISKFILTER_PROTECTION_CONFIG Conf = NULL;
	IO_STATUS_BLOCK IoStatus = { 0 };
	HANDLE ConfigHandle;
	PFILE_OBJECT ConfigFile;

	LogInfo("Reading config file (%wZ)\n", ConfigPath);

	if (!RetConfig)
		return STATUS_UNSUCCESSFUL;

	Conf = (PDISKFILTER_PROTECTION_CONFIG)__malloc(sizeof(DISKFILTER_PROTECTION_CONFIG));
	if (!Conf)
		return STATUS_INSUFFICIENT_RESOURCES;

	WCHAR prefix[] = L"\\??\\";
	PWCHAR TempPath = (PWCHAR)__malloc(ConfigPath->Length + (wcslen(prefix) + 10) * sizeof(WCHAR));
	if (TempPath)
	{
		swprintf(TempPath, L"%ls%wZ", prefix, ConfigPath);
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, TempPath);
		if (NT_SUCCESS(GetFileHandleReadOnly(&ConfigHandle, &uniPath)))
		{
			if (NT_SUCCESS(ObReferenceObjectByHandle(ConfigHandle, 0, NULL, KernelMode, (PVOID *)&ConfigFile, NULL)))
			{
				UNICODE_STRING	uniDosName;
				// 得到类似C:这样的盘符，为了获取VolumeInfo
				if (NT_SUCCESS(IoVolumeDeviceToDosName(ConfigFile->DeviceObject, &uniDosName)))
				{
					WCHAR ConfigVolumeLetter = toupper(*(WCHAR *)uniDosName.Buffer);
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
	status = IrpCreateFile(&ConfigFileObject, FILE_ALL_ACCESS, ConfigPath, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NO_INTERMEDIATE_BUFFERING, NULL, 0);
	if (!NT_SUCCESS(status))
		return status;

	status = IrpReadFile(ConfigFileObject, &IoStatus, Conf, sizeof(DISKFILTER_PROTECTION_CONFIG), NULL);
	if (!NT_SUCCESS(status))
		return status;

	// 不需要关闭配置文件对象

	LogInfo("Magic=0x%.4X, Version=0x%.4X, Flags=%.2X\n", Conf->Magic, Conf->Version, Conf->ProtectionFlags);

	// 检查配置文件是否有效
	// 头部不匹配
	if (Conf->Magic != DISKFILTER_CONFIG_MAGIC)
		return STATUS_UNSUCCESSFUL + 10;

	// 版本不匹配
	if (Conf->Version != DISKFILTER_DRIVER_VERSION)
		return STATUS_UNSUCCESSFUL + 11;

	// 保护卷个数无效
	if (Conf->ProtectVolumeCount > sizeof(Conf->ProtectVolume) / sizeof(Conf->ProtectVolume[0]))
		return STATUS_UNSUCCESSFUL + 12;

	// 驱动白名单或黑名单个数无效
	if (Conf->DriverCount > sizeof(Conf->DriverList) / sizeof(Conf->DriverList[0]))
		return STATUS_UNSUCCESSFUL + 13;

	// 解冻空间个数无效
	if (Conf->ThawSpaceCount > sizeof(Conf->ThawSpacePath) / sizeof(Conf->ThawSpacePath[0]))
		return STATUS_UNSUCCESSFUL + 14;

	RtlCopyMemory(RetConfig, Conf, sizeof(DISKFILTER_PROTECTION_CONFIG));
	return STATUS_SUCCESS;
}

// 写入保护配置
NTSTATUS WriteProtectionConfig(PDISKFILTER_PROTECTION_CONFIG ConfigData)
{
	if (ConfigVolume.Volume == 0 || !ConfigVcnPairs || ConfigVcnPairs->Extents[0].Lcn.QuadPart == -1) // 配置文件不支持压缩
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

// 重定向表相关函数
RTL_GENERIC_COMPARE_RESULTS NTAPI CompareRoutine(
	PRTL_GENERIC_TABLE Table,
	PVOID FirstStruct,
	PVOID SecondStruct
)
{
	PREDIRECT_INFO first = (PREDIRECT_INFO)FirstStruct;
	PREDIRECT_INFO second = (PREDIRECT_INFO)SecondStruct;

	UNREFERENCED_PARAMETER(Table);

	if (first->OriginalIndex < second->OriginalIndex)
		return GenericLessThan;
	else if (first->OriginalIndex > second->OriginalIndex)
		return GenericGreaterThan;
	else
		return GenericEqual;
}

PVOID NTAPI AllocateRoutine(
	PRTL_GENERIC_TABLE Table,
	CLONG ByteSize
)
{
	UNREFERENCED_PARAMETER(Table);
	return __malloc(ByteSize);
}

void NTAPI FreeRoutine(
	PRTL_GENERIC_TABLE Table,
	PVOID Buffer
)
{
	UNREFERENCED_PARAMETER(Table);
	__free(Buffer);
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
		return status;
	}

	// 初始化位图
	for (i = 0; i < Bitmap->BitmapSize.QuadPart; i++)
	{
		if (bitmap_test((PULONG)Bitmap->Buffer, i))
		{
			ULONGLONG j = 0;
			ULONGLONG base = volumeInfo->FirstDataSector + (i * SectorsPerCluster);
			for (j = 0; j < SectorsPerCluster; j++)
			{
				if (!NT_SUCCESS(DPBitmap_Set(volumeInfo->BitmapUsed, base + j, TRUE)))
				{
					status = STATUS_UNSUCCESSFUL;
					goto out;
				}
			}
		}
	}

	// 初始化clusterMap
	RtlInitializeGenericTable(&volumeInfo->RedirectMap, CompareRoutine, AllocateRoutine, FreeRoutine, NULL);

	status = STATUS_SUCCESS;

out:

	if (!NT_SUCCESS(status))
	{
		if (volumeInfo->BitmapRedirect)
		{
			DPBitmap_Free(volumeInfo->BitmapRedirect);
			volumeInfo->BitmapRedirect = NULL;
		}
		if (volumeInfo->BitmapAllow)
		{
			DPBitmap_Free(volumeInfo->BitmapAllow);
			volumeInfo->BitmapAllow = NULL;
		}
		if (volumeInfo->BitmapUsed)
		{
			DPBitmap_Free(volumeInfo->BitmapUsed);
			volumeInfo->BitmapUsed = NULL;
		}
	}
	if (Bitmap)
		__free(Bitmap);

	return status;
}

// 设置文件数据直接读写
NTSTATUS SetDirectReadWriteFile(PVOLUME_INFO volume, PWCHAR path)
{
	NTSTATUS status;

	HANDLE fileHandle = (HANDLE)-1;

	ULONG   Cls, r, sectorsPerCluster;
	LARGE_INTEGER PrevVCN, Lcn;
	PRETRIEVAL_POINTERS_BUFFER pVcnPairs = NULL;
	WCHAR tempBuffer[MAX_PATH];
	UNICODE_STRING target;

	if (volume == NULL)
		return STATUS_UNSUCCESSFUL;

	swprintf_s(tempBuffer, MAX_PATH, L"\\Device\\Harddisk%d\\Partition%d%ls", volume->DiskNumber, volume->PartitionNumber, path);
	RtlInitUnicodeString(&target, tempBuffer);
	status = GetFileHandleReadOnly(&fileHandle, &target);
	if (!NT_SUCCESS(status))
	{
		goto out;
	}

	sectorsPerCluster = volume->BytesPerCluster / volume->BytesPerSector;

	pVcnPairs = (PRETRIEVAL_POINTERS_BUFFER)GetFileClusterList(fileHandle);

	if (!pVcnPairs || pVcnPairs->Extents[0].Lcn.QuadPart == -1) // 不支持被压缩的文件
	{
		status = STATUS_UNSUCCESSFUL;
		goto out;
	}

	PrevVCN = pVcnPairs->StartingVcn;
	for (r = 0, Cls = 0; r < pVcnPairs->ExtentCount; r++)
	{
		ULONG	CnCount;
		Lcn = pVcnPairs->Extents[r].Lcn;
		LONGLONG EndLcn = Lcn.QuadPart + pVcnPairs->Extents[r].NextVcn.QuadPart - PrevVCN.QuadPart - 1;
		LogInfo("Cluster %lld -> %lld (Sector %lld -> %lld) is allowed to direct write.\n", Lcn.QuadPart, EndLcn, volume->FirstDataSector + Lcn.QuadPart * sectorsPerCluster, volume->FirstDataSector + EndLcn * sectorsPerCluster);

		for (CnCount = (ULONG)(pVcnPairs->Extents[r].NextVcn.QuadPart - PrevVCN.QuadPart);
			CnCount; CnCount--, Cls++, Lcn.QuadPart++)
		{
			ULONGLONG	i = 0;
			ULONGLONG	base = volume->FirstDataSector + (Lcn.QuadPart * sectorsPerCluster);
			for (i = 0; i < sectorsPerCluster; i++)
			{
				// 设置位图
				DPBitmap_Set(volume->BitmapAllow, base + i, TRUE);
				DPBitmap_Set(volume->BitmapUsed, base + i, TRUE);
			}
		}

		PrevVCN = pVcnPairs->Extents[r].NextVcn;
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
					LogErrorMessageWithString(FilterDevice, MSG_THAWSPACE_LOAD_FAILED, Config.ThawSpacePath[i], wcslen(Config.ThawSpacePath[i]));
				}
			}
		}
	}
}

// 根据硬盘号和分区号获取保护卷
PVOLUME_INFO FindProtectVolume(ULONG DiskNum, DWORD PartitionNum)
{
	for (UINT i = 0; i < VaildVolumeCount; i++)
	{
		if (ProtectVolumeList[i].DiskNumber == DiskNum && ProtectVolumeList[i].PartitionNumber == PartitionNum)
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

// 初始化保护卷（获取保护卷信息、获取位图）
void InitProtectVolumes()
{
	for (UCHAR i = 0; i < Config.ProtectVolumeCount; i++)
	{
		USHORT DiskNum = Config.ProtectVolume[i] & 0xFFFF;
		USHORT PartitionNum = (Config.ProtectVolume[i] >> 16) & 0xFFFF;
		LogInfo("Protected volume: disk %hu partition %hu\n", DiskNum, PartitionNum);

		PVOLUME_INFO VolInfo = FindProtectVolume(DiskNum, PartitionNum);
		if (VolInfo)
		{
			LogInfo("Is a initialized volume\n");
			continue;
		}

		UINT Cur = VaildVolumeCount;
		if (NT_SUCCESS(GetVolumeInfo(DiskNum, PartitionNum, &ProtectVolumeList[Cur])))
		{
			LogInfo("Found vaild volume on disk %hu partition %hu\n", DiskNum, PartitionNum);
			if (NT_SUCCESS(InitVolumeLogicBitmap(&ProtectVolumeList[Cur])))
			{
				LogInfo("Successfully get volume logic bitmap\n");
				// 只有在成功获取位图之后，才认为这个卷有效

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
					//获取处理线程的对象
					status = ObReferenceObjectByHandle(
						ThreadHandle,
						THREAD_ALL_ACCESS,
						NULL,
						KernelMode,
						&ProtectVolumeList[Cur].ReadWriteThread,
						NULL
					);

					if (NULL != ThreadHandle)
						ZwClose(ThreadHandle);

					if (NT_SUCCESS(status))
					{
						VaildVolumeCount = Cur + 1;
					}
					else
					{
						ProtectVolumeList[Cur].ThreadTerminate = TRUE;
						KeSetEvent(
							&ProtectVolumeList[Cur].RequestEvent,
							(KPRIORITY)0,
							FALSE
						);
						LogErr("Failed to get thread handle\n");
						WCHAR strMsg[512];
						swprintf_s(strMsg, 512, L"(%hu,%hu)", DiskNum, PartitionNum);
						LogErrorMessageWithString(FilterDevice, MSG_PROTECT_VOLUME_LOAD_FAILED, strMsg, wcslen(strMsg));
					}
				}
				else
				{
					LogInfo("Failed to create handler thread\n");
					WCHAR strMsg[512];
					swprintf_s(strMsg, 512, L"(%hu,%hu)", DiskNum, PartitionNum);
					LogErrorMessageWithString(FilterDevice, MSG_PROTECT_VOLUME_LOAD_FAILED, strMsg, wcslen(strMsg));
				}
			}
			else
			{
				LogInfo("Failed to get volume logic bitmap\n");
				WCHAR strMsg[512];
				swprintf_s(strMsg, 512, L"(%hu,%hu)", DiskNum, PartitionNum);
				LogErrorMessageWithString(FilterDevice, MSG_PROTECT_VOLUME_LOAD_FAILED, strMsg, wcslen(strMsg));
			}
		}
	}
	LogInfo("VaildVolumeCount = %u\n", VaildVolumeCount);

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
				ofn->FileNameLength = wcslen(ofn->FileName);
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
				LogErrorMessageWithString(FilterDevice, MSG_THAWSPACE_LOAD_OK, Config.ThawSpacePath[i], wcslen(Config.ThawSpacePath[i]));
			}
			else
			{
				LogErrorMessageWithString(FilterDevice, MSG_THAWSPACE_LOAD_FAILED, Config.ThawSpacePath[i], wcslen(Config.ThawSpacePath[i]));
			}
		}
		else
		{
			PFILE_OBJECT FileObject;
			IO_STATUS_BLOCK IoStatus;
			UNICODE_STRING FilePath;
			RtlInitUnicodeString(&FilePath, Config.ThawSpacePath[i]);
			IrpCreateFile(&FileObject, FILE_ALL_ACCESS, &FilePath, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NO_INTERMEDIATE_BUFFERING, NULL, 0);
			LogErrorMessageWithString(FilterDevice, MSG_THAWSPACE_HIDE, Config.ThawSpacePath[i], wcslen(Config.ThawSpacePath[i]));
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
						InbvAcquireDisplayOwnership();
						InbvResetDisplay();
						InbvSetTextColor(15);
						InbvInstallDisplayStringFilter(0);
						InbvEnableDisplayString(1);
						InbvSetScrollRegion(0, 0, 639, 475);
						InbvDisplayString("DiskFilter is initializing ThawSpace...\nPlease do not shut down or restart the computer.\n");
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
							FILE_END_OF_FILE_INFORMATION file_eof;
							file_eof.EndOfFile.QuadPart = FileSize;

							status = ZwSetInformationFile(
								file_handle,
								&io_status,
								&file_eof,
								sizeof(FILE_END_OF_FILE_INFORMATION),
								FileEndOfFileInformation
							);

							LogInfo("ThawSpace %wZ: File not found, initializing disk file.\n", &file_name);
							CHAR Buf[256];
							strcpy(Buf, "Initializing ThawSpace volume ?\n");
							*strchr(Buf, '?') = (UCHAR)(((USHORT)Config.ThawSpacePath[i][MAX_PATH]) & ~DISKFILTER_THAWSPACE_HIDE);
							// 写入初始化标记，防止因为错误导致无限重启初始化
							Config.ThawSpacePath[i][0] |= DISKFILTER_THAWSPACE_HIDE;
							InbvDisplayString(Buf);
							FormatFAT32FileSystem(file_handle, FileSize, "ThawSpace");
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
			InbvDisplayString("Initialization finished.\n");
			if (*NtBuildNumber <= 3790) // 直接重新启动会在Windows XP上提示未正常关闭，删除bootstat.dat文件后再重新启动
				SafeReboot();
			else
				NtShutdownSystem(1);
		}
	}
}

// 判断文件是否可信（文件扇区是否未被重定向）
NTSTATUS IsFileCreditable(PUNICODE_STRING filePath)
{
	NTSTATUS	status;
	HANDLE		fileHandle = (HANDLE)-1;
	PFILE_OBJECT	fileObject = NULL;
	PRETRIEVAL_POINTERS_BUFFER	pVcnPairs = NULL;
	PVOLUME_INFO	volumeInfo = NULL;
	ULONG	sectorsPerCluster;
	UNICODE_STRING filePathNew = { 0 };

	BOOLEAN	IsCreditable = FALSE;

	status = GetFileHandleReadOnly(&fileHandle, filePath);

	if (!NT_SUCCESS(status))
	{
		LogWarn("Failed to open file: %wZ, error code 0x%.8X\n", filePath, status);
		goto out;
	}

	status = ObReferenceObjectByHandle(fileHandle, 0, NULL, KernelMode, (PVOID *)&fileObject, NULL);

	if (!NT_SUCCESS(status))
	{
		LogWarn("Failed to get file object for file: %wZ, error code 0x%.8X\n", filePath, status);
		goto out;
	}

	if (fileObject->DeviceObject->DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM)
	{
		UNICODE_STRING	uniDosName;
		// 得到类似C:这样的盘符，为了获取VolumeInfo
		status = IoVolumeDeviceToDosName(fileObject->DeviceObject, &uniDosName);

		if (NT_SUCCESS(status))
		{
			volumeInfo = VolumeList[toupper(*(WCHAR *)uniDosName.Buffer) - L'A'];
			ExFreePool(uniDosName.Buffer);
		}
		else
		{
			LogWarn("Failed to read volume letter for file: %wZ\n", filePath);
		}
	}
	ObDereferenceObject(fileObject);

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
					goto out;
				}
			}
		}
		else
		{
			filePathNew.Buffer = NULL;
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

	ULONG	Cls, r;
	LARGE_INTEGER	PrevVCN = pVcnPairs->StartingVcn;
	for (r = 0, Cls = 0; r < pVcnPairs->ExtentCount; r++)
	{
		ULONG	CnCount;
		LARGE_INTEGER Lcn = pVcnPairs->Extents[r].Lcn;

		for (CnCount = (ULONG)(pVcnPairs->Extents[r].NextVcn.QuadPart - PrevVCN.QuadPart);
			CnCount; CnCount--, Cls++, Lcn.QuadPart++)
		{
			ULONGLONG	i = 0;
			ULONGLONG	base = volumeInfo->FirstDataSector + (Lcn.QuadPart * sectorsPerCluster);
			for (i = 0; i < sectorsPerCluster; i++)
			{
				// 此扇区被重定向了, 不可信文件, 终止认证
				if (base + i >= volumeInfo->SectorCount || DPBitmap_Test(volumeInfo->BitmapRedirect, base + i))
				{
					LogInfo("File %wZ sector %llu has been redirected\n", filePath, base + i);
					goto __exit;
				}
			}
		}
		PrevVCN = pVcnPairs->Extents[r].NextVcn;
	}

	// 经过考验
	IsCreditable = TRUE;

__exit:

	__free(pVcnPairs);

out:
	if (filePathNew.Buffer != NULL)
		__free(filePathNew.Buffer);

	return IsCreditable ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
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

// 获取真实需要读取的扇区
ULONGLONG GetRealSectorForRead(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex)
{
	ULONGLONG	mapIndex = orgIndex;

	// 此扇区是否允许直接操作
	if (IsSectorAllow(volumeInfo, orgIndex))
	{
		return orgIndex;
	}

	// 此扇区是否已经被重定向
	if (DPBitmap_Test(volumeInfo->BitmapRedirect, orgIndex))
	{
		// 找到重定向到哪里, 并返回	
		PREDIRECT_INFO	result;
		REDIRECT_INFO	pair;
		pair.OriginalIndex = orgIndex;

		result = (PREDIRECT_INFO)RtlLookupElementGenericTable(&volumeInfo->RedirectMap, &pair);

		if (result)
		{
			mapIndex = result->MappedIndex;
			return mapIndex;
		}
	}

	return mapIndex;
}

// 获取真实需要写入的扇区
ULONGLONG GetRealSectorForWrite(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex)
{
	ULONGLONG	mapIndex = (ULONGLONG)-1;

	// 此扇区是否允许直接写
	if (IsSectorAllow(volumeInfo, orgIndex))
	{
		return orgIndex;
	}

	// 此扇区是否已经被重定向
	if (DPBitmap_Test(volumeInfo->BitmapRedirect, orgIndex))
	{
		// 找到重定向到哪里, 并返回	
		PREDIRECT_INFO	result;
		REDIRECT_INFO	pair;
		pair.OriginalIndex = orgIndex;

		result = (PREDIRECT_INFO)RtlLookupElementGenericTable(&volumeInfo->RedirectMap, &pair);

		if (result)
		{
			mapIndex = result->MappedIndex;
		}
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

			// 加入重定向列表
			{
				REDIRECT_INFO	pair;
				pair.OriginalIndex = orgIndex;
				pair.MappedIndex = mapIndex;
				RtlInsertElementGenericTable(&volumeInfo->RedirectMap, &pair, sizeof(REDIRECT_INFO), NULL);
			}
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
	NTSTATUS	status;

	// 当前操作的物理偏移
	ULONGLONG	physicalOffset = 0;
	ULONGLONG	sectorIndex;
	ULONGLONG	realIndex;
	ULONG		bytesPerSector = volumeInfo->BytesPerSector;

	// 以下几个参数为判断为处理的扇区是连续的扇区而设
	BOOLEAN		isFirstBlock = TRUE;
	ULONGLONG	prevIndex = (ULONGLONG)-1;
	ULONGLONG	prevOffset = (ULONGLONG)-1;
	PVOID		prevBuffer = NULL;
	ULONG		totalProcessBytes = 0;

	// 判断上次要处理的扇区跟这次要处理的扇区是否连续，连续了就一起处理，否则单独处理, 加快速度
	while (length)
	{
		sectorIndex = logicOffset / bytesPerSector;

		if (IRP_MJ_READ == majorFunction)
		{
			realIndex = GetRealSectorForRead(volumeInfo, sectorIndex);
		}
		else
		{
			realIndex = GetRealSectorForWrite(volumeInfo, sectorIndex);
		}

		if (-1 == realIndex)
		{
			return STATUS_DISK_FULL;
		}

		physicalOffset = realIndex * bytesPerSector;

	__reInit:
		// 初始prevIndex
		if (isFirstBlock)
		{
			prevIndex = realIndex;
			prevOffset = physicalOffset;
			prevBuffer = buff;
			totalProcessBytes = bytesPerSector;

			isFirstBlock = FALSE;

			goto __next;
		}

		// 测试是否连继,  如果连续，跳到下个判断
		if (realIndex == prevIndex + 1)
		{
			prevIndex = realIndex;
			totalProcessBytes += bytesPerSector;
			goto __next;
		}
		// 处理上次连续需要处理的簇, 重置isFirstBlock
		else
		{
			isFirstBlock = TRUE;
			status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], majorFunction, volumeInfo->StartOffset + prevOffset,
				prevBuffer, totalProcessBytes, TRUE);

			// 重新初始化
			goto __reInit;
		}
	__next:
		// 最后一个扇区
		if (bytesPerSector >= length)
		{
			status = FastFsdRequest(LowerDeviceObject[volumeInfo->DiskNumber], majorFunction, volumeInfo->StartOffset + prevOffset,
				prevBuffer, totalProcessBytes, TRUE);

			// 中断退出
			break;
		}

		// 跳到下一个扇区, 处理剩余的数据
		logicOffset += (ULONGLONG)bytesPerSector;
		buff = (char *)buff + bytesPerSector;
		length -= bytesPerSector;
	}

	return status;
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
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}
		//从请求队列的首部拿出一个请求来准备处理，这里使用了自旋锁机制，所以不会有冲突
		while (ReqEntry = ExInterlockedRemoveHeadList(
			&volume_info->ListHead,
			&volume_info->ListLock
		))
		{
			void * newbuff = NULL;

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
				cacheOffset.QuadPart = 0;
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

			// 得到在卷中的偏移 磁盘偏移-卷逻辑偏移
			cacheOffset.QuadPart = offset.QuadPart - volume_info->StartOffset;

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
			newbuff = __malloc(length);

			if (newbuff)
			{
				if (IRP_MJ_READ == io_stack->MajorFunction)
				{
					status = HandleDiskRequest(volume_info, io_stack->MajorFunction, cacheOffset.QuadPart,
						newbuff, length);
					RtlCopyMemory(buffer, newbuff, length);
				}
				else
				{
					RtlCopyMemory(newbuff, buffer, length);
					status = HandleDiskRequest(volume_info, io_stack->MajorFunction, cacheOffset.QuadPart,
						newbuff, length);
				}
				__free(newbuff);
			}
			else
			{
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
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			continue;
		// 处理请求失败，将请求直接交给下层设备处理
		__failed:
			IoSkipCurrentIrpStackLocation(Irp);
			IoCallDriver(LowerDeviceObject[volume_info->DiskNumber], Irp);
			continue;
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

	for (UINT i = 0; i < VaildVolumeCount; i++)
	{
		// 卷是否在受保护的硬盘上
		if (ProtectVolumeList[i].DiskNumber != DeviceNumber)
			continue;

		// 保护MBR及GPT分区表
		if (IRP_MJ_WRITE == irpStack->MajorFunction && offset.QuadPart < 34 * 512)
		{
			*Status = Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return TRUE;
		}

		if ((offset.QuadPart >= ProtectVolumeList[i].StartOffset) &&
			((offset.QuadPart - ProtectVolumeList[i].StartOffset) < ProtectVolumeList[i].BytesTotal)
			)
		{
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
	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;

	if (!IsProtect)
	{
		return FALSE;
	}

	BOOL flag = FALSE;
	for (UINT i = 0; i < VaildVolumeCount; i++)
	{
		if (ProtectVolumeList[i].DiskNumber == DeviceNumber)
		{
			flag = TRUE;
			break;
		}
	}
	if (!flag)
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
		LogInfo("Denied SCSI passthrough request to %wZ on disk %d partition %d\n", PhysicalDeviceName, DeviceNumber, PartitionNumber);
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
		LogInfo("Denied set partition information request to %wZ on disk %d partition %d\n", PhysicalDeviceName, DeviceNumber, PartitionNumber);
		return TRUE;
	// 防止格式化硬盘
	case IOCTL_DISK_COPY_DATA:
	case IOCTL_DISK_CREATE_DISK:
	case IOCTL_DISK_FORMAT_TRACKS:
	case IOCTL_DISK_FORMAT_TRACKS_EX:
	case IOCTL_DISK_REASSIGN_BLOCKS:
	case IOCTL_DISK_REASSIGN_BLOCKS_EX:
	case IOCTL_STORAGE_FIRMWARE_DOWNLOAD:
	case IOCTL_STORAGE_PROTOCOL_COMMAND:
		*Status = Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		LogInfo("Denied IOCTL 0x%.8X request to %wZ on disk %d partition %d\n", ControlCode, PhysicalDeviceName, DeviceNumber, PartitionNumber);
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

		switch (ControlCode)
		{
		case DISKFILTER_IOCTL_DRIVER_CONTROL:
			if (InBufferLength == sizeof(DISKFILTER_CONTROL))
			{
				LogInfo("ControlCode=0x%.8X, InBufferLength=%ld OutBufferLength=%ld\n", ControlCode, InBufferLength, OutBufferLength);
				PDISKFILTER_CONTROL Data = (PDISKFILTER_CONTROL)SystemBuffer;
				if (RtlEqualMemory(Data->AuthorizationContext, DiskFilter_AuthorizationContext, 128))
				{
					if (Data->ControlCode == DISKFILTER_CONTROL_TEST)
					{
						*Status = STATUS_SUCCESS;
						break;
					}
					Data->Password[sizeof(Data->Password) - 1] = L'\0';
					UCHAR Password[32];
					RtlZeroMemory(Password, 32);
					SHA256(Data->Password, wcslen(Data->Password) * sizeof(WCHAR), Password);
					if (!RtlEqualMemory(Password, Config.Password, 32))
					{
						*Status = STATUS_ACCESS_DENIED;
						LogErrorMessageWithString(FilterDevice, MSG_FAILED_LOGIN_ATTEMPT, Data->Password, wcslen(Data->Password));
						break;
					}
					switch (Data->ControlCode)
					{
					case DISKFILTER_CONTROL_GETCONFIG:
						if (OutBufferLength >= sizeof(DISKFILTER_PROTECTION_CONFIG))
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
						RtlCopyMemory(&NewConfig, &Data->Config, sizeof(NewConfig));
						*Status = WriteProtectionConfig(&NewConfig);
						break;
					case DISKFILTER_CONTROL_GETSTATUS:
						if (OutBufferLength >= sizeof(DISKFILTER_STATUS))
						{
							DISKFILTER_STATUS CurStatus;
							CurStatus.AllowDriverLoad = AllowLoadDriver;
							CurStatus.ProtectEnabled = IsProtect;
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
		AllowLoadDriver = (Config.ProtectionFlags & PROTECTION_ALLOW_DRIVER_LOAD) ? TRUE : FALSE;
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
		if ((Config.ProtectionFlags & PROTECTION_DRIVER_WHITELIST) && IsHashInList(Config.DriverList, Config.DriverCount, ImageHash))
		{
			LogInfo("In white list\n");
			return;
		}
		else if ((Config.ProtectionFlags & PROTECTION_DRIVER_BLACKLIST) && !IsHashInList(Config.DriverList, Config.DriverCount, ImageHash))
		{
			LogInfo("Not in black list\n");
			return;
		}
	}

	// 禁止加载驱动
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
}

// 卸载驱动时被调用，驱动只有在遇到错误时才可以被卸载
VOID
OnDiskFilterUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING dosDeviceName;

	RtlInitUnicodeString(&dosDeviceName, DISKFILTER_DOS_DEVICE_NAME_W);

	IoDeleteSymbolicLink(&dosDeviceName);

	if (FilterDevice)
		IoDeleteDevice(FilterDevice);

	ThawSpaceUnload(DriverObject);

	LogInfo("Driver unloaded\n");
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
		DriverObject->DriverUnload = OnDiskFilterUnload;
		return;
	}
	RtlCopyMemory(&NewConfig, &Config, sizeof(Config));

	CheckThawSpace();

	if (Config.ProtectionFlags & PROTECTION_ENABLE)
	{
		InitProtectVolumes();
		StartProtect();

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

	LogInfo("Driver loaded\n");

	RtlInitUnicodeString(&ntDeviceName, DISKFILTER_DEVICE_NAME_W);

	status = IoCreateDevice(
		DriverObject,
		0,								// DeviceExtensionSize
		&ntDeviceName,					// DeviceName
		FILE_DEVICE_DISKFLT,			// DeviceType
		0,								// DeviceCharacteristics
		TRUE,							// Exclusive
		&deviceObject					// [OUT]
	);

	if (!NT_SUCCESS(status))
	{
		LogErr("IoCreateDevice failed. status = 0x%.8X\n", status);
		goto failed;
	}

	RtlInitUnicodeString(&dosDeviceName, DISKFILTER_DOS_DEVICE_NAME_W);

	status = IoCreateSymbolicLink(&dosDeviceName, &ntDeviceName);
	if (!NT_SUCCESS(status))
	{
		LogErr("IoCreateSymbolicLink failed. status = 0x%.8X\n", status);
		LogErrorMessage(deviceObject, MSG_FAILED_TO_INIT);
		goto failed;
	}

	mempool_init();

	FilterDevice = NULL;
	VaildVolumeCount = 0;
	ConfigFileObject = NULL;
	memset(LowerDeviceObject, 0, sizeof(LowerDeviceObject));
	memset(&Config, 0, sizeof(Config));
	memset(&NewConfig, 0, sizeof(NewConfig));
	memset(ProtectVolumeList, 0, sizeof(ProtectVolumeList));
	memset(VolumeList, 0, sizeof(VolumeList));
	VaildVolumeCount = 0;
	memset(&ConfigVolume, 0, sizeof(ConfigVolume));
	ConfigVcnPairs = NULL;
	IsProtect = FALSE;
	AllowLoadDriver = TRUE;

	WCHAR strAppend[] = L"\\Parameters";
	ULONG TotalLen = RegistryPath->Length / 2 + wcslen(strAppend) + 10;
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
	DriverObject->DriverUnload = OnDiskFilterUnload;
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