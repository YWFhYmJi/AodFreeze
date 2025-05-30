#include "Utils.h"
#include "mempool/mempool.h"
#include <wchar.h>
#include "fatlbr.h"
#include <ntdddisk.h>
#include <ntddvol.h>
#include "messages.h"
#include <stdarg.h>
#include "IrpFile.h"
#include <mountmgr.h>

NTSTATUS KSleep(ULONG microSecond)
{
	LARGE_INTEGER timeout = RtlConvertLongToLargeInteger(-10000 * microSecond);
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
	return STATUS_SUCCESS;
}

NTSTATUS WriteReadOnlyMemory(
	PVOID lpDest,
	PVOID lpSource,
	ULONG ulSize
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KSPIN_LOCK spinLock;
	KIRQL oldIrql;
	PMDL pMdlMemory;
	PVOID lpWritableAddress;

	KeInitializeSpinLock(&spinLock);
	pMdlMemory = IoAllocateMdl(lpDest, ulSize, FALSE, FALSE, NULL);
	if (!pMdlMemory)
		return status;

	MmBuildMdlForNonPagedPool(pMdlMemory);
	MmProbeAndLockPages(pMdlMemory, KernelMode, IoWriteAccess);
	lpWritableAddress = MmMapLockedPages(pMdlMemory, KernelMode);
	if (lpWritableAddress)
	{
		oldIrql = 0;
		KeAcquireSpinLock(&spinLock, &oldIrql);
		RtlCopyMemory(lpWritableAddress, lpSource, ulSize);
		KeReleaseSpinLock(&spinLock, oldIrql);
		MmUnmapLockedPages(lpWritableAddress, pMdlMemory);
		status = STATUS_SUCCESS;
	}

	MmUnlockPages(pMdlMemory);
	IoFreeMdl(pMdlMemory);
	return status;
}

#define rightrotate(w, n) ((w >> n) | (w) << (32-(n)))
#define copy_uint32(p, val) *((UINT32 *)p) = swap_endian<UINT32>((val))

void SHA256(const PVOID lpData, ULONG64 ulSize, UCHAR lpOutput[32])
{
	static const UINT32 k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	UINT32 h0 = 0x6a09e667;
	UINT32 h1 = 0xbb67ae85;
	UINT32 h2 = 0x3c6ef372;
	UINT32 h3 = 0xa54ff53a;
	UINT32 h4 = 0x510e527f;
	UINT32 h5 = 0x9b05688c;
	UINT32 h6 = 0x1f83d9ab;
	UINT32 h7 = 0x5be0cd19;
	int r = (int)(ulSize * 8 % 512);
	int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
	ULONG64 new_len = ulSize + append + 8;
	PUCHAR buf = (PUCHAR)__malloc(new_len);
	RtlZeroMemory(buf + ulSize, append);
	RtlCopyMemory(buf, lpData, ulSize);
	buf[ulSize] = 0x80;
	UINT64 bits_len = ulSize * 8;
	for (int i = 0; i < 8; i++)
	{
		buf[ulSize + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
	}
	UINT32 w[64];
	RtlZeroMemory(w, sizeof(w));
	size_t chunk_len = new_len / 64;
	for (int idx = 0; idx < chunk_len; idx++)
	{
		UINT32 val = 0;
		for (int i = 0; i < 64; i++)
		{
			val = val | (*(buf + idx * 64 + i) << (8 * (3 - i)));
			if (i % 4 == 3)
			{
				w[i / 4] = val;
				val = 0;
			}
		}
		for (int i = 16; i < 64; i++)
		{
			UINT32 s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
			UINT32 s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		UINT32 a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
		for (int i = 0; i < 64; i++)
		{
			UINT32 s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
			UINT32 ch = (e & f) ^ (~e & g);
			UINT32 temp1 = h + s_1 + ch + k[i] + w[i];
			UINT32 s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
			UINT32 maj = (a & b) ^ (a & c) ^ (b & c);
			UINT32 temp2 = s_0 + maj;
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}
	copy_uint32(lpOutput, h0);
	copy_uint32(lpOutput + 1, h1);
	copy_uint32(lpOutput + 2, h2);
	copy_uint32(lpOutput + 3, h3);
	copy_uint32(lpOutput + 4, h4);
	copy_uint32(lpOutput + 5, h5);
	copy_uint32(lpOutput + 6, h6);
	copy_uint32(lpOutput + 7, h7);
	__free(buf);
}

#undef rightrotate
#undef copy_uint32

BOOL bitmap_test(ULONG *bitmap, ULONGLONG index)
{
	//	return ((BYTE *)BitmapDetail)[Cluster / 8] & (1 << (Cluster % 8));
	return ((bitmap[index / 8 / sizeof(ULONG)] & (1ul << (index % (8 * sizeof(ULONG))))) ? TRUE : FALSE);
}

void bitmap_set(ULONG *bitmap, ULONGLONG index, BOOL val)
{
	if (val)
		bitmap[index / 8 / sizeof(ULONG)] |= (1ul << (index % (8 * sizeof(ULONG))));
	else
		bitmap[index / 8 / sizeof(ULONG)] &= ~(1ul << (index % (8 * sizeof(ULONG))));
}

NTSTATUS RtlAllocateUnicodeString(PUNICODE_STRING us, ULONG maxLength)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (maxLength > 0)
	{
		if ((us->Buffer = (PWSTR)__malloc(maxLength)) != NULL)
		{
			RtlZeroMemory(us->Buffer, maxLength);

			us->Length = 0;
			us->MaximumLength = (USHORT)maxLength;

			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
		}
	}

	return status;
}

NTSTATUS GetFileHandleReadOnly(PHANDLE fileHandle, PUNICODE_STRING fileName)
{
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK IoStatusBlock;

	InitializeObjectAttributes(&oa,
		fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	return ZwCreateFile(fileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
}

PVOID GetSystemInfo(SYSTEM_INFORMATION_CLASS InfoClass)
{
	NTSTATUS ns;
	ULONG RetSize, Size = 0x100;
	PVOID Info;

	while (1)
	{
		if ((Info = __malloc(Size)) == NULL)
			return NULL;

		ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
		if (ns == STATUS_INFO_LENGTH_MISMATCH)
		{
			__free(Info);
			Size += 0x100;
		}
		else
		{
			break;
		}
	}

	if (!NT_SUCCESS(ns))
	{
		if (Info)
			__free(Info);

		return NULL;
	}

	return Info;
}

NTSTATUS ReadFileAlign(HANDLE FileHandle, PVOID Buffer, ULONG Length, ULONG AlignSize, LONGLONG Offset)
{
	ULONG AlignedSize = (Length / AlignSize + (Length % AlignSize ? 1 : 0)) * AlignSize;
	PUCHAR AlignedBuffer = (PUCHAR)__malloc(AlignedSize);
	if (!AlignedBuffer)
		return STATUS_INSUFFICIENT_RESOURCES;
	LARGE_INTEGER ByteOffset = { 0 };
	ByteOffset.QuadPart = Offset;
	IO_STATUS_BLOCK IoStatus = { 0 };
	NTSTATUS status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus, AlignedBuffer, AlignedSize, &ByteOffset, NULL);
	if (!NT_SUCCESS(status))
	{
		__free(AlignedBuffer);
		return status;
	}
	RtlCopyMemory(Buffer, AlignedBuffer, Length);
	__free(AlignedBuffer);
	return status;
}

NTSTATUS GetVolumeBitmapInfo(ULONG DiskNum, ULONG PartitionNum, PVOLUME_BITMAP_BUFFER *lpBitmap)
{
	NTSTATUS status;
	HANDLE FileHandle;
	UNICODE_STRING FileName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK IoStatusBlock;

	WCHAR VolumeName[MAX_PATH];

	if (!lpBitmap)
		return STATUS_UNSUCCESSFUL;

	swprintf_s(VolumeName, MAX_PATH, L"\\Device\\Harddisk%d\\Partition%d", DiskNum, PartitionNum);

	RtlInitUnicodeString(&FileName, VolumeName);

	InitializeObjectAttributes(&oa, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwCreateFile(&FileHandle,
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
		IO_STATUS_BLOCK	ioBlock;
		PVOLUME_BITMAP_BUFFER pInfo = NULL;
		STARTING_LCN_INPUT_BUFFER StartingLCN;
		ULONG BitmapSize = 0;

		StartingLCN.StartingLcn.QuadPart = 0;
		do
		{
			BitmapSize += 1024 * 1024; // 1MB

			pInfo = (PVOLUME_BITMAP_BUFFER)__malloc(BitmapSize);
			if (!pInfo)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}

			status = ZwFsControlFile(FileHandle,
				NULL,
				NULL,
				NULL,
				&ioBlock,
				FSCTL_GET_VOLUME_BITMAP,
				&StartingLCN,
				sizeof(StartingLCN),
				pInfo,
				BitmapSize
			);

			if (status == STATUS_BUFFER_OVERFLOW)
				__free(pInfo);
		} while (status == STATUS_BUFFER_OVERFLOW);

		if (!NT_SUCCESS(status))
		{
			if (pInfo)
				__free(pInfo);

			*lpBitmap = NULL;
		}
		else
		{
			LogInfo("Bitmap size = %llu\n", pInfo->BitmapSize.QuadPart);
			*lpBitmap = pInfo;
		}

		ZwClose(FileHandle);
	}

	return status;
}

PVOID GetFileClusterList(HANDLE hFile)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	LARGE_INTEGER StartVcn;
	PRETRIEVAL_POINTERS_BUFFER pVcnPairs;
	ULONG ulOutPutSize = 0;
	ULONG uCounts = 200;

	StartVcn.QuadPart = 0;
	ulOutPutSize = sizeof(RETRIEVAL_POINTERS_BUFFER) + uCounts * sizeof(pVcnPairs->Extents) + sizeof(LARGE_INTEGER);
	pVcnPairs = (RETRIEVAL_POINTERS_BUFFER *)__malloc(ulOutPutSize);
	if (pVcnPairs == NULL)
	{
		return NULL;
	}

	while ((status = ZwFsControlFile(hFile, NULL, NULL, 0, &iosb,
		FSCTL_GET_RETRIEVAL_POINTERS,
		&StartVcn, sizeof(LARGE_INTEGER),
		pVcnPairs, ulOutPutSize)) == STATUS_BUFFER_OVERFLOW)
	{
		uCounts += 200;
		ulOutPutSize = sizeof(RETRIEVAL_POINTERS_BUFFER) + uCounts * sizeof(pVcnPairs->Extents) + sizeof(LARGE_INTEGER);
		__free(pVcnPairs);

		pVcnPairs = (RETRIEVAL_POINTERS_BUFFER *)__malloc(ulOutPutSize);
		if (pVcnPairs == NULL)
		{
			return NULL;
		}
	}

	if (!NT_SUCCESS(status))
	{
		__free(pVcnPairs);
		return NULL;
	}

	return pVcnPairs;
}

#define HASH_BUFFER_SIZE (20 * 1024 * 1024) // 20MB

NTSTATUS GetImageHash(PUNICODE_STRING lpFileName, UCHAR lpHash[32])
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK StatusBlock;
	PFILE_OBJECT LocalFileObject;
	HANDLE FileHandle;
	NTSTATUS status;
	LARGE_INTEGER FileSize;
	PUCHAR Buffer = NULL;

	InitializeObjectAttributes(&ObjectAttributes, lpFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenFile(&FileHandle, GENERIC_READ, &ObjectAttributes, &StatusBlock,
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status))
		return status;

	status = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID *)&LocalFileObject, NULL);
	if (!NT_SUCCESS(status))
	{
		ZwClose(FileHandle);
		return status;
	}

	status = FsRtlGetFileSize(LocalFileObject, &FileSize);
	if (!NT_SUCCESS(status))
		goto out;

	LONGLONG lSize = FileSize.QuadPart;
	Buffer = (PUCHAR)__malloc(HASH_BUFFER_SIZE + 40);
	if (!Buffer)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto out;
	}
	*(LONGLONG*)Buffer = lSize;
	memset(Buffer + 8, 0, 32);
	if (lSize <= HASH_BUFFER_SIZE + 32)
	{
		status = ZwReadFile(FileHandle, NULL, NULL, NULL, &StatusBlock, Buffer + 8, (ULONG)lSize, NULL, NULL);
		if (NT_SUCCESS(status))
		{
			SHA256(Buffer, lSize + 8, lpHash);
		}
	}
	else
	{
		LONGLONG lCur = 0;
		while (lCur < lSize)
		{
			ULONG lRead = min(lSize - lCur, HASH_BUFFER_SIZE);
			status = ZwReadFile(FileHandle, NULL, NULL, NULL, &StatusBlock, Buffer + 40, lRead, NULL, NULL);
			if (!NT_SUCCESS(status))
				goto out;
			SHA256(Buffer, lRead + 40, Buffer + 8);
			lCur += lRead;
		}
		SHA256(Buffer, 40, lpHash);
	}
out:
	if (Buffer)
		__free(Buffer);
	ObDereferenceObject(LocalFileObject);
	ZwClose(FileHandle);
	return status;
}

BOOLEAN IsHashInList(PVOID lpHashList, UCHAR nListSize, const UCHAR lpHash[32])
{
	for (UCHAR i = 0; i < nListSize; i++)
	{
		PUCHAR HashPos = (PUCHAR)lpHashList + i * 32;
		if (RtlEqualMemory(HashPos, lpHash, 32))
		{
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS GetFatFirstSectorOffset(HANDLE fileHandle, PULONGLONG firstDataSector)
{
	NTSTATUS status;
	IO_STATUS_BLOCK	IoStatusBlock;
	FAT_LBR fatLBR = { 0 };

	LARGE_INTEGER	pos;
	pos.QuadPart = 0;

	if (!firstDataSector)
	{
		return STATUS_NOT_FOUND;
	}

	status = ZwReadFile(fileHandle, NULL, NULL, NULL, &IoStatusBlock, &fatLBR, sizeof(fatLBR), &pos, NULL);

	if (NT_SUCCESS(status) && sizeof(FAT_LBR) == IoStatusBlock.Information)
	{
		DWORD dwRootDirSectors = 0;
		DWORD dwFATSz = 0;

		// Validate jump instruction to boot code. This field has two
		// allowed forms: 
		// jmpBoot[0] = 0xEB, jmpBoot[1] = 0x??, jmpBoot[2] = 0x90 
		// and
		// jmpBoot[0] = 0xE9, jmpBoot[1] = 0x??, jmpBoot[2] = 0x??
		// 0x?? indicates that any 8-bit value is allowed in that byte.
		// JmpBoot[0] = 0xEB is the more frequently used format.

		if ((fatLBR.wTrailSig != 0xAA55) ||
			((fatLBR.pbyJmpBoot[0] != 0xEB ||
				fatLBR.pbyJmpBoot[2] != 0x90) &&
				(fatLBR.pbyJmpBoot[0] != 0xE9)))
		{
			status = STATUS_NOT_FOUND;
			goto __faild;
		}

		// Compute first sector offset for the FAT volumes:		


		// First, we determine the count of sectors occupied by the
		// root directory. Note that on a FAT32 volume the BPB_RootEntCnt
		// value is always 0, so on a FAT32 volume dwRootDirSectors is
		// always 0. The 32 in the above is the size of one FAT directory
		// entry in bytes. Note also that this computation rounds up.

		dwRootDirSectors =
			(((fatLBR.bpb.wRootEntCnt * 32) +
			(fatLBR.bpb.wBytsPerSec - 1)) /
				fatLBR.bpb.wBytsPerSec);

		// The start of the data region, the first sector of cluster 2,
		// is computed as follows:

		dwFATSz = fatLBR.bpb.wFATSz16;
		if (!dwFATSz)
			dwFATSz = fatLBR.ebpb32.dwFATSz32;


		if (!dwFATSz)
		{
			status = STATUS_NOT_FOUND;
			goto __faild;
		}


		// 得到数据区开始，就是第一簇的位置
		*firstDataSector =
			(fatLBR.bpb.wRsvdSecCnt +
			(fatLBR.bpb.byNumFATs * dwFATSz) +
				dwRootDirSectors);
	}

	status = STATUS_SUCCESS;
__faild:

	return status;
}

NTSTATUS GetPartNumFromVolLetter(WCHAR Letter, PULONG DiskNum, PULONG PartitionNum)
{
	NTSTATUS status;
	HANDLE fileHandle;
	UNICODE_STRING fileName;
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK IoStatusBlock;

	WCHAR volumeDosName[MAX_PATH];
	swprintf_s(volumeDosName, MAX_PATH, L"\\??\\%c:", Letter);

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
		PARTITION_INFORMATION_EX		partitionInfo;

		ULONG	buff[256];
		PVOLUME_DISK_EXTENTS		diskExtents;

		diskExtents = (PVOLUME_DISK_EXTENTS)buff;

		// 得到此卷所在的硬盘号，不考虑跨盘卷
		status = ZwDeviceIoControlFile(fileHandle,
			NULL,
			NULL,
			NULL,
			&ioBlock,
			IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
			NULL,
			0,
			diskExtents,
			sizeof(buff)
		);

		if (!NT_SUCCESS(status))
		{
			ZwClose(fileHandle);
			return status;
		}

		*DiskNum = diskExtents->Extents[0].DiskNumber;

		// 得到此卷的一类型，在物理硬盘的上的偏移等信息

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
			*PartitionNum = partitionInfo.PartitionNumber;
		}

		ZwClose(fileHandle);
	}

	return status;
}

void ChangeDriveIconProtect(WCHAR volume)
{
	HANDLE	keyHandle;
	UNICODE_STRING	keyPath;
	OBJECT_ATTRIBUTES	objectAttributes;
	ULONG		ulResult;
	NTSTATUS	status;

	RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons");

	InitializeObjectAttributes(&objectAttributes,
		&keyPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateKey(&keyHandle,
		KEY_ALL_ACCESS,
		&objectAttributes,
		0,
		NULL,
		REG_OPTION_VOLATILE,   // 重启后无效
		&ulResult);

	if (NT_SUCCESS(status))
	{
		WCHAR	volumeName[10];
		HANDLE	subKey;
		swprintf_s(volumeName, 10, L"%c", volume);

		RtlInitUnicodeString(&keyPath, volumeName);

		InitializeObjectAttributes(&objectAttributes,
			&keyPath,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			keyHandle,
			NULL);

		status = ZwCreateKey(&subKey,
			KEY_ALL_ACCESS,
			&objectAttributes,
			0,
			NULL,
			REG_OPTION_VOLATILE,   // 重启后无效
			&ulResult);

		if (NT_SUCCESS(status))
		{
			HANDLE	subsubKey;
			RtlInitUnicodeString(&keyPath, L"DefaultIcon");

			InitializeObjectAttributes(&objectAttributes,
				&keyPath,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				subKey,
				NULL);

			status = ZwCreateKey(&subsubKey,
				KEY_ALL_ACCESS,
				&objectAttributes,
				0,
				NULL,
				REG_OPTION_VOLATILE,   // 重启后无效
				&ulResult);

			if (NT_SUCCESS(status))
			{
				UNICODE_STRING	keyName;
				WCHAR iconPath[] = L"%SystemRoot%\\System32\\drivers\\diskflt.sys,0";
				WCHAR iconPathWin7[] = L"%SystemRoot%\\System32\\drivers\\diskflt.sys,1";
				WCHAR iconPathWin10[] = L"%SystemRoot%\\System32\\drivers\\diskflt.sys,2";

				RtlInitUnicodeString(&keyName, L"");

				if (*NtBuildNumber <= 3790)
				{
					status = ZwSetValueKey(subsubKey, &keyName, 0, REG_SZ, iconPath, sizeof(iconPath));
				}
				else if (*NtBuildNumber <= 9600)
				{
					status = ZwSetValueKey(subsubKey, &keyName, 0, REG_SZ, iconPathWin7, sizeof(iconPathWin7));
				}
				else
				{
					status = ZwSetValueKey(subsubKey, &keyName, 0, REG_SZ, iconPathWin10, sizeof(iconPathWin10));
				}

				ZwClose(subsubKey);
			}

			ZwClose(subKey);
		}

		ZwClose(keyHandle);
	}
}

wchar_t * wcsstr_n(const wchar_t *string, size_t count, const wchar_t *strCharSet)
{
	wchar_t   *cp = (wchar_t *)string;
	wchar_t   *s1, *s2;

	if (!*strCharSet)
		return ((wchar_t *)string);

	while (count && *cp)
	{
		s1 = cp;
		s2 = (wchar_t*)strCharSet;

		while (*s1 && *s2 && !(toupper(*s1) - toupper(*s2)))
			s1++, s2++;

		if (!*s2)
			return(cp);
		cp++;
		count--;
	}

	return(NULL);
}

NTSTATUS
FltReadWriteSectorsCompletion(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
)
/*++
Routine Description:
A completion routine for use when calling the lower device objects to
which our filter deviceobject is attached.

Arguments:

DeviceObject - Pointer to deviceobject
Irp        - Pointer to a PnP Irp.
Context    - NULL or PKEVENT
Return Value:

NT Status is returned.

--*/
{
	PMDL    mdl;

	UNREFERENCED_PARAMETER(DeviceObject);

	if (!NT_SUCCESS(Irp->IoStatus.Status))
	{
		PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
		LogErr("Disk IO error! DeviceObject=%p, MajorFunction=%d, Offset=%llu, Length=%u, Status=0x%.8X\n",
			DeviceObject, irpStack->MajorFunction, irpStack->Parameters.Read.ByteOffset.QuadPart, irpStack->Parameters.Read.Length, Irp->IoStatus.Status);
	}

	// 
	// Free resources 
	// 

	if (Irp->AssociatedIrp.SystemBuffer && (Irp->Flags & IRP_DEALLOCATE_BUFFER)) {
		__free(Irp->AssociatedIrp.SystemBuffer);
	}

	/*
	因为这个 IRP 就是在我这层次建立的，上层本就不知道有这么一个 IRP。
	那么到这里我就要在 CompleteRoutine 中使用 IoFreeIrp()来释放掉这个 IRP，
	并返回STATUS_MORE_PROCESSING_REQUIRED不让它继续传递。这里一定要注意，
	在 CompleteRoutine函数返回后，这个 IRP 已经释放了，
	如果这个时候在有任何关于这个 IRP 的操作那么后果是灾难性的，必定导致 BSOD 错误。
	*/
	while (Irp->MdlAddress) {
		mdl = Irp->MdlAddress;
		Irp->MdlAddress = mdl->Next;
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}

	if (Irp->PendingReturned && (Context != NULL)) {
		*Irp->UserIosb = Irp->IoStatus;
		KeSetEvent((PKEVENT)Context, IO_DISK_INCREMENT, FALSE);
	}

	IoFreeIrp(Irp);

	// 
	// Don't touch irp any more 
	// 
	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS FastFsdRequest(
	IN PDEVICE_OBJECT DeviceObject,
	IN ULONG MajorFunction,
	IN LONGLONG ByteOffset,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN BOOLEAN Wait
)
{
	PIRP irp;
	IO_STATUS_BLOCK iosb;
	KEVENT event;
	NTSTATUS status;
	LARGE_INTEGER byteOffset;

	byteOffset.QuadPart = ByteOffset;
	irp = IoBuildAsynchronousFsdRequest(MajorFunction, DeviceObject,
		Buffer, Length, &byteOffset, &iosb);
	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	// vista 对直接磁盘写入进行了保护, 驱动操作需要在IRP的FLAGS加上SL_FORCE_DIRECT_WRITE标志
	/*
	If the SL_FORCE_DIRECT_WRITE flag is set, kernel-mode drivers can write to volume areas that they
	normally cannot write to because of direct write blocking. Direct write blocking was implemented for
	security reasons in Windows Vista and later operating systems. This flag is checked both at the file
	system layer and storage stack layer. For more
	information about direct write blocking, see Blocking Direct Write Operations to Volumes and Disks.
	The SL_FORCE_DIRECT_WRITE flag is available in Windows Vista and later versions of Windows.
	http://msdn.microsoft.com/en-us/library/ms795960.aspx
	*/
	if (IRP_MJ_WRITE == MajorFunction)
	{
		IoGetNextIrpStackLocation(irp)->Flags |= SL_FORCE_DIRECT_WRITE;
	}

	if (Wait)
	{
		KeInitializeEvent(&event, NotificationEvent, FALSE);
		IoSetCompletionRoutine(irp, FltReadWriteSectorsCompletion,
			&event, TRUE, TRUE, TRUE);

		status = IoCallDriver(DeviceObject, irp);
		if (STATUS_PENDING == status)
		{
			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
			status = iosb.Status;
		}
	}
	else
	{
		IoSetCompletionRoutine(irp, FltReadWriteSectorsCompletion,
			NULL, TRUE, TRUE, TRUE);
		irp->UserIosb = NULL;
		status = IoCallDriver(DeviceObject, irp);
	}

	return status;
}

void LogErrorMessage(
	IN PDEVICE_OBJECT DeviceObject,
	IN NTSTATUS ErrorCode)
{
	PIO_ERROR_LOG_PACKET errorLogEntry;

	errorLogEntry = (PIO_ERROR_LOG_PACKET)
		IoAllocateErrorLogEntry(
			DeviceObject,
			(UCHAR)(sizeof(IO_ERROR_LOG_PACKET))
		);

	if (errorLogEntry)
	{
		errorLogEntry->ErrorCode = ErrorCode;
		errorLogEntry->DumpDataSize = 0;
		errorLogEntry->NumberOfStrings = 0;
		IoWriteErrorLogEntry(errorLogEntry);
	}
}

void LogErrorMessageWithString(
	IN PDEVICE_OBJECT DeviceObject,
	IN NTSTATUS ErrorCode,
	IN PWCHAR Str,
	IN ULONG StrLength)
{
	PIO_ERROR_LOG_PACKET errorLogEntry;

	errorLogEntry = (PIO_ERROR_LOG_PACKET)
		IoAllocateErrorLogEntry(
			DeviceObject,
			(UCHAR)(sizeof(IO_ERROR_LOG_PACKET) + (StrLength + 1) * sizeof(WCHAR))
		);

	if (errorLogEntry)
	{
		errorLogEntry->ErrorCode = ErrorCode;
		errorLogEntry->DumpDataSize = 0;
		errorLogEntry->NumberOfStrings = 1;
		errorLogEntry->StringOffset = sizeof(IO_ERROR_LOG_PACKET) + errorLogEntry->DumpDataSize;
		RtlCopyMemory((PUCHAR)errorLogEntry + errorLogEntry->StringOffset, Str, (StrLength + 1) * sizeof(WCHAR));
		IoWriteErrorLogEntry(errorLogEntry);
	}
}

NTSTATUS ReadRegString(PUNICODE_STRING RegPath, PWCHAR KeyName, PWCHAR Buffer, ULONG BufferSize, PULONG RetSize)
{
	HANDLE	keyHandle;
	OBJECT_ATTRIBUTES	objectAttributes;
	ULONG		ulResult;
	NTSTATUS	status;

	LogInfo("Reading registry path %wZ\\%ls\n", RegPath, KeyName);

	InitializeObjectAttributes(&objectAttributes,
		RegPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateKey(&keyHandle,
		KEY_READ,
		&objectAttributes,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		&ulResult);

	if (NT_SUCCESS(status))
	{
		UNICODE_STRING keyName;
		RtlInitUnicodeString(&keyName, KeyName);
		ULONG NeedSize = 0;
		status = ZwQueryValueKey(keyHandle, &keyName, KeyValuePartialInformation, NULL, 0, &NeedSize);
		if (NeedSize > 0)
		{
			PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)__malloc(NeedSize);
			if (info)
			{
				ULONG CurSize = 0;
				status = ZwQueryValueKey(keyHandle, &keyName, KeyValuePartialInformation, info, NeedSize, &CurSize);
				if (NT_SUCCESS(status))
				{
					if (info->Type == REG_SZ)
					{
						*RetSize = info->DataLength * sizeof(WCHAR);
						if (info->DataLength * sizeof(WCHAR) > BufferSize)
							status = STATUS_BUFFER_TOO_SMALL;
						else
							RtlCopyMemory(Buffer, info->Data, info->DataLength * sizeof(WCHAR));
					}
					else
					{
						status = STATUS_UNSUCCESSFUL;
					}
				}
				__free(info);
			}
			else
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
			}
		}

		ZwClose(keyHandle);
	}
	return status;
}

NTSTATUS ReadLinkTarget(PUNICODE_STRING LinkPath, PUNICODE_STRING LinkTarget, PULONG ReturnedLength)
{
	HANDLE	linkHandle;
	OBJECT_ATTRIBUTES	objectAttributes;
	NTSTATUS	status;

	LogInfo("Reading symbloic link %wZ\n", LinkPath);
	InitializeObjectAttributes(&objectAttributes,
		LinkPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &objectAttributes);
	if (!NT_SUCCESS(status))
		return status;

	status = ZwQuerySymbolicLinkObject(linkHandle, LinkTarget, ReturnedLength);
	ZwClose(linkHandle);

	return status;
}

NTSTATUS
AdjustPrivilege(
	IN ULONG    Privilege,
	IN BOOLEAN  Enable
)
{
	NTSTATUS            status;
	HANDLE              token_handle;
	TOKEN_PRIVILEGES    token_privileges;

	status = ZwOpenProcessToken(
		NtCurrentProcess(),
		TOKEN_ALL_ACCESS,
		&token_handle
	);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	token_privileges.PrivilegeCount = 1;
	token_privileges.Privileges[0].Luid = RtlConvertUlongToLuid(Privilege);
	token_privileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

	status = ZwAdjustPrivilegesToken(
		token_handle,
		FALSE,
		&token_privileges,
		sizeof(token_privileges),
		NULL,
		NULL
	);

	ZwClose(token_handle);

	return status;
}

NTSTATUS StringToNum(PWCHAR String, PULONG RetNum, BOOLEAN Strict)
{
	ULONG Number = 0;
	for (size_t i = 0; String[i] != L'\0'; i++)
	{
		if (!(String[i] >= L'0' && String[i] <= L'9'))
		{
			if (Strict)
				return STATUS_INVALID_PARAMETER;
			break;
		}
		Number = Number * 10 + (String[i] - L'0');
	}
	*RetNum = Number;
	return STATUS_SUCCESS;
}

void SafeReboot()
{
	HANDLE FileHandle = NULL;
	IO_STATUS_BLOCK IoStatus;
	PFILE_OBJECT FileObject;
	NTSTATUS status;
	UNICODE_STRING FilePath;

	FilePath = RTL_CONSTANT_STRING(L"\\SystemRoot");

	if (*NtBuildNumber <= 3790) // XP上在启动阶段SystemRoot链接指向的ArcName对象不存在，特殊处理
	{
		ULONG DiskNum = 0, PartNum = 0;
		WCHAR SystemPath[MAX_PATH];
		UNICODE_STRING LinkTarget;
		RtlInitEmptyUnicodeString(&LinkTarget, SystemPath, sizeof(SystemPath));
		status = ReadLinkTarget(&FilePath, &LinkTarget, NULL);
		if (NT_SUCCESS(status))
		{
			LogInfo("%wZ -> %wZ\n", &FilePath, &LinkTarget);
			SystemPath[LinkTarget.Length / 2] = L'\0';
			_wcsupr(SystemPath);
			status = STATUS_UNSUCCESSFUL;
			WCHAR DiskNumPattern[] = L"\\ARCNAME\\MULTI(0)DISK(0)RDISK(", PartNumPattern[] = L")PARTITION(", EndPattern[] = L")";
			PWCHAR DiskNumPtr = wcsstr(SystemPath, DiskNumPattern);
			if (DiskNumPtr != NULL)
			{
				DiskNumPtr += wcslen(DiskNumPattern);
				PWCHAR PartNumPtr = wcsstr(DiskNumPtr, PartNumPattern);
				if (PartNumPtr != NULL)
				{
					*PartNumPtr = L'\0';
					PartNumPtr += wcslen(PartNumPattern);
					PWCHAR EndPtr = wcsstr(PartNumPtr, EndPattern);
					if (EndPtr != NULL)
					{
						*EndPtr = L'\0';
						status = NT_SUCCESS(StringToNum(DiskNumPtr, &DiskNum)) && NT_SUCCESS(StringToNum(PartNumPtr, &PartNum));
					}
				}
			}
		}
		else
		{
			LogWarn("Failed to read symbolic link %wZ, error code=0x%.8X\n", &FilePath, status);
		}
		if (NT_SUCCESS(status))
		{
			LogInfo("System disk number = %lu, partition number = %lu\n", DiskNum, PartNum);
			WCHAR VolumeName[MAX_PATH];
			swprintf_s(VolumeName, MAX_PATH, L"\\Device\\Harddisk%d\\Partition%d", DiskNum, PartNum);
			RtlInitUnicodeString(&FilePath, VolumeName);
		}
		status = GetFileHandleReadOnly(&FileHandle, &FilePath);
	}
	else
	{
		status = GetFileHandleReadOnly(&FileHandle, &FilePath);
	}

	if (NT_SUCCESS(status))
	{
		UNICODE_STRING FilePathNew = RTL_CONSTANT_STRING(L"\\Windows\\bootstat.dat");
		status = IrpCreateFile(&FileObject, FILE_READ_ATTRIBUTES, FileHandle, &FilePathNew, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, 0, NULL, 0);
		ZwClose(FileHandle);
		if (NT_SUCCESS(status))
		{
			FILE_BASIC_INFORMATION FileBasicInfo = { 0 };
			FILE_DISPOSITION_INFORMATION FileDispInfo = { 0 };
			FileBasicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
			IrpSetInformationFile(FileObject, &IoStatus, &FileBasicInfo, sizeof(FileBasicInfo), FileBasicInformation);
			FileDispInfo.DeleteFile = TRUE;
			IrpSetInformationFile(FileObject, &IoStatus, &FileDispInfo, sizeof(FileDispInfo), FileDispositionInformation);
			ObDereferenceObject(FileObject);
		}
		else
		{
			LogWarn("Failed to open %wZ, error code=0x%.8X\n", &FilePathNew, status);
		}
	}
	else
	{
		LogWarn("Failed to locate %wZ, error code=0x%.8X\n", &FilePath, status);
	}
	NtShutdownSystem(1);
}

NTSTATUS MountVolume(PUNICODE_STRING DeviceName, WCHAR VolumeLetter)
{
	WCHAR SymLinkName[MAX_PATH];
	UNICODE_STRING SymLink;
	NTSTATUS status;

	VolumeLetter = toupper(VolumeLetter);
	swprintf_s(SymLinkName, MAX_PATH, L"\\DosDevices\\Global\\%c:", VolumeLetter);
	RtlInitUnicodeString(&SymLink, SymLinkName);
	status = IoCreateSymbolicLink(&SymLink, DeviceName);
	if (!NT_SUCCESS(status))
	{
		LogWarn("Failed to create symbolic link %wZ -> %wZ, error code=0x%.8X\n", DeviceName, &SymLink, status);
		return status;
	}
	return status;
}

NTSTATUS UnmountVolume(WCHAR VolumeLetter)
{
	WCHAR SymLinkName[MAX_PATH];
	UNICODE_STRING SymLink;
	NTSTATUS status;

	VolumeLetter = toupper(VolumeLetter);
	swprintf_s(SymLinkName, MAX_PATH, L"\\DosDevices\\Global\\%c:", VolumeLetter);
	RtlInitUnicodeString(&SymLink, SymLinkName);
	status = IoDeleteSymbolicLink(&SymLink);
	if (!NT_SUCCESS(status))
	{
		LogWarn("Failed to delete symbolic link %wZ, error code=0x%.8X\n", &SymLink, status);
		return status;
	}
	return status;
}

#pragma pack(push, 1)
// Starting at offset 36 into the BPB, this is the structure for a FAT32 FS
typedef struct _BPBFAT32_struct {
	unsigned int      FATSize;             // 4
	unsigned short    ExtFlags;              // 2
	unsigned short    FSVersion;             // 2
	unsigned int      RootCluster;           // 4
	unsigned short    FSInfo;                // 2
	unsigned short    BkBootSec;             // 2
	unsigned char     Reserved[12];          // 12
	unsigned char     BS_DriveNumber;            // 1
	unsigned char     BS_Reserved1;              // 1
	unsigned char     BS_BootSig;                // 1
	unsigned int      BS_VolumeID;               // 4
	char     BS_VolumeLabel[11];        // 11
	char     BS_FileSystemType[8];      // 8
} BPB32_struct;

typedef struct _BPB_struct {
	unsigned char     BS_JumpBoot[3];            // 3
	char     BS_OEMName[8];             // 8
	unsigned short    BytesPerSector;        // 2
	unsigned char     SectorsPerCluster;     // 1
	unsigned short    ReservedSectorCount;   // 2
	unsigned char     NumFATs;               // 1
	unsigned short    RootEntryCount;        // 2
	unsigned short    TotalSectors16;        // 2
	unsigned char     Media;                 // 1
	unsigned short    FATSize16;             // 2
	unsigned short    SectorsPerTrack;       // 2
	unsigned short    NumberOfHeads;         // 2
	unsigned int      HiddenSectors;         // 4
	unsigned int      TotalSectors32;        // 4
	BPB32_struct fat32;
} BPB_struct;
#pragma pack(pop)

void FormatFAT32FileSystem(HANDLE hFile, ULONGLONG FileSize, CHAR VolumeLabel[11])
{
	UCHAR sectorBuf0[512];
	UCHAR sectorBuf[512];
	BPB_struct bpb;
	UINT ssa;
	IO_STATUS_BLOCK IoStatus = { 0 };
	LARGE_INTEGER Offset = { 0 };

	LogInfo("Initializating disk file with size %llu\n", FileSize);
	ULONG BufferSize = 20 * 1024 * 1024; // 20MB
	PUCHAR Buffer = (PUCHAR)__malloc(BufferSize);
	memset(Buffer, 0, BufferSize);
	ULONGLONG Cur = 0;
	while (Cur < FileSize)
	{
		ULONG WriteSize = min(BufferSize, FileSize - Cur);
		Offset.QuadPart = Cur;
		ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, Buffer, WriteSize, &Offset, NULL);
		Cur += WriteSize;
	}
	__free(Buffer);
	LogInfo("Fill file ok\n");

	memset(sectorBuf0, 0x00, 0x200);
	memset(&bpb, 0, sizeof(bpb));

	// jump instruction
	bpb.BS_JumpBoot[0] = 0xEB;
	bpb.BS_JumpBoot[1] = 0x58;
	bpb.BS_JumpBoot[2] = 0x90;

	// OEM name
	memcpy(bpb.BS_OEMName, "MSDOS5.0", 8);

	// BPB
	bpb.BytesPerSector = 0x200;        // hard coded, must be a define somewhere
	bpb.SectorsPerCluster = 8;         // this may change based on drive size
	bpb.ReservedSectorCount = 32;
	bpb.NumFATs = 2;
	bpb.Media = 0xf8;
	bpb.SectorsPerTrack = 32;          // unknown here
	bpb.NumberOfHeads = 2;             // ?
	bpb.TotalSectors32 = FileSize / 0x200;
	// BPB-FAT32 Extension
	UINT TmpVal2 = ((256 * bpb.SectorsPerCluster) + bpb.NumFATs) / 2;
	bpb.fat32.FATSize = (bpb.TotalSectors32 - bpb.ReservedSectorCount + (TmpVal2 - 1)) / TmpVal2;
	bpb.fat32.RootCluster = 2;
	bpb.fat32.FSInfo = 1;
	bpb.fat32.BkBootSec = 6;
	bpb.fat32.BS_DriveNumber = 0x80;
	bpb.fat32.BS_BootSig = 0x29;
	bpb.fat32.BS_VolumeID = 0xfbf4499b;      // hardcoded volume id.  this is weird.  should be generated each time.
	memcpy(bpb.fat32.BS_VolumeLabel, "NO NAME    ", 11);
	memcpy(bpb.fat32.BS_FileSystemType, "FAT32   ", 8);
	memcpy(sectorBuf0, &bpb, sizeof(bpb));

	memcpy(sectorBuf0 + 0x5a, "\x0e\x1f\xbe\x77\x7c\xac\x22\xc0\x74\x0b\x56\xb4\x0e\xbb\x07\x00\xcd\x10\x5e\xeb\xf0\x32\xe4\xcd\x17\xcd\x19\xeb\xfeThis is not a bootable disk.  Please insert a bootable floppy and\r\npress any key to try again ... \r\n", 129);

	// ending signatures
	sectorBuf0[0x1fe] = 0x55;
	sectorBuf0[0x1ff] = 0xAA;
	Offset.QuadPart = 0;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf0, 512, &Offset, NULL);
	LogInfo("Write boot sector ok\n");

	// set up key sectors...
	ssa = bpb.ReservedSectorCount + (bpb.NumFATs * bpb.fat32.FATSize);
	// FSInfo sector
	memset(sectorBuf, 0x00, 0x200);
	*((UINT*)sectorBuf) = 0x41615252;
	*((UINT*)(sectorBuf + 0x1e4)) = 0x61417272;
	*((UINT*)(sectorBuf + 0x1e8)) = 0xffffffff; // last known number of free data clusters on volume
	*((UINT*)(sectorBuf + 0x1ec)) = 0xffffffff; // number of most recently known to be allocated cluster
	*((UINT*)(sectorBuf + 0x1f0)) = 0;  // reserved
	*((UINT*)(sectorBuf + 0x1f4)) = 0;  // reserved
	*((UINT*)(sectorBuf + 0x1f8)) = 0;  // reserved
	*((UINT*)(sectorBuf + 0x1fc)) = 0xaa550000;
	//write_sector(sectorBuf, 1);
	Offset.QuadPart = 1 * 512ull;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	LogInfo("Write FSInfo sector ok\n");

	// write backup copy of metadata
	//write_sector(sectorBuf0, 6);
	Offset.QuadPart = 6 * 512ull;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf0, 512, &Offset, NULL);
	LogInfo("Write metadata sector ok\n");

	memset(sectorBuf, 0x00, 0x200);
	*((UINT*)(sectorBuf + 0x000)) = 0x0ffffff8;   // special - EOF marker
	*((UINT*)(sectorBuf + 0x004)) = 0xffffffff;   // special and clean
	*((UINT*)(sectorBuf + 0x008)) = 0x0fffffff;   // root directory (one cluster)
	Offset.QuadPart = bpb.ReservedSectorCount * 512ull;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	Offset.QuadPart = (bpb.ReservedSectorCount + bpb.fat32.FATSize) * 512ull;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	LogInfo("Write root directory ok\n");

	memset(sectorBuf, 0x00, 0x200);
	memset(sectorBuf, 0x20, 11);
	memcpy(sectorBuf, VolumeLabel, min(strlen(VolumeLabel), 11));
	sectorBuf[11] = 0x08;
	Offset.QuadPart = ssa * 512ll;
	ZwWriteFile(hFile, NULL, NULL, NULL, &IoStatus, sectorBuf, 512, &Offset, NULL);
	LogInfo("Write volume label ok\n");
}

int _COMPAT_swprintf_s(wchar_t * _Dst, size_t _SizeInWords, const wchar_t * _Format, ...)
{
	va_list ap;
	va_start(ap, _Format);
	int res = _vsnwprintf(_Dst, _SizeInWords, _Format, ap);
	va_end(ap);
	return res;
}