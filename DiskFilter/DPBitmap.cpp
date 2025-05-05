#include "DPBitmap.h"
#include "mempool/mempool.h"

void DPBitmap_Free(DP_BITMAP *bitmap)
{
	//释放bitmap
	if (NULL != bitmap)
	{
		if (NULL != bitmap->buffer)
		{
			for (ULONG i = 0; i < bitmap->regionNumber; i++)
			{
				if (NULL != bitmap->buffer[i])
				{
					//从最底层的块开始释放，所有块都轮询一次				
					__free(bitmap->buffer[i]);
				}
			}
			//释放块的指针
			__free(bitmap->buffer);
		}
		//释放bitmap本身
		__free(bitmap);
	}
}

NTSTATUS DPBitmap_Create(DP_BITMAP **bitmap, ULONGLONG bitMapSize, ULONG regionBytes)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DP_BITMAP *myBitmap = NULL;

	//检查参数，以免使用了错误的参数导致发生处零错等错误
	if (NULL == bitmap || 0 == regionBytes || 0 == bitMapSize)
	{
		return status;
	}
	__try
	{
		*bitmap = NULL;
		//分配一个bitmap结构，这是无论如何都要分配的，这个结构相当于一个bitmap的handle	
		if (NULL == (myBitmap = (DP_BITMAP *)__malloc(sizeof(DP_BITMAP))))
		{
			__leave;
		}

		//清空结构
		memset(myBitmap, 0, sizeof(DP_BITMAP));

		myBitmap->regionSize = regionBytes * 8;
		if (myBitmap->regionSize > bitMapSize)
		{
			myBitmap->regionSize = (ULONG)(bitMapSize / 2);
		}
		//根据参数对结构中的成员进行赋值
		myBitmap->bitMapSize = bitMapSize;
		myBitmap->bitMapUsed = 0;
		myBitmap->regionBytes = regionBytes + sizeof(int);

		myBitmap->regionNumber = (ULONG)(bitMapSize / myBitmap->regionSize);
		if (bitMapSize % myBitmap->regionSize)
		{
			myBitmap->regionNumber++;
		}

		//分配出regionNumber那么多个指向region的指针，这是一个指针数组
		if (NULL == (myBitmap->buffer = (UCHAR **)__malloc(sizeof(UCHAR *) * myBitmap->regionNumber)))
		{
			__leave;
		}
		//清空指针数组
		memset(myBitmap->buffer, 0, sizeof(UCHAR *) * myBitmap->regionNumber);
		*bitmap = myBitmap;
		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))
	{
		if (NULL != myBitmap)
		{
			DPBitmap_Free(myBitmap);
		}
		*bitmap = NULL;
	}
	return status;
}

ULONGLONG DPBitmap_FindNext(DP_BITMAP *bitMap, ULONGLONG startIndex, BOOL set)
{
	ULONG	jmpValue = set ? 0 : 0xFFFFFFFF;
	ULONG	slot = 0;

	// 遍历slot
	for (slot = min(startIndex / bitMap->regionSize, bitMap->regionNumber - 1); slot < bitMap->regionNumber; slot++)
	{
		ULONGLONG	max = 0;

		// 还没有分配
		if (!bitMap->buffer[slot])
		{
			if (set)
			{
				startIndex = (slot + 1) * (ULONGLONG)bitMap->regionSize;
				continue;
			}
			else
			{
				return startIndex;
			}
		}

		for (max = min((slot + 1) * (ULONGLONG)bitMap->regionSize, bitMap->bitMapSize);
			startIndex < max; )
		{
			ULONG	sIndex = startIndex % bitMap->regionSize;

			// 查找下一个置位的索引

			if (jmpValue == ((PULONG)bitMap->buffer[slot])[sIndex / 32])
			{
				// 快速跳越
				startIndex += 32 - (sIndex % 32);
				continue;
			}

			if (set == ((((PULONG)bitMap->buffer[slot])[sIndex / 32] & (1 << (sIndex % 32))) > 0))
			{
				// 找到
				return startIndex;
			}
			startIndex++;
		}
	}

	return (ULONGLONG)-1;
}

ULONGLONG DPBitmap_FindPrev(DP_BITMAP *bitMap, ULONGLONG startIndex, BOOL set)
{
	ULONG	jmpValue = set ? 0 : 0xFFFFFFFF;
	ULONG	slot = 0;

	// 遍历slot
	for (slot = min(startIndex / bitMap->regionSize, bitMap->regionNumber - 1); ; slot--)
	{
		ULONGLONG	mn = 0;

		// 还没有分配
		if (!bitMap->buffer[slot])
		{
			if (set)
			{
				if (slot == 0)
					break;

				startIndex = slot * (ULONGLONG)bitMap->regionSize - 1;
				continue;
			}
			else
			{
				return startIndex;
			}
		}

		for (mn = slot * (ULONGLONG)bitMap->regionSize;
			startIndex >= mn; )
		{
			ULONG	sIndex = startIndex % bitMap->regionSize;

			// 查找上一个置位的索引

			if (jmpValue == ((PULONG)bitMap->buffer[slot])[sIndex / 32])
			{
				// 快速跳越
				startIndex -= (sIndex % 32);
				if (startIndex == 0)
					return (ULONGLONG)-1;
				startIndex--;
				continue;
			}

			if (set == ((((PULONG)bitMap->buffer[slot])[sIndex / 32] & (1 << (sIndex % 32))) > 0))
			{
				// 找到
				return startIndex;
			}

			if (startIndex == 0)
				return (ULONGLONG)-1;

			startIndex--;
		}

		if (slot == 0)
			break;
	}

	return (ULONGLONG)-1;
}

NTSTATUS DPBitmap_Set(DP_BITMAP *bitMap, ULONGLONG index, BOOL set)
{
	ULONG	slot = (ULONG)(index / bitMap->regionSize);
	if (slot > (bitMap->regionNumber - 1))
	{
		LogWarn("DPBitmap_Set out of range slot %d\n", slot);
		return STATUS_UNSUCCESSFUL;
	}

	if (!bitMap->buffer[slot])
	{
		if (!set)
		{
			return STATUS_SUCCESS;
		}
		bitMap->buffer[slot] = (UCHAR *)__malloc(bitMap->regionBytes);
		if (!bitMap->buffer[slot])
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		memset(bitMap->buffer[slot], 0, bitMap->regionBytes);
	}

	index %= bitMap->regionSize;

	if (set)
	{
		if (!(((ULONG *)bitMap->buffer[slot])[index / 32] & (1 << (index % 32))))
		{
			((ULONG *)bitMap->buffer[slot])[index / 32] |= (1 << (index % 32));
			InterlockedIncrement64((LONGLONG *)&bitMap->bitMapUsed);
		}
	}
	else
	{
		if (((ULONG *)bitMap->buffer[slot])[index / 32] & (1 << (index % 32)))
		{
			((ULONG *)bitMap->buffer[slot])[index / 32] &= ~(1 << (index % 32));
			InterlockedDecrement64((LONGLONG *)&bitMap->bitMapUsed);
		}
	}

	return STATUS_SUCCESS;
}

BOOL DPBitmap_Test(DP_BITMAP *bitMap, ULONGLONG index)
{
	ULONG	slot = (ULONG)(index / bitMap->regionSize);
	if (slot > (bitMap->regionNumber - 1))
	{
		LogWarn("DPBitmap_Test out of range slot %d\n", slot);
		return FALSE;
	}
	// 还没分配
	if (!bitMap->buffer[slot])
	{
		return FALSE;
	}

	index %= bitMap->regionSize;

	return (((ULONG *)bitMap->buffer[slot])[index / 32] & (1 << (index % 32)) ? TRUE : FALSE);
}

ULONGLONG DPBitmap_Count(DP_BITMAP *bitMap, BOOL set)
{
	if (!set)
		return bitMap->bitMapSize - bitMap->bitMapUsed;
	return bitMap->bitMapUsed;
}