#pragma once

#include "Pch.h"

typedef struct _DP_BITMAP_
{
	// 总位数
	ULONGLONG	bitMapSize;
	// 已用位数
	ULONGLONG	bitMapUsed;
	// 每个块代表多少位
	ULONG		regionSize;
	// 每个块占多少byte
	ULONG		regionBytes;
	// 这个bitmap总共有多少个块
	ULONG		regionNumber;
	// 指向bitmap存储空间的指针
	UCHAR **	buffer;
} DP_BITMAP, *PDP_BITMAP;

// 位图一次最多申请2M
#define BITMAP_SLOT_SIZE	(1024 * 1024 * 2)

void DPBitmap_Free(DP_BITMAP *bitmap);
NTSTATUS DPBitmap_Create(
	DP_BITMAP **bitmap,		// 位图句柄指针
	ULONGLONG bitMapSize,	// 位图有多少个单位
	ULONG regionBytes	// 位图粒度，分成N块，一块占多少byte
);

ULONGLONG DPBitmap_FindNext(DP_BITMAP *bitMap, ULONGLONG startIndex, BOOL set);

ULONGLONG DPBitmap_FindPrev(DP_BITMAP *bitMap, ULONGLONG startIndex, BOOL set);

NTSTATUS DPBitmap_Set(DP_BITMAP *bitMap, ULONGLONG index, BOOL set);

BOOL DPBitmap_Test(DP_BITMAP *bitMap, ULONGLONG index);

ULONGLONG DPBitmap_Count(DP_BITMAP *bitMap, BOOL set);
