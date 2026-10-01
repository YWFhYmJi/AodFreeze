#pragma once
#include <Windows.h>
#include <winsvc.h>
#include <winioctl.h>
#include <tchar.h>
#include <stdio.h>
#include <ShlObj.h>
#include <Dbt.h>
#include <Shlwapi.h>
#include "ntdll.h"
#include "..\\DiskFilter\\Public.h"

#pragma comment(lib, "Shlwapi.lib")

#define DISKFILTER_SERVICE_NAME L"diskflt"
#define DISKFILTER_HASH_BUFFER_SIZE (20 * 1024 * 1024) // 20MB

#ifndef _tsprintf_s
#define _DEFINED_tsprintf
#ifdef UNICODE
#define _tsprintf_s swprintf_s
#else
#define _tsprintf_s sprintf_s
#endif
#endif

class DiskfltHelper
{
private:
	static BOOL WINAPI SafeIsWow64Process(HANDLE hProcess, PBOOL Wow64Process)
	{
#if !defined(_WIN64)
		typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		static LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;

		if (fnIsWow64Process == NULL)
		{
			HMODULE hModule = GetModuleHandle(L"kernel32.dll");
			if (hModule == NULL)
				return FALSE;

			fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(hModule, "IsWow64Process");
			if (fnIsWow64Process == NULL)
				return FALSE;
		}
		return fnIsWow64Process(hProcess, Wow64Process);
#else
		* Wow64Process = FALSE;
		return TRUE;
#endif
	}

	static BOOL SafeWow64DisableWow64FsRedirection(PVOID* OldValue)
	{
#if !defined(_WIN64)
		typedef BOOL(WINAPI* LPFN_WOW64DISABLEWOW64FSREDIRECTION) (PVOID*);
		static LPFN_WOW64DISABLEWOW64FSREDIRECTION fnWow64DisableWow64FsRedirection = NULL;

		if (fnWow64DisableWow64FsRedirection == NULL)
		{
			HMODULE hModule = GetModuleHandle(L"kernel32.dll");
			if (hModule == NULL)
				return FALSE;

			fnWow64DisableWow64FsRedirection = (LPFN_WOW64DISABLEWOW64FSREDIRECTION)GetProcAddress(hModule, "Wow64DisableWow64FsRedirection");
			if (fnWow64DisableWow64FsRedirection == NULL)
				return FALSE;
		}
		return fnWow64DisableWow64FsRedirection(OldValue);
#else
		return TRUE;
#endif
	}

	static BOOL SafeWow64RevertWow64FsRedirection(PVOID OldValue)
	{
#if !defined(_WIN64)
		typedef BOOL(WINAPI* LPFN_WOW64REVERTWOW64FSREDIRECTION) (PVOID);
		static LPFN_WOW64REVERTWOW64FSREDIRECTION fnWow64RevertWow64FsRedirection = NULL;

		if (fnWow64RevertWow64FsRedirection == NULL)
		{
			HMODULE hModule = GetModuleHandle(L"kernel32.dll");
			if (hModule == NULL)
				return FALSE;

			fnWow64RevertWow64FsRedirection = (LPFN_WOW64REVERTWOW64FSREDIRECTION)GetProcAddress(hModule, "Wow64RevertWow64FsRedirection");
			if (fnWow64RevertWow64FsRedirection == NULL)
				return FALSE;
		}
		return fnWow64RevertWow64FsRedirection(OldValue);
#else
		return TRUE;
#endif
	}

	static BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
	{
		LPTSTR lpEnd;
		LONG lResult;
		DWORD dwSize;
		TCHAR szName[MAX_PATH];
		HKEY hKey;
		FILETIME ftWrite;

		// First, see if we can delete the key without having
		// to recurse.

		lResult = RegDeleteKey(hKeyRoot, lpSubKey);

		if (lResult == ERROR_SUCCESS)
			return TRUE;

		lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

		if (lResult != ERROR_SUCCESS)
		{
			if (lResult == ERROR_FILE_NOT_FOUND)
				return TRUE;
			else
				return FALSE;
		}

		// Check for an ending slash and add one if it is missing.

		lpEnd = lpSubKey + lstrlen(lpSubKey);

		if (*(lpEnd - 1) != TEXT('\\'))
		{
			*lpEnd = TEXT('\\');
			lpEnd++;
			*lpEnd = TEXT('\0');
		}

		// Enumerate the keys

		dwSize = MAX_PATH;
		lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
			NULL, NULL, &ftWrite);

		if (lResult == ERROR_SUCCESS)
		{
			do {

				*lpEnd = TEXT('\0');
				wcscat_s(lpSubKey, MAX_PATH * 2, szName);

				if (!RegDelnodeRecurse(hKeyRoot, lpSubKey))
					break;

				dwSize = MAX_PATH;

				lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
					NULL, NULL, &ftWrite);

			} while (lResult == ERROR_SUCCESS);
		}

		lpEnd--;
		*lpEnd = TEXT('\0');

		RegCloseKey(hKey);

		// Try again to delete the key.

		lResult = RegDeleteKey(hKeyRoot, lpSubKey);

		if (lResult == ERROR_SUCCESS)
			return TRUE;

		return FALSE;
	}

public:
	template <typename T>
	static T swap_endian(T u)
	{
		union
		{
			T u;
			unsigned char u8[sizeof(T)];
		} source, dest;

		source.u = u;

		for (size_t k = 0; k < sizeof(T); k++)
			dest.u8[k] = source.u8[sizeof(T) - k - 1];

		return dest.u;
	}

	static BOOL IsServiceRunning(LPCWSTR serviceName)
	{
		BOOL		ret = FALSE;
		SC_HANDLE   scmHandle = NULL;
		SC_HANDLE   serviceHandle = NULL;

		scmHandle = OpenSCManagerW(NULL, NULL, GENERIC_READ);

		if (NULL == scmHandle)
		{
			return ret;
		}

		serviceHandle = OpenServiceW(scmHandle, serviceName, GENERIC_READ);

		if (NULL != serviceHandle)
		{
			SERVICE_STATUS	status;
			if (QueryServiceStatus(serviceHandle, &status))
			{
				if (SERVICE_RUNNING == status.dwCurrentState)
				{
					ret = TRUE;
				}
			}
		}

		if (scmHandle != NULL)
		{
			CloseServiceHandle(scmHandle);
		}

		if (serviceHandle != NULL)
		{
			CloseServiceHandle(serviceHandle);
		}

		return ret;
	}

#define rightrotate(w, n) ((w >> n) | (w) << (32-(n)))
#define copy_uint32(p, val) *((UINT32 *)p) = swap_endian<UINT32>((val))

	static void SHA256(const PVOID lpData, size_t ulSize, UCHAR lpOutput[32])
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
		size_t new_len = ulSize + append + 8;
		PUCHAR buf = (PUCHAR)malloc(new_len);
		RtlZeroMemory(buf + ulSize, append);
		RtlCopyMemory(buf, lpData, ulSize);
		buf[ulSize] = 0x80;
		size_t bits_len = ulSize * 8;
		for (int i = 0; i < 8; i++)
		{
			buf[ulSize + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
		}
		UINT32 w[64];
		RtlZeroMemory(w, sizeof(w));
		size_t chunk_len = new_len / 64;
		for (size_t idx = 0; idx < chunk_len; idx++)
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
		free(buf);
	}

#undef rightrotate
#undef copy_uint32

	static LPTSTR GetHashString(UCHAR Hash[32])
	{
		UINT* hash = (UINT*)Hash;
		LPTSTR str = (LPTSTR)malloc(65 * sizeof(TCHAR));
		_tsprintf_s(str, 65, _T("%.8X%.8X%.8X%.8X%.8X%.8X%.8X%.8X"), hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
		return str;
	}

	static LPTSTR GetSizeString(ULONGLONG Size)
	{
		const int KB = 1024, MB = KB * 1024, GB = MB * 1024;
		LPTSTR str = (LPTSTR)malloc(100 * sizeof(TCHAR));
		if (Size >= GB) _tsprintf_s(str, 100, _T("%.2lf GB"), 1.0 * Size / GB);
		else if (Size >= MB) _tsprintf_s(str, 100, _T("%.2lf MB"), 1.0 * Size / MB);
		else if (Size >= KB) _tsprintf_s(str, 100, _T("%.2lf KB"), 1.0 * Size / KB);
		else _tsprintf_s(str, 100, _T("%llu B"), Size);
		return str;
	}

	static BOOL Is64BitOS()
	{
#if defined(_WIN64) || defined(_ARM64_)
		return TRUE;
#elif defined(_WIN32)
		BOOL f64bitOS = FALSE;
		return (SafeIsWow64Process(GetCurrentProcess(), &f64bitOS) && f64bitOS);
#else
		return FALSE;
#endif
	}

	static BOOL Wow64FsRedirection(BOOL Enable = FALSE)
	{
#if defined(_WIN64) || defined(_ARM64_)
		return TRUE;
#else
		static PVOID pOldVal = NULL;
		if (!Enable)
		{
			BOOL bRet = SafeWow64DisableWow64FsRedirection(&pOldVal);
			if (!bRet)
				pOldVal = NULL;
			return bRet;
		}
		else if (pOldVal != NULL)
			return SafeWow64RevertWow64FsRedirection(pOldVal);
		return FALSE;
#endif
	}

	static BOOL EnableDebugPrivilege(LPCTSTR PName, BOOL bEnable)
	{
		BOOL              result = TRUE;
		HANDLE            token;
		TOKEN_PRIVILEGES  tokenPrivileges;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
		{
			result = FALSE;
			return result;
		}
		tokenPrivileges.PrivilegeCount = 1;
		tokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

		LookupPrivilegeValue(NULL, PName, &tokenPrivileges.Privileges[0].Luid);
		AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		if (GetLastError() != ERROR_SUCCESS)
		{
			result = FALSE;
		}

		CloseHandle(token);
		return result;
	}

	static void ShutdownWindows(DWORD dwReason)
	{
		EnableDebugPrivilege(SE_SHUTDOWN_NAME, TRUE);
		ExitWindowsEx(dwReason, 0);
		EnableDebugPrivilege(SE_SHUTDOWN_NAME, FALSE);
	}

	static BOOL GetDriveNumFromVolLetter(CHAR letter, PDWORD diskNum, PDWORD partitionNum)
	{
		HANDLE hDevice;
		DWORD dwRead;
		STORAGE_DEVICE_NUMBER number;
		CHAR path[MAX_PATH];

		sprintf_s(path, "\\\\.\\%c:", letter);
		hDevice = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hDevice == INVALID_HANDLE_VALUE)
		{
			return FALSE;
		}

		if (!DeviceIoControl(hDevice, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &number, sizeof(number), &dwRead, NULL))
		{
			CloseHandle(hDevice);
			return FALSE;
		}

		*diskNum = number.DeviceNumber;
		*partitionNum = number.PartitionNumber;

		CloseHandle(hDevice);
		return TRUE;
	}

	static BOOL IsValidPartition(DWORD diskNum, DWORD partNum)
	{
		if (!partNum)
			return FALSE;
		WCHAR fileName[MAX_PATH];
		swprintf_s(fileName, L"\\\\.\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", diskNum, partNum);
		HANDLE Handle = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
		if (Handle == INVALID_HANDLE_VALUE)
			return FALSE;
		CloseHandle(Handle);
		return TRUE;
	}

	typedef struct _FILE_FS_SIZE_INFORMATION {
		LARGE_INTEGER   TotalAllocationUnits;
		LARGE_INTEGER   AvailableAllocationUnits;
		ULONG           SectorsPerAllocationUnit;
		ULONG           BytesPerSector;
	} FILE_FS_SIZE_INFORMATION, * PFILE_FS_SIZE_INFORMATION;

	typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
		ULONG FileSystemAttributes;
		LONG  MaximumComponentNameLength;
		ULONG FileSystemNameLength;
		WCHAR FileSystemName[1];
	} FILE_FS_ATTRIBUTE_INFORMATION, * PFILE_FS_ATTRIBUTE_INFORMATION;

	static NTSTATUS GetVolumeSpace(DWORD diskNum, DWORD partNum, PULONGLONG totalSpace, PULONGLONG freeSpace, PFILE_FS_SIZE_INFORMATION fsInfo = NULL)
	{
		WCHAR fileName[MAX_PATH];
		swprintf_s(fileName, L"\\\\.\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", diskNum, partNum);
		HANDLE Handle = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
		if (Handle == INVALID_HANDLE_VALUE)
			return STATUS_INVALID_HANDLE;

		FILE_FS_SIZE_INFORMATION info;
		IO_STATUS_BLOCK	IoStatusBlock;

		NTSTATUS status = ZwQueryVolumeInformationFile(Handle,
			&IoStatusBlock,
			&info,
			sizeof(FILE_FS_SIZE_INFORMATION),
			FileFsSizeInformation);

		if (!NT_SUCCESS(status))
			return status;

		ULONGLONG _bytesPerCluster = 1ull * info.BytesPerSector * info.SectorsPerAllocationUnit;

		*totalSpace = _bytesPerCluster * info.TotalAllocationUnits.QuadPart;
		*freeSpace = _bytesPerCluster * info.AvailableAllocationUnits.QuadPart;
		if (fsInfo)
		{
			memcpy(fsInfo, &info, sizeof(info));
		}

		CloseHandle(Handle);
		return STATUS_SUCCESS;
	}

	static BOOL GetVolumeFileSystemName(DWORD diskNum, DWORD partNum, LPWSTR fsName, DWORD bufferSize)
	{
		ULONG infoSize = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 20;

		WCHAR fileName[MAX_PATH];
		swprintf_s(fileName, L"\\\\.\\GLOBALROOT\\Device\\Harddisk%d\\Partition%d", diskNum, partNum);
		HANDLE Handle = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
		if (Handle == INVALID_HANDLE_VALUE)
			return FALSE;

		PFILE_FS_ATTRIBUTE_INFORMATION info = (PFILE_FS_ATTRIBUTE_INFORMATION)malloc(infoSize);
		if (!info)
			return FALSE;

		memset(info, 0, infoSize);

		IO_STATUS_BLOCK	IoStatusBlock;

		NTSTATUS status = ZwQueryVolumeInformationFile(Handle,
			&IoStatusBlock,
			info,
			infoSize,
			FileFsAttributeInformation);

		if (!NT_SUCCESS(status) && status != 0x80000005) // STATUS_BUFFER_OVERFLOW
			return FALSE;

		infoSize += info->FileSystemNameLength;
		info = (PFILE_FS_ATTRIBUTE_INFORMATION)realloc(info, infoSize);
		if (!info)
			return FALSE;

		status = ZwQueryVolumeInformationFile(Handle,
			&IoStatusBlock,
			info,
			infoSize,
			FileFsAttributeInformation);

		if (!NT_SUCCESS(status))
			return FALSE;

		if (bufferSize < info->FileSystemNameLength / 2 + 2)
			return FALSE;

		memcpy(fsName, info->FileSystemName, info->FileSystemNameLength);
		fsName[info->FileSystemNameLength / 2] = L'\0';
		return TRUE;
	}

	static BOOL IsFATVolume(CHAR VolumeLetter)
	{
		ULONG infoSize = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + 20;

		WCHAR fileName[MAX_PATH];
		swprintf_s(fileName, L"\\\\.\\%c:", VolumeLetter);
		HANDLE Handle = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
		if (Handle == INVALID_HANDLE_VALUE)
			return FALSE;

		PFILE_FS_ATTRIBUTE_INFORMATION info = (PFILE_FS_ATTRIBUTE_INFORMATION)malloc(infoSize);
		if (!info)
			return FALSE;

		memset(info, 0, infoSize);

		IO_STATUS_BLOCK	IoStatusBlock;

		NTSTATUS status = ZwQueryVolumeInformationFile(Handle,
			&IoStatusBlock,
			info,
			infoSize,
			FileFsAttributeInformation);

		if (!NT_SUCCESS(status) && status != 0x80000005) // STATUS_BUFFER_OVERFLOW
			return FALSE;

		infoSize += info->FileSystemNameLength;
		info = (PFILE_FS_ATTRIBUTE_INFORMATION)realloc(info, infoSize);
		if (!info)
			return FALSE;

		memset(info, 0, infoSize);

		status = ZwQueryVolumeInformationFile(Handle,
			&IoStatusBlock,
			info,
			infoSize,
			FileFsAttributeInformation);

		if (!NT_SUCCESS(status))
			return FALSE;

		return !_wcsnicmp(info->FileSystemName, L"FAT", 3);
	}

	static BOOL ReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName)
	{
		HGLOBAL hRes;
		HRSRC hResInfo;
		HANDLE hFile;
		DWORD dwBytes;
		hResInfo = FindResource(hModule, MAKEINTRESOURCE(wResourceID), lpType);
		if (hResInfo == NULL)
			return FALSE;
		hRes = LoadResource(hModule, hResInfo);
		if (hRes == NULL)
			return FALSE;
		hFile = CreateFile(lpFileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == NULL)
			return FALSE;

		WriteFile(hFile, hRes, SizeofResource(NULL, hResInfo), &dwBytes, NULL);

		CloseHandle(hFile);
		FreeResource(hRes);
		return TRUE;
	}

	static BOOL ExecuteCMD(const WCHAR* cmd, PDWORD exitCode)
	{
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		WCHAR* cmdline;

		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;

		memset(&pi, 0, sizeof(pi));
		cmdline = _wcsdup(cmd);
		if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
			return FALSE;

		free(cmdline);

		WaitForSingleObject(pi.hProcess, INFINITE);
		if (exitCode)
			GetExitCodeProcess(pi.hProcess, exitCode);
		return TRUE;
	}

	static BOOL ExecuteCMDNative(const WCHAR* cmd, PDWORD exitCode)
	{
		Wow64FsRedirection(FALSE);
		BOOL success = ExecuteCMD(cmd, exitCode);
		Wow64FsRedirection(TRUE);
		return success;
	}

	static void NotifyVolumeChange(WCHAR VolumeLetter, BOOL IsRemove)
	{
		DWORD receipients = BSM_APPLICATIONS | BSM_ALLDESKTOPS;
		DWORD device_event = IsRemove ? DBT_DEVICEREMOVECOMPLETE : DBT_DEVICEARRIVAL;
		DEV_BROADCAST_VOLUME params;
		ZeroMemory(&params, sizeof(params));
		params.dbcv_size = sizeof(params);
		params.dbcv_devicetype = DBT_DEVTYP_VOLUME;
		params.dbcv_reserved = 0;
		params.dbcv_unitmask = (1 << (toupper(VolumeLetter) - 'A'));
		params.dbcv_flags = 0;
		BroadcastSystemMessage(BSF_NOHANG | BSF_FORCEIFHUNG | BSF_NOTIMEOUTIFNOTHUNG, &receipients, WM_DEVICECHANGE, device_event, (LPARAM)&params);
		WCHAR NameBuf[3] = { (WCHAR)toupper(VolumeLetter), L':', 0 };
		SHChangeNotify(IsRemove ? SHCNE_DRIVEREMOVED : SHCNE_DRIVEADD, SHCNF_PATHW, NameBuf, NULL);
	}

	static HANDLE LockVolume(WCHAR VolumeLetter)
	{
		WCHAR fileName[MAX_PATH];
		swprintf_s(fileName, L"\\\\.\\%C:", VolumeLetter);
		HANDLE Handle = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
		if (Handle == INVALID_HANDLE_VALUE)
			return Handle;
		DWORD dwRead;
		if (!DeviceIoControl(Handle, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &dwRead, NULL))
		{
			CloseHandle(Handle);
			return INVALID_HANDLE_VALUE;
		}
		return Handle;
	}

	static BOOL DeleteFileNative(const WCHAR* path)
	{
		Wow64FsRedirection(FALSE);
		BOOL success = DeleteFileW(path);
		Wow64FsRedirection(TRUE);
		return success;
	}

	static BOOL CreateRegKey(HKEY rootKey, const WCHAR* path, PHKEY regKey)
	{
		if (path && path[0] != L'\0')
		{
			LSTATUS result = RegCreateKeyExW(rootKey, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, regKey, NULL);

			if (ERROR_SUCCESS != result)
			{
				SetLastError(result);
				return FALSE;
			}
		}
		else
		{
			*regKey = rootKey;
		}
		return TRUE;
	}

	static BOOL OpenRegKeyReadonly(HKEY rootKey, const WCHAR* path, PHKEY regKey)
	{
		if (path && path[0] != L'\0')
		{
			LSTATUS result = RegOpenKeyExW(rootKey, path, 0, KEY_READ, regKey);

			if (ERROR_SUCCESS != result)
			{
				SetLastError(result);
				return FALSE;
			}
		}
		else
		{
			*regKey = rootKey;
		}
		return TRUE;
	}

	static BOOL DeleteRegKey(HKEY hKeyRoot, LPCTSTR lpSubKey)
	{
		TCHAR szDelKey[MAX_PATH * 2];
		wcscpy_s(szDelKey, MAX_PATH * 2, lpSubKey);
		return RegDelnodeRecurse(hKeyRoot, szDelKey);
	}

	static BOOL SetRegDword(HKEY regKey, const WCHAR* path, const WCHAR* name, DWORD value)
	{
		HKEY subKey = NULL;
		LSTATUS result;
		BOOL success = FALSE;

		if (!CreateRegKey(regKey, path, &subKey))
			return FALSE;

		result = RegSetValueExW(subKey, name, NULL, REG_DWORD, (LPBYTE)&value, sizeof(DWORD));
		if (ERROR_SUCCESS == result)
			success = TRUE;
		if (subKey != regKey)
		{
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		SetLastError(result);
		return success;
	}

	static BOOL QueryRegDword(HKEY regKey, const WCHAR* path, const WCHAR* name, PDWORD value)
	{
		HKEY subKey = NULL;
		LSTATUS result;
		DWORD type = REG_DWORD;
		DWORD retLen = sizeof(*value);
		BOOL success = FALSE;

		if (!OpenRegKeyReadonly(regKey, path, &subKey))
			return FALSE;

		result = RegQueryValueExW(subKey, name, 0, &type, (LPBYTE)value, &retLen);
		if (ERROR_SUCCESS == result && type == REG_DWORD)
			success = TRUE;
		if (subKey != regKey)
		{
			RegCloseKey(subKey);
		}
		SetLastError(result);
		return success;
	}

	static BOOL SetRegDwordBackup(HKEY regKey, HKEY regKeyBackup, const WCHAR* path, const WCHAR* pathBackup, const WCHAR* name, const WCHAR* nameBackup, DWORD value)
	{
		DWORD data = 0;
		if (regKeyBackup != NULL && QueryRegDword(regKey, path, name, &data))
			SetRegDword(regKeyBackup, pathBackup, nameBackup ? nameBackup : name, data);
		return SetRegDword(regKey, path, name, value);
	}

	static BOOL RestoreRegDword(HKEY regKey, HKEY regKeyBackup, const WCHAR* path, const WCHAR* pathBackup, const WCHAR* name, const WCHAR* nameBackup, DWORD value, BOOL del = FALSE)
	{
		DWORD data = 0;
		if (regKeyBackup != NULL && QueryRegDword(regKeyBackup, pathBackup, nameBackup ? nameBackup : name, &data))
		{
			value = data;
			del = FALSE;
		}
		return del ? SetRegString(regKey, path, name, NULL) : SetRegDword(regKey, path, name, value);
	}

	static BOOL SetRegString(HKEY regKey, const WCHAR* path, const WCHAR* name, const WCHAR* value, DWORD type = REG_SZ)
	{
		HKEY subKey = NULL;
		LSTATUS result;
		BOOL success = FALSE;

		if (!CreateRegKey(regKey, path, &subKey))
			return FALSE;

		if (value)
			result = RegSetValueExW(subKey, name, NULL, type, (LPBYTE)value, (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
		else
		{
			result = RegDeleteValueW(subKey, name);
			if (ERROR_FILE_NOT_FOUND == result)
				result = ERROR_SUCCESS;
		}
		if (ERROR_SUCCESS == result)
			success = TRUE;
		if (subKey != regKey)
		{
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		SetLastError(result);
		return success;
	}

	typedef struct _OFFLINE_REGISTRY {
		WCHAR RegName[MAX_PATH];
		WCHAR RootPath[MAX_PATH];
		WCHAR ControlSetName[MAX_PATH];
		WCHAR FilePath[MAX_PATH];
		WCHAR TempFilePath[MAX_PATH];
	} OFFLINE_REGISTRY, * POFFLINE_REGISTRY;

	static BOOL MountOfflineRegistry(const WCHAR* offlineDirectory, const WCHAR* regName, BOOL strict, POFFLINE_REGISTRY offlineRegistry)
	{
		WCHAR Temp[MAX_PATH];
		GetTempPathW(MAX_PATH, Temp);
		wcscpy_s(offlineRegistry->RegName, regName);
		if (!offlineDirectory)
		{
			wcscpy_s(offlineRegistry->RootPath, regName);
			if (!wcscmp(regName, L"SYSTEM"))
				wcscpy_s(offlineRegistry->ControlSetName, L"CurrentControlSet");
			else
				offlineRegistry->ControlSetName[0] = L'\0';
			offlineRegistry->FilePath[0] = L'\0';
			offlineRegistry->TempFilePath[0] = L'\0';
			return TRUE;
		}
		else
		{
			swprintf_s(offlineRegistry->RootPath, L"OFFREG_%s_%p%p", regName, offlineDirectory, offlineRegistry); // 利用指针的地址作为随机数
			swprintf_s(offlineRegistry->FilePath, L"%s\\System32\\config\\%s", offlineDirectory, regName);
			swprintf_s(offlineRegistry->TempFilePath, L"%s\\%s", Temp, offlineRegistry->RootPath);

			if (!CopyFileW(offlineRegistry->FilePath, offlineRegistry->TempFilePath, FALSE))
				return FALSE;

			EnableDebugPrivilege(SE_BACKUP_NAME, TRUE);
			EnableDebugPrivilege(SE_RESTORE_NAME, TRUE);
			LSTATUS result = RegLoadKeyW(HKEY_LOCAL_MACHINE, offlineRegistry->RootPath, offlineRegistry->TempFilePath);
			if (ERROR_SUCCESS != result)
				goto failed;

			if (!wcscmp(regName, L"SYSTEM"))
			{
				DWORD num;

				swprintf_s(Temp, L"%s\\Select", offlineRegistry->RootPath);
				if (!QueryRegDword(HKEY_LOCAL_MACHINE, Temp, L"Default", &num))
				{
					if (strict)
					{
						RegUnLoadKeyW(HKEY_LOCAL_MACHINE, offlineRegistry->RootPath);
						goto failed;
					}
					else
						num = 1;
				}
				swprintf_s(offlineRegistry->ControlSetName, L"ControlSet%03d", num);
			}
			else
				offlineRegistry->ControlSetName[0] = L'\0';
			EnableDebugPrivilege(SE_BACKUP_NAME, FALSE);
			EnableDebugPrivilege(SE_RESTORE_NAME, FALSE);
			return TRUE;
		failed:
			DeleteFileW(offlineRegistry->TempFilePath);
			EnableDebugPrivilege(SE_BACKUP_NAME, FALSE);
			EnableDebugPrivilege(SE_RESTORE_NAME, FALSE);
			SetLastError(result);
			return FALSE;
		}
	}

	static BOOL UnmountOfflineRegistry(const POFFLINE_REGISTRY offlineRegistry)
	{
		BOOL ret = FALSE;
		if (offlineRegistry->TempFilePath[0] == L'\0')
			return TRUE;
		EnableDebugPrivilege(SE_BACKUP_NAME, TRUE);
		EnableDebugPrivilege(SE_RESTORE_NAME, TRUE);
		LSTATUS result = RegUnLoadKeyW(HKEY_LOCAL_MACHINE, offlineRegistry->RootPath);
		if (ERROR_SUCCESS == result)
		{
			WCHAR Temp[MAX_PATH];
			swprintf_s(Temp, L"%s.%p%p.bak", offlineRegistry->FilePath, Temp, offlineRegistry);
			MoveFileExW(offlineRegistry->FilePath, Temp, MOVEFILE_REPLACE_EXISTING);
			if (CopyFileW(offlineRegistry->TempFilePath, offlineRegistry->FilePath, FALSE))
				ret = TRUE;
			DeleteFileW(offlineRegistry->TempFilePath);
		}
		EnableDebugPrivilege(SE_BACKUP_NAME, FALSE);
		EnableDebugPrivilege(SE_RESTORE_NAME, FALSE);
		return ret;
	}
};

class DiskfltApi
{
private:
	HANDLE _filterDevice;
	BOOL _isMultipleInstance;
	LPWSTR _password;
	size_t _passwordLen;

public:
	DiskfltApi()
	{
		_filterDevice = CreateFileW(DISKFILTER_WIN32_DEVICE_NAME_W, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		_isMultipleInstance = (!IsValid() && GetLastError() == ERROR_ACCESS_DENIED);
		_password = NULL;
		_passwordLen = (size_t)-1;
	}

	BOOL IsValid() const { return _filterDevice != INVALID_HANDLE_VALUE; }

	BOOL IsMultipleInstance() const { return _isMultipleInstance; }

	BOOL IsDriverInstalled() const { return DiskfltHelper::IsServiceRunning(DISKFILTER_SERVICE_NAME) && (IsValid() || _isMultipleInstance); }

	void SetPassword(LPCWSTR Password)
	{
		if (IsValid())
		{
			if (_password != NULL)
				free(_password);
			_passwordLen = wcslen(Password);
			_password = (LPWSTR)malloc((_passwordLen + 1) * sizeof(WCHAR));
			if (_password)
				memcpy(_password, Password, (_passwordLen + 1) * sizeof(WCHAR));
			else
				_passwordLen = (size_t)-1;
		}
	}

	void Close()
	{
		if (IsValid())
		{
			if (_password != NULL)
				free(_password);

			_password = NULL;
			_passwordLen = (size_t)-1;
			CloseHandle(_filterDevice);
			_filterDevice = INVALID_HANDLE_VALUE;
		}
	}

	BOOL CheckPassword(LPCWSTR Password) const
	{
		if (_password == NULL || Password == NULL)
			return _password == Password;
		return wcscmp(_password, Password) == 0;
	}

	~DiskfltApi() { Close(); }

	BOOL GetConfig(PDISKFILTER_PROTECTION_CONFIG Config) const
	{
		DWORD dwRead = 0;
		DISKFILTER_CONTROL ControlData;
		memset(&ControlData, 0, sizeof(ControlData));
		memcpy(ControlData.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(ControlData.AuthorizationContext));
		memcpy(ControlData.Password, _password, min(sizeof(ControlData.Password), (_passwordLen + 1) * sizeof(WCHAR)));
		ControlData.ControlCode = DISKFILTER_CONTROL_GETCONFIG;
		return DeviceIoControl(_filterDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &ControlData, sizeof(ControlData), Config, sizeof(DISKFILTER_PROTECTION_CONFIG), &dwRead, NULL) && dwRead == sizeof(DISKFILTER_PROTECTION_CONFIG);
	}

	BOOL GetBufferStatus(ULONG DiskNum, ULONG PartNum, PDISKFILTER_BUFFER_STATUS BufStatus) const
	{
		DWORD dwRead = 0;
		DISKFILTER_CONTROL ControlData;
		memset(&ControlData, 0, sizeof(ControlData));
		memcpy(ControlData.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(ControlData.AuthorizationContext));
		ULONG VolNum = DISKFILTER_MAKE_VOLNUM(DiskNum, PartNum);
		memcpy(ControlData.Password, &VolNum, sizeof(VolNum));
		ControlData.ControlCode = DISKFILTER_CONTROL_GET_BUFFER_STATUS;
		return DeviceIoControl(_filterDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &ControlData, sizeof(ControlData), BufStatus, sizeof(DISKFILTER_BUFFER_STATUS), &dwRead, NULL) && dwRead == sizeof(DISKFILTER_BUFFER_STATUS);
	}

	BOOL GetStatus(PDISKFILTER_STATUS CurStatus) const
	{
		DWORD dwRead = 0;
		DISKFILTER_CONTROL ControlData;
		memset(&ControlData, 0, sizeof(ControlData));
		memcpy(ControlData.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(ControlData.AuthorizationContext));
		memcpy(ControlData.Password, _password, min(sizeof(ControlData.Password), (_passwordLen + 1) * sizeof(WCHAR)));
		ControlData.ControlCode = DISKFILTER_CONTROL_GETSTATUS;
		return DeviceIoControl(_filterDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &ControlData, sizeof(ControlData), CurStatus, sizeof(DISKFILTER_STATUS), &dwRead, NULL) && dwRead == sizeof(DISKFILTER_STATUS);
	}

	static ULONGLONG CalcVolumeNeedMemory(DWORD diskNum, DWORD partNum)
	{
		ULONGLONG totalSpace, freeSpace, needMemory = 0;
		DiskfltHelper::FILE_FS_SIZE_INFORMATION info;

		if (!NT_SUCCESS(DiskfltHelper::GetVolumeSpace(diskNum, partNum, &totalSpace, &freeSpace, &info)))
			return 0;

		needMemory = totalSpace * 4 / info.BytesPerSector / 8;

		return needMemory;
	}

	static BOOL InstallProtectDriver(HMODULE hModule, WORD x86ResourceId, WORD x64ResourceId, LPCTSTR resourceType, const WCHAR* serviceName, const WCHAR* configPath)
	{
		HKEY regKey, subKey;
		WCHAR sysDirPath[MAX_PATH];
		WCHAR targetPath[MAX_PATH];
		WCHAR regPath[MAX_PATH];
		LSTATUS result;
		WCHAR buff[1024];
		DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;
		BOOL success = TRUE;

		if (!serviceName || !configPath || !GetSystemDirectoryW(sysDirPath, sizeof(sysDirPath)))
			return FALSE;

		swprintf_s(targetPath, L"%s\\drivers\\%s.sys", sysDirPath, serviceName);

		// 释放文件
		if (DiskfltHelper::Is64BitOS())
		{
			DiskfltHelper::Wow64FsRedirection(FALSE);
			BOOL Flag = DiskfltHelper::ReleaseResource(hModule, x64ResourceId, resourceType, targetPath);
			DiskfltHelper::Wow64FsRedirection(TRUE);
			if (!Flag)
				return FALSE;
		}
		else
		{
			if (!DiskfltHelper::ReleaseResource(hModule, x86ResourceId, resourceType, targetPath))
				return FALSE;
		}

		// 安装服务
		swprintf_s(regPath, L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName);
		if (!DiskfltHelper::CreateRegKey(HKEY_LOCAL_MACHINE, regPath, &regKey))
			goto failed;
		success = success && DiskfltHelper::SetRegDword(regKey, NULL, L"Type", SERVICE_KERNEL_DRIVER);
		success = success && DiskfltHelper::SetRegDword(regKey, NULL, L"Start", SERVICE_BOOT_START);
		success = success && DiskfltHelper::SetRegString(regKey, NULL, L"Group", L"Boot Bus Extender");
		success = success && DiskfltHelper::SetRegDword(regKey, NULL, L"Tag", 10);
		success = success && DiskfltHelper::SetRegDword(regKey, NULL, L"ErrorControl", SERVICE_ERROR_NORMAL);
		success = success && DiskfltHelper::SetRegString(regKey, NULL, L"ImagePath", NULL); // 防止残余注册表导致开机蓝屏
		if (success && DiskfltHelper::CreateRegKey(regKey, L"Parameters", &subKey))
		{
			success = success && DiskfltHelper::SetRegString(subKey, NULL, L"ConfigPath", configPath);
			success = success && DiskfltHelper::SetRegDword(subKey, NULL, L"DisableShutdownMessage", 1);
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		else
			success = FALSE;
		RegFlushKey(regKey);
		RegCloseKey(regKey);
		if (!success)
			goto failed;

		// 安装过滤器
		if (!DiskfltHelper::CreateRegKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}", &regKey))
			goto failed;

		memset(buff, 0, sizeof(buff));
		success = FALSE;

		result = RegQueryValueExW(regKey, L"UpperFilters", 0, &type, (LPBYTE)buff, &retLen);

		if (ERROR_SUCCESS == result && type == REG_MULTI_SZ)
		{
			BOOL	alreadyExists = FALSE;
			WCHAR* ptr = NULL;
			for (ptr = buff; *ptr; ptr += lstrlenW(ptr) + 1)
			{
				if (lstrcmpiW(ptr, serviceName) == 0)
				{
					alreadyExists = TRUE;
					break;
				}
			}

			if (!alreadyExists)
			{
				DWORD	added = lstrlenW(serviceName);
				memcpy(ptr, serviceName, added * sizeof(WCHAR));

				ptr += added;

				*ptr = '\0';
				*(ptr + 1) = '\0';

				result = RegSetValueExW(regKey, L"UpperFilters", 0, REG_MULTI_SZ, (LPBYTE)buff, retLen + ((added + 1) * sizeof(WCHAR)));
				if (ERROR_SUCCESS == result)
					success = TRUE;
				RegFlushKey(regKey);
			}
			else
				success = TRUE;
		}
		RegCloseKey(regKey);
		if (!success)
		{
			SetLastError(result);
			goto failed;
		}

		// 安装日志记录器
		swprintf_s(buff, L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\System\\%s", serviceName);
		if (DiskfltHelper::CreateRegKey(HKEY_LOCAL_MACHINE, buff, &regKey))
		{
			DiskfltHelper::SetRegDword(regKey, NULL, L"TypesSupported", 7);
			swprintf_s(buff, L"%%SystemRoot%%\\System32\\IoLogMsg.dll;%%SystemRoot%%\\System32\\drivers\\%s.sys", serviceName);
			DiskfltHelper::SetRegString(regKey, NULL, L"EventMessageFile", buff, REG_EXPAND_SZ);
			RegFlushKey(regKey);
			RegCloseKey(regKey);
		}

		return TRUE;
	failed:
		DWORD err = GetLastError();
		DiskfltHelper::DeleteRegKey(HKEY_LOCAL_MACHINE, regPath);
		DiskfltHelper::DeleteFileNative(targetPath);
		SetLastError(err);
		return FALSE;
	}

	static void InstallMisc()
	{
		LONG result;
		HKEY regKey, regKeyBackup;
		BOOL backup = FALSE;
		ULONG type;
		DWORD retLen;

		// 备份原始设置
		if (DiskfltHelper::CreateRegKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\AodFreeze", &regKeyBackup))
			backup = TRUE;
		else
			regKeyBackup = NULL;

		// 关闭磁盘检查
		if (DiskfltHelper::CreateRegKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", &regKey))
		{
			WCHAR buff[1024];

			memset(buff, 0, sizeof(buff));
			type = REG_MULTI_SZ;
			retLen = sizeof(buff);

			result = RegQueryValueExW(regKey, L"BootExecute", 0, &type, (LPBYTE)buff, &retLen);

			if (ERROR_SUCCESS == result && retLen > 0 && type == REG_MULTI_SZ)
			{
				BOOL changed = FALSE;

				if (backup)
				{
					RegSetValueExW(regKeyBackup, L"BootExecute", 0, REG_MULTI_SZ, (LPBYTE)buff, retLen);
					RegFlushKey(regKeyBackup);
				}
				for (WCHAR* ptr = buff; *ptr && retLen > 0; )
				{
					if (StrStrW(ptr, L"autocheck autochk"))
					{
						DWORD removeLength = (lstrlenW(ptr) + 1) * sizeof(WCHAR);
						retLen -= removeLength;
						memmove(ptr, (char*)ptr + removeLength, retLen - ((char*)ptr - (char*)buff));
						changed = TRUE;
					}
					else
					{
						ptr += lstrlenW(ptr) + 1;
					}
				}
				if (changed)
				{
					result = RegSetValueExW(regKey, L"BootExecute", 0, REG_MULTI_SZ, (LPBYTE)buff, retLen);
					RegFlushKey(regKey);
				}
			}

			DiskfltHelper::SetRegDwordBackup(regKey, regKeyBackup, L"Power", NULL, L"HiberbootEnabled", NULL, 0); // 关闭快速启动
			DiskfltHelper::SetRegDwordBackup(regKey, regKeyBackup, L"Memory Management\\PrefetchParameters", NULL, L"EnablePrefetcher", NULL, 0); // 关闭预加载
			RegFlushKey(regKey);
			RegCloseKey(regKey);
		}

		// 禁用恢复环境和启动修复
		DiskfltHelper::Wow64FsRedirection(FALSE);
		DiskfltHelper::ExecuteCMD(L"bcdedit.exe /set {current} bootstatuspolicy ignoreallfailures", NULL);
		DiskfltHelper::ExecuteCMD(L"bcdedit.exe /set {current} recoveryenabled No", NULL);
		DiskfltHelper::Wow64FsRedirection(TRUE);

		// 关闭自动更新
		DiskfltHelper::SetRegDwordBackup(HKEY_LOCAL_MACHINE, regKeyBackup, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", NULL, L"NoAutoUpdate", NULL, 1);

		if (backup)
		{
			RegFlushKey(regKeyBackup);
			RegCloseKey(regKeyBackup);
		}
	}

	static BOOL Install(HMODULE hModule, WORD x86ResourceId, WORD x64ResourceId, LPCTSTR resourceType, const WCHAR* serviceName, const WCHAR* configPath)
	{
		if (!InstallProtectDriver(hModule, x86ResourceId, x64ResourceId, resourceType, serviceName, configPath))
			return FALSE;
		InstallMisc();
		return TRUE;
	}

	static BOOL UninstallProtectDriver(const WCHAR* serviceName, const DiskfltHelper::OFFLINE_REGISTRY* offlineRegSystem)
	{
		BOOL success = FALSE;
		WCHAR targetPath[MAX_PATH];
		LONG result;
		HKEY regKey;

		if (!offlineRegSystem)
			return FALSE;

		swprintf_s(targetPath, L"%s\\%s\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}", offlineRegSystem->RootPath, offlineRegSystem->ControlSetName);
		if (!DiskfltHelper::CreateRegKey(HKEY_LOCAL_MACHINE, targetPath, &regKey))
			return FALSE;

		WCHAR buff[1024];
		DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;

		memset(buff, 0, sizeof(buff));

		result = RegQueryValueExW(regKey, L"UpperFilters", 0, &type, (LPBYTE)buff, &retLen);

		if (ERROR_SUCCESS != result || type != REG_MULTI_SZ)
		{
			RegCloseKey(regKey);
			goto cleanup;
		}

		for (WCHAR* ptr = buff; *ptr; ptr += lstrlenW(ptr) + 1)
		{
			if (lstrcmpiW(ptr, serviceName) == 0)
			{
				DWORD removeLength = (lstrlenW(ptr) + 1) * sizeof(WCHAR);
				retLen -= removeLength;
				memmove(ptr, (char*)ptr + removeLength, retLen - ((char*)ptr - (char*)buff));

				result = RegSetValueExW(regKey, L"UpperFilters", 0, REG_MULTI_SZ, (LPBYTE)buff, retLen);
				// 一定要flush,否则不保存
				RegFlushKey(regKey);
				break;
			}
		}
		RegCloseKey(regKey);

		if (ERROR_SUCCESS != result)
			goto cleanup;

		success = TRUE;

		swprintf_s(targetPath, L"%s\\%s\\Services\\%s", offlineRegSystem->RootPath, offlineRegSystem->ControlSetName, serviceName);
		DiskfltHelper::DeleteRegKey(HKEY_LOCAL_MACHINE, targetPath);

		swprintf_s(targetPath, L"%s\\%s\\Services\\EventLog\\System\\%s", offlineRegSystem->RootPath, offlineRegSystem->ControlSetName, serviceName);
		DiskfltHelper::DeleteRegKey(HKEY_LOCAL_MACHINE, targetPath);

		result = ERROR_SUCCESS;
	cleanup:
		SetLastError(result);
		return success;
	}

	static void UninstallMisc(const DiskfltHelper::OFFLINE_REGISTRY* offlineRegSystem, const DiskfltHelper::OFFLINE_REGISTRY* offlineRegSoftware)
	{
		WCHAR targetPath[MAX_PATH];
		HKEY regKey, regKeyBackup;
		BOOL backup = FALSE;

		if (!offlineRegSystem || !offlineRegSoftware)
			return;

		// 启用恢复环境和启动修复
		if (offlineRegSystem->TempFilePath[0] == L'\0')
		{
			DiskfltHelper::Wow64FsRedirection(FALSE);
			DiskfltHelper::ExecuteCMD(L"bcdedit.exe /set {current} bootstatuspolicy DisplayAllFailures", NULL);
			DiskfltHelper::ExecuteCMD(L"bcdedit.exe /set {current} recoveryenabled Yes", NULL);
			DiskfltHelper::Wow64FsRedirection(TRUE);
		}
		else
		{
			// TODO: 离线处理BCD
		}

		swprintf_s(targetPath, _T("%s\\AodFreeze"), offlineRegSoftware->RootPath);
		if (DiskfltHelper::OpenRegKeyReadonly(HKEY_LOCAL_MACHINE, targetPath, &regKeyBackup))
			backup = TRUE;
		else
			regKeyBackup = NULL;

		swprintf_s(targetPath, L"%s\\%s\\Control\\Session Manager", offlineRegSystem->RootPath, offlineRegSystem->ControlSetName);
		if (DiskfltHelper::CreateRegKey(HKEY_LOCAL_MACHINE, targetPath, &regKey))
		{
			// 恢复磁盘检查
			WCHAR buff[1024];
			DWORD retLen = sizeof(buff);
			ULONG type = REG_MULTI_SZ;

			memset(buff, 0, sizeof(buff));
			if (backup && ERROR_SUCCESS == RegQueryValueExW(regKeyBackup, L"BootExecute", 0, &type, (LPBYTE)buff, &retLen) && type == REG_MULTI_SZ)
				RegSetValueExW(regKey, L"BootExecute", 0, REG_MULTI_SZ, (LPBYTE)buff, retLen);
			else if (offlineRegSystem->TempFilePath[0] == L'\0')
				DiskfltHelper::ExecuteCMDNative(L"chkntfs.exe /D", NULL);

			DiskfltHelper::RestoreRegDword(regKey, regKeyBackup, L"Power", NULL, L"HiberbootEnabled", NULL, 1); // 恢复快速启动
			DiskfltHelper::RestoreRegDword(regKey, regKeyBackup, L"Memory Management\\PrefetchParameters", NULL, L"EnablePrefetcher", NULL, 3); // 恢复预加载
			RegFlushKey(regKey);
			RegCloseKey(regKey);
		}

		swprintf_s(targetPath, _T("%s\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"), offlineRegSoftware->RootPath);
		DiskfltHelper::RestoreRegDword(HKEY_LOCAL_MACHINE, regKeyBackup, targetPath, NULL, L"NoAutoUpdate", NULL, 0, TRUE); // 恢复自动更新

		if (backup)
			RegCloseKey(regKeyBackup);
	}

	static BOOL Uninstall(const WCHAR* serviceName, const WCHAR* offlineDirectory = NULL)
	{
		DiskfltHelper::OFFLINE_REGISTRY offlineRegSys = { 0 }, offlineRegSoft = { 0 };
		if (!DiskfltHelper::MountOfflineRegistry(offlineDirectory, L"SYSTEM", FALSE, &offlineRegSys))
			return FALSE;
		if (!UninstallProtectDriver(serviceName, &offlineRegSys))
			return FALSE;
		if (DiskfltHelper::MountOfflineRegistry(offlineDirectory, L"SOFTWARE", FALSE, &offlineRegSoft))
			UninstallMisc(&offlineRegSys, &offlineRegSoft);
		if (!DiskfltHelper::UnmountOfflineRegistry(&offlineRegSys))
			return FALSE;
		if (!DiskfltHelper::UnmountOfflineRegistry(&offlineRegSoft))
			return FALSE;
		WCHAR targetPath[MAX_PATH];
		if (!offlineDirectory)
		{
			WCHAR sysDirPath[MAX_PATH];
			GetSystemDirectoryW(sysDirPath, sizeof(sysDirPath));
			swprintf_s(targetPath, L"%s\\drivers\\%s.sys", sysDirPath, serviceName);
		}
		else
			swprintf_s(targetPath, L"%s\\System32\\drivers\\%s.sys", offlineDirectory, serviceName);
		DiskfltHelper::DeleteFileNative(targetPath);
		return TRUE;
	}

	static BOOL InstallProtectionConfig(PDISKFILTER_PROTECTION_CONFIG Config, const WCHAR* ConfigPath)
	{
		HANDLE hFile;
		DWORD dwWrite;

		hFile = CreateFileW(ConfigPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return FALSE;

		if (!WriteFile(hFile, Config, sizeof(*Config), &dwWrite, NULL))
		{
			CloseHandle(hFile);
			return FALSE;
		}

		CloseHandle(hFile);
		return TRUE;
	}

	static BOOL ReadProtectionConfigR3(PDISKFILTER_PROTECTION_CONFIG Config, const WCHAR* ConfigPath)
	{
		HANDLE hFile;
		DWORD dwRead;

		hFile = CreateFileW(ConfigPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			return FALSE;

		if (!ReadFile(hFile, Config, sizeof(*Config), &dwRead, NULL))
		{
			CloseHandle(hFile);
			return FALSE;
		}

		CloseHandle(hFile);
		return TRUE;
	}

	static BOOL IsPartitionProtected(PDISKFILTER_PROTECTION_CONFIG config, DWORD diskNum, DWORD partNum)
	{
		//if (!(config->ProtectionFlags & PROTECTION_ENABLE))
		//	return FALSE;
		for (int i = 0; i < config->ProtectVolumeCount; i++)
		{
			DWORD DiskNum = config->ProtectVolume[i] & 0xFFFF;
			DWORD PartitionNum = (config->ProtectVolume[i] >> 16) & 0xFFFF;
			if (diskNum == DiskNum && partNum == PartitionNum)
				return TRUE;
		}
		return FALSE;
	}

	static BOOL IsPartitionProtected(PDISKFILTER_STATUS status, DWORD diskNum, DWORD partNum)
	{
		if (!status->ProtectEnabled)
			return FALSE;
		for (int i = 0; i < status->ProtectVolumeCount; i++)
		{
			DWORD DiskNum = status->ProtectVolume[i] & 0xFFFF;
			DWORD PartitionNum = (status->ProtectVolume[i] >> 16) & 0xFFFF;
			if (diskNum == DiskNum && partNum == PartitionNum)
				return TRUE;
		}
		return FALSE;
	}

	static void ChangeProtectState(PDISKFILTER_PROTECTION_CONFIG config, DWORD diskNum, DWORD partNum, BOOL isProtect)
	{
		for (int i = 0; i < config->ProtectVolumeCount; i++)
		{
			DWORD DiskNum = config->ProtectVolume[i] & 0xFFFF;
			DWORD PartitionNum = (config->ProtectVolume[i] >> 16) & 0xFFFF;
			if (diskNum == DiskNum && partNum == PartitionNum)
			{
				if (isProtect)
					return;

				for (int j = i + 1; j < config->ProtectVolumeCount; j++)
					config->ProtectVolume[j - 1] = config->ProtectVolume[j];

				config->ProtectVolume[config->ProtectVolumeCount - 1] = 0;
				config->ProtectVolumeCount--;
				return;
			}
		}
		if (isProtect && config->ProtectVolumeCount < sizeof(config->ProtectVolume) / sizeof(*config->ProtectVolume))
		{
			config->ProtectVolume[config->ProtectVolumeCount] = (diskNum & 0xFFFF) | ((partNum & 0xFFFF) << 16);
			config->ProtectVolumeCount++;
		}
	}

	static ULONGLONG CalcSystemTotalNeedMemory(PDISKFILTER_PROTECTION_CONFIG Config)
	{
		ULONGLONG	needMemory = 0;
		for (int i = 0; i < Config->ProtectVolumeCount; i++)
		{
			DWORD DiskNum = Config->ProtectVolume[i] & 0xFFFF;
			DWORD PartitionNum = (Config->ProtectVolume[i] >> 16) & 0xFFFF;
			needMemory += CalcVolumeNeedMemory(DiskNum, PartitionNum);
		}
		// 给系统预留10M
		int	sysReserve = 1024 * 1024 * 10;
		needMemory += sysReserve;
		return needMemory;
	}

	static BOOL GetImageHash(LPCTSTR lpFileName, UCHAR lpHash[32])
	{
		HANDLE FileHandle;
		LARGE_INTEGER FileSize;
		PUCHAR Buffer = NULL;
		BOOL bRet = FALSE;
		LONGLONG lSize;

		FileHandle = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (FileHandle == INVALID_HANDLE_VALUE)
			return FALSE;

		if (!GetFileSizeEx(FileHandle, &FileSize))
			goto out;

		lSize = FileSize.QuadPart;
		Buffer = (PUCHAR)malloc(DISKFILTER_HASH_BUFFER_SIZE + 40);
		if (!Buffer)
			goto out;
		*(LONGLONG*)Buffer = lSize;
		memset(Buffer + 8, 0, 32);
		if (lSize <= DISKFILTER_HASH_BUFFER_SIZE + 32)
		{
			DWORD dwRead = 0;
			if (ReadFile(FileHandle, Buffer + 8, (ULONG)lSize, &dwRead, NULL))
			{
				DiskfltHelper::SHA256(Buffer, dwRead + 8, lpHash);
				bRet = TRUE;
			}
		}
		else
		{
			while (1)
			{
				DWORD dwRead = 0;
				if (!ReadFile(FileHandle, Buffer + 40, DISKFILTER_HASH_BUFFER_SIZE, &dwRead, NULL) || dwRead == 0)
					break;
				DiskfltHelper::SHA256(Buffer, dwRead + 40, Buffer + 8);
			}
			DiskfltHelper::SHA256(Buffer, 40, lpHash);
			bRet = TRUE;
		}
	out:
		if (Buffer)
			free(Buffer);
		CloseHandle(FileHandle);
		return bRet;
	}

	BOOL DeviceControl(UCHAR ControlCode, const PVOID Data = NULL, SIZE_T DataSize = 0, PVOID Output = NULL, SIZE_T OutputSize = 0) const
	{
		DWORD dwRead = 0;
		DISKFILTER_CONTROL ControlData;
		if (DataSize > sizeof(ControlData.Config))
			return FALSE;
		memset(&ControlData, 0, sizeof(ControlData));
		memcpy(ControlData.AuthorizationContext, DiskFilter_AuthorizationContext, sizeof(ControlData.AuthorizationContext));
		memcpy(ControlData.Password, _password, min(sizeof(ControlData.Password), (_passwordLen + 1) * sizeof(WCHAR)));
		ControlData.ControlCode = ControlCode;
		if (DataSize)
			memcpy(&ControlData.Config, Data, DataSize);
		return DeviceIoControl(_filterDevice, DISKFILTER_IOCTL_DRIVER_CONTROL, &ControlData, sizeof(ControlData), Output, (DWORD)OutputSize, &dwRead, NULL) && dwRead == OutputSize;
	}

	BOOL ChangeProtectConfig(PDISKFILTER_PROTECTION_CONFIG Config) const
	{
		return DeviceControl(DISKFILTER_CONTROL_SETCONFIG, Config, sizeof(*Config));
	}

	BOOL ChangeDriverLoadState(BOOL AllowDriverLoad) const
	{
		return DeviceControl(AllowDriverLoad ? DISKFILTER_CONTROL_ALLOW_DRIVER_LOAD : DISKFILTER_CONTROL_DENY_DRIVER_LOAD);
	}

	BOOL MountDirectDisk(DWORD DiskNum, DWORD PartNum, WCHAR VolumeLetter, BOOL ReadOnly) const
	{
		DISKFILTER_DIRECTDISK DDConf = { 0 };
		DDConf.DiskNumber = DiskNum;
		DDConf.PartitionNumber = PartNum;
		DDConf.DriveLetter = VolumeLetter;
		DDConf.ReadOnly = ReadOnly;
		return DeviceControl(DISKFILTER_CONTROL_MOUNT_DIRECT_DISK, &DDConf, sizeof(DDConf));
	}

	BOOL UnmountDirectDisk(ULONG Number) const
	{
		return DeviceControl(DISKFILTER_CONTROL_UNMOUNT_DIRECT_DISK, &Number, sizeof(ULONG));
	}

	BOOL GetDirectDiskList(PDISKFILTER_DIRECTDISK_STATUS DDList) const
	{
		return DeviceControl(DISKFILTER_CONTROL_GET_DIRECTDISK_STATUS, NULL, 0, DDList, sizeof(*DDList));
	}

	BOOL SetSaveData(DWORD DiskNum, DWORD PartNum) const
	{
		DISKFILTER_SAVEDATA SDConf = { 0 };
		SDConf.DiskNumber = DiskNum;
		SDConf.PartitionNumber = PartNum;
		return DeviceControl(DISKFILTER_CONTROL_SET_SAVE_DATA, &SDConf, sizeof(SDConf));
	}

	BOOL CancelSaveData(DWORD DiskNum, DWORD PartNum) const
	{
		DISKFILTER_SAVEDATA SDConf = { 0 };
		SDConf.DiskNumber = DiskNum;
		SDConf.PartitionNumber = PartNum;
		return DeviceControl(DISKFILTER_CONTROL_CANCEL_SAVE_DATA, &SDConf, sizeof(SDConf));
	}

	BOOL GetSaveDataList(PDISKFILTER_SAVEDATA_STATUS SDList) const
	{
		return DeviceControl(DISKFILTER_CONTROL_GET_SAVE_DATA, NULL, 0, SDList, sizeof(*SDList));
	}

	static UINT FindDriverItemByHash(PDISKFILTER_PROTECTION_CONFIG Config, UCHAR Hash[32])
	{
		for (UCHAR i = 0; i < Config->DriverCount; i++)
			if (!memcmp(Config->DriverList[i], Hash, sizeof(Hash)))
				return i;
		return -1;
	}

	static UINT FindThawSpaceItemByVolume(PDISKFILTER_PROTECTION_CONFIG Config, WCHAR VolumeLetter)
	{
		for (UCHAR i = 0; i < Config->ThawSpaceCount; i++)
			if ((Config->ThawSpacePath[i][MAX_PATH] & ~DISKFILTER_THAWSPACE_HIDE) == VolumeLetter)
				return i;
		return -1;
	}

	static ULONG FindDirectDiskItemByVolume(PDISKFILTER_DIRECTDISK_STATUS Config, WCHAR VolumeLetter)
	{
		for (UCHAR i = 0; i < Config->MountVolumeCount; i++)
			if (Config->MountVolume[i].DriveLetter == VolumeLetter)
				return Config->MountVolume[i].Number;
		return -1;
	}
};

#ifdef _DEFINED_tsprintf
#undef _DEFINED_tsprintf
#undef _tsprintf_s
#endif