#include <Windows.h>
#include <tlhelp32.h>
#include <ntstatus.h>

#include <string>
#include <vector>
#include <iostream>

#ifdef UNICODE
std::string ToString(LPCTSTR lpString)
{
	int iLen = 0;
	std::vector<char> buffer;

	iLen = WideCharToMultiByte(CP_ACP, 0, lpString, -1, NULL, 0, NULL, NULL);
	buffer.resize(iLen);
	WideCharToMultiByte(CP_ACP, 0, lpString, -1, static_cast<LPSTR>(&buffer[0]), iLen, NULL, NULL);

	return std::string(&buffer[0]);
}
#else
std::string ToString(LPCTSTR lpString)
{
	return std::string(lpString);
}
#endif

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _PROCESS_BASIC_INFORMATION
{
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessResourceManagement,
	ProcessCookie,
	ProcessImageInformation,
	MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG  ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PWCHAR Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef ULONG GDI_HANDLE_BUFFER[60];

typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		} s1;
	} u1;

	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ReservedBits0 : 25;
		} s2;
	} u2;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	} u3;
	ULONG SystemReserved[1];
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];

	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData; // HotpatchInformation
	PVOID* ReadOnlyStaticServerData;

	PVOID AnsiCodePageData; // PCPTABLEINFO
	PVOID OemCodePageData; // PCPTABLEINFO
	PVOID UnicodeCaseTableData; // PNLSTABLEINFO

	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;

	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;

	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps; // PHEAP

	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;

	PRTL_CRITICAL_SECTION LoaderLock;

	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG_PTR ActiveProcessAffinityMask;
	GDI_HANDLE_BUFFER GdiHandleBuffer;
	PVOID PostProcessInitRoutine;

	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];

	ULONG SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

	UNICODE_STRING CSDVersion;

	PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
	PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
	PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

	SIZE_T MinimumStackCommit;

	PVOID* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
	ULONG FlsHighIndex;

	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
	PVOID pUnused; // pContextData
	PVOID pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		} s3;
	} u4;
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	PVOID TppWorkerpListLock;
	LIST_ENTRY TppWorkerpList;
	PVOID WaitOnAddressHashTable[128];
	PVOID TelemetryCoverageHeader; // REDSTONE3
	ULONG CloudFileFlags;
} PEB, *PPEB;

typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength);

HMODULE hModule = NULL;
pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;

BOOL Initialize()
{
	hModule = LoadLibrary(TEXT("ntdll.dll"));
	if (hModule == NULL)
	{
		fprintf(stderr, "加载 ntdll.dll 失败: %d", GetLastError());
		return FALSE;
	}

	NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL)
	{
		fprintf(stderr, "获取 NtQueryInformationProcess 函数失败: %d", GetLastError());
		FreeLibrary(hModule);
		return FALSE;
	}

	return TRUE;
}

void Uninitialize()
{
	FreeLibrary(hModule);
}

BOOL QueryProcessCommandLine(LPCTSTR lpProcessName, LPCTSTR lpCommandLine)
{
	BOOL bRet = FALSE;
	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = INVALID_HANDLE_VALUE;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	DWORD dwErr = 0;
	PROCESS_BASIC_INFORMATION pbi;
	ULONG requiredLen = 0;
	SIZE_T numberOfBytesRead = 0;
	PEB peb;
	size_t offset = 0;
	size_t paramAddress = 0;
	UNICODE_STRING commandLine;
	TCHAR buffer[1024];

	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
	{
		std::cerr << "获得进程快照失败: " << GetLastError() << std::endl;
		return bRet;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe32);
	do
	{
		std::cout << ToString(pe32.szExeFile) << std::endl;

		if (!lstrcmp(pe32.szExeFile, lpProcessName))
		{
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
			if (hProcess == INVALID_HANDLE_VALUE)
			{
				if ((dwErr = GetLastError()) == ERROR_ACCESS_DENIED)
				{
					std::cerr << "没有权限: " << ToString(lpProcessName) << std::endl;
				}
				continue;
			}

			if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &requiredLen) != STATUS_SUCCESS)
			{
				std::cerr << "查询进程信息失败: " << ToString(lpProcessName) << std::endl;
				CloseHandle(hProcess);
				continue;
			}

			if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &numberOfBytesRead))
			{
				std::cerr << "获取 PEB 失败: " << ToString(lpProcessName) << std::endl;
				CloseHandle(hProcess);
				continue;
			}

			offset = reinterpret_cast<size_t>(pbi.PebBaseAddress) + offsetof(PEB, ProcessParameters);

			if (!ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(offset), &paramAddress, sizeof(size_t), &numberOfBytesRead))
			{
				std::cerr << "获取进程参数偏移地址失败: " << ToString(lpProcessName) << std::endl;
				CloseHandle(hProcess);
				continue;
			}

			offset = paramAddress + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine);

			if (!ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(offset), &commandLine, sizeof(UNICODE_STRING), &numberOfBytesRead))
			{
				std::cerr << "获取命令行参数失败: " << ToString(lpProcessName) << std::endl;
				CloseHandle(hProcess);
				continue;
			}

			ZeroMemory(buffer, sizeof(buffer));

			if (!ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(commandLine.Buffer), &buffer, sizeof(buffer), &numberOfBytesRead))
			{
				std::cerr << "获取命令行参数失败: " << ToString(lpProcessName) << std::endl;
				CloseHandle(hProcess);
				continue;
			}

			std::cout << "commond line: " << ToString(buffer) << std::endl;

			CloseHandle(hProcess);
		}
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return bRet;
}

int main()
{
	SetConsoleOutputCP(CP_UTF8);
	if (!Initialize())
	{
		return 1;
	}

	QueryProcessCommandLine(TEXT("main.exe"), TEXT("232"));

	Uninitialize();
	return 0;
}

