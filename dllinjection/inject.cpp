#include <cstdio>
#include <Windows.h>

int main(int argc, char *argv[]) {
		char appName[_MAX_PATH];
		char dllName[_MAX_PATH];

		int process_id;

		if (argc < 3) {
			printf ("Usage: %s pid dll", argv[0]);
			return 0;
		}
		else {
			process_id = atoi(argv[1]);
			strcpy(dllName, argv[2]);
		}

		HANDLE hProcess;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
		if (!hProcess) {
			printf("[ERROR] Couldn't open process.\n");
			return 0;
		}

		// Then we need to allocate memory in the process for our .dll name
		// This needs to be done because our remote thread will read the
		// remote process memory once it's there, not current dll memory
		LPVOID lpMemory;
		lpMemory = (LPVOID)VirtualAllocEx(hProcess, NULL, sizeof(dllName), MEM_COMMIT, PAGE_READWRITE);
		if (!lpMemory) {
			printf("[ERROR] Couldn't allocate memory.\n");
			return 0;
		}

		DWORD hWrite;
		hWrite = WriteProcessMemory(hProcess, lpMemory, (LPVOID)dllName, sizeof(dllName), NULL);
		if (hWrite == 0) {
			printf("[ERROR] Couldn't write any bytes.\n");
			return 0;
		}
		// Process started, throw our dll in
		// First, capture LoadLibraryA from kernel32.dll

		HMODULE hKernel32;
		hKernel32 = GetModuleHandle("kernel32.dll");
		if (!hKernel32) {
			printf("[ERROR] Couldn't open kernel32.\n");
			return 0;
		}

		LPVOID  lpLoadLibraryA;
		lpLoadLibraryA = (LPVOID)(GetProcAddress(hKernel32, "LoadLibraryA"));
		if (!lpLoadLibraryA) {
			printf("[ERROR] Couldn't open LoadLibraryW.\n");
			return 0;
		}

		// Now the memory is set up and we have LoadLibraryA, we simply
		// need to create a remote thread that will run LoadLibraryA with
		// our dll in the remote process
		HANDLE hThread;
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpLoadLibraryA, lpMemory, 0, NULL);
		if (!hThread) {
			printf("[ERROR] Couldn't open LoadLibraryA thread. Dll not injected.\n");
			return 0;
		}

		// Our thread is running, wait for it to return. If thread executed fine,
		// it will return WAIT_OBJECT_0, that is, our thread returned 0 (OK)
		// WAIT_OBJECT_0 == 0x00000000L
		DWORD hWait;
		hWait = WaitForSingleObject(hThread, INFINITE);
		if (hWait) {
			printf("[ERROR] Thread didn't return 0. Dll not injected.\n");
			return 0;
		}

		// However, this doesn't mean our .dll was injected. To be sure,
		// We need to check thread exit status code, that is, in this case,
		// LoadLibraryA return value. Also check if get exit code succeeds
		DWORD  hDll;
		BOOL tExit;
		tExit = GetExitCodeThread(hThread, &hDll);
		//printf("Thread & Result: %d,%d\n", GetCurrentThreadId(),hDll);
		if (!tExit) {
			printf("[ERROR] Can't get LoadLibraryA return handle.\n");
			return 0;
		}

		if (hDll == 0x00000000) {
			printf("[ERROR] LoadLibraryA couldn't inject dll.\n");
			DWORD dLastError = GetLastError();
			printf("Error: %d", dLastError);
			return 0;
		}

		// Let the process return it's intended course. Clean up
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, lpMemory, sizeof(dllName), MEM_RELEASE);
		CloseHandle(hProcess);
		return 0;
}
