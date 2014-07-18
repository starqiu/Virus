#include <windows.h>
typedef int (*MYPROC) (char* s);

int main(){
	HMODULE hmod = LoadLibraryA("msg4.dll");
	MYPROC proc = (MYPROC)GetProcAddress(hmod,"ShowMsg");
	proc("hello\n");
	FreeLibrary(hmod);
	return 0;
}