#include <windows.h>

int main(){
	HMODULE hmod =NULL;
	char* msgDll="msg4.dll";
	char* showMsgFunc="ShowMsg";
	char* hello="hello\n";
	__asm{
		push msgDll
		call dword ptr[LoadLibraryA]
		mov hmod,eax
		push showMsgFunc
		push eax
		call dword ptr[GetProcAddress]
		push hello
		call eax
		add esp,4
		push hmod
		call dword ptr[FreeLibrary]
	}
	return 0;
}