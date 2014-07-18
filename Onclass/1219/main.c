#include <windows.h>
#include <stdio.h>

int main(){
	char* mstr ="LoadLibraryA:0x%08x\n";
	__asm{
		push dword ptr[LoadLibraryA]
		push mstr
		call printf
		add esp,8
	}
	return 0;
	__asm{
		push 0xBBAADDCC
		mov eax,0xAABBCCDD
		call eax
		ret
	}
}