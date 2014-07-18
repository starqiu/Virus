#include <stdio.h>
int main(){
	int x=9,y=0;
	__asm{
		mov eax,dword ptr [x]
		_emit 0x89
		_emit 0xc1
		mov dword ptr[y],ecx
	}
	printf("%d,%d",x,y);
	return 0;
}