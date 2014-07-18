#include <stdio.h>

int add(int x, int y) 
{
    __asm {
        mov eax,dword ptr[ebp+8]
		add eax,dword ptr[ebp+12]
    }
}
int main()
{
    //输出 add(2,4)的值
	printf("add(2,4)=%d",add(2,4));
}
