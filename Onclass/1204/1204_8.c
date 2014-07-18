#include <stdio.h>
int main(int argc,char* argv[]){//函数嵌套
	int x=9;
	__asm call func;
	printf("%d",x);
	return 0;
	__asm{
		func:
			mov dword ptr[x],5
			ret
	}
}