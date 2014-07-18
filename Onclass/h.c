#include <stdio.h>
int main(){
	char* hw="hello world\n";
	__asm{
		push hw
		call printf
		add esp,4
	}
	return 0;
}