#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
    int n, r=0;
    n = 3;
    __asm{
		mov ebx,dword ptr[n]
		xor eax,eax
		push ebx//pass parameter
		call fib
		jmp end
	fib:
		push ebp
		mov ebp,esp
		push ebx//save callee register
		mov ebx,dword ptr [esp+8]//get parameter
		cmp ebx,0
		jb L0
		cmp ebx,0
		je L1
		cmp ebx,1
		je L1
		mov eax,ebx
		sub eax,1
		push eax
		call fib//fib(n-1)
		mov dword ptr [r],eax
		mov eax,ebx
		sub eax,2
		push eax
		call fib//fib(n-2)
		add eax,dword ptr [r]
		mov dword ptr [r],eax
		add esp,4//restore stack frame
		pop ebx
		pop ebp
		ret
	L0:
		mov eax,0
		add esp,4//restore stack frame
		pop ebx
		pop ebp
		ret
	L1:
		mov eax,1
		add esp,4//restore stack frame
		pop ebx
		pop ebp
		ret  
	end:
    }
 printf("fib(%d) = %d\n", n, r);
 return 0;
}
