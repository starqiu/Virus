#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
    int n, r=0;
    n = 6; 
    __asm{
		//mov ecx,dword ptr[n]
		xor eax,eax
		push n//pass parameter
		call fib		
		add esp,4
		mov dword ptr [r],eax
		jmp end
		//pop ebx
		//ret
		
	fib:
		push ebp
		mov ebp,esp
		mov ecx,dword ptr [ebp+8]
		cmp ecx,0
		jb L0
		cmp ecx,0
		je L1
		cmp ecx,1
		je L1
		mov eax,ecx
		sub eax,1
		push eax
		call fib//fib(n-1)
		add esp,4//restore stack frame
		push eax
		mov ecx,dword ptr [ebp+8]
		sub ecx,2
		push ecx
		call fib//fib(n-2)
		mov dword ptr [r],eax
		add esp,4//restore stack frame	
		pop eax
		add eax,dword ptr [r]
		pop ebp
		ret
	L0:
		mov eax,0
		pop ebp
		ret
	L1:
		mov eax,1
		pop ebp
		ret  
	end:	
	} 
	printf("fib(%d) = %d\n", n, r);
	return 0;
}