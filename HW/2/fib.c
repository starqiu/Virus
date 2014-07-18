#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
    int n, r=0;
    if (argc < 2) {
        printf("Usage: %s number(<40)\n", argv[0]);
        return -1;
    }
    n = atoi(argv[1]);
    __asm {
		xor eax,eax
		push n//pass parameter
		call fib		
		add esp,4
		mov dword ptr [r],eax
		jmp end	
	fib:
		push ebp
		mov ebp,esp
		mov ecx,dword ptr [ebp+8]//get parameter
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
		pop eax//fib(n-1)
		add eax,dword ptr [r]//fib(n-1)+fib(n-2)
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
