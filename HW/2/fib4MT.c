#include <stdio.h>
#include <stdlib.h>
struct ctx {
  int eip, esp, ebx, ebp;
} M, A, B;
int temp=0;
int n=0;
int round=0;
char* d="%d ";
char* dn="%d\n";
__declspec(naked) void swtch(struct ctx *from, struct ctx *to)
{
    __asm{
        mov eax, [esp+4]
        pop dword ptr [eax]
        mov [eax+4], esp
        mov [eax+8], ebx
        mov [eax+12], ebp
        mov eax, [esp+8]
        mov ecx, [esp+4]
        mov ebp, [ecx+12]
        mov ebx, [ecx+8]
        mov esp, [ecx+4]
        push [ecx]
        ret
    }
}

void A_proc()
{	
__asm{
	push ebp
	mov ebp,esp
    sub esp,8
	mov dword ptr [ebp-8],1//init var f=1 for A's fib
	mov dword ptr [ebp-4],1//init counter i=1 
	mov eax,dword ptr [ebp-8]
	push eax//arg2 f
	push d//arg1 "%d "
	call printf
	add esp,8
	push offset B
	push offset A
	call swtch
	add esp,8
	jmp L0
L3:
	mov ecx,dword ptr[ebp-4]//i++
	add ecx,1
	mov dword ptr[ebp-4],ecx
L0:
	mov edx,dword ptr[round]
	cmp dword ptr[ebp-4],edx
	jge L2//i>=round
L1:	
	mov eax,dword ptr[ebp-8]//f
	add eax,dword ptr[temp]
	mov dword ptr[ebp-8],eax//f+=temp
	mov ecx,dword ptr[ebp-8]
	mov dword ptr[temp],ecx//temp=f
	
	mov edx,dword ptr [temp]//printf("%d ",temp);
	push edx
	push d//arg1 "%d "
	call printf
	add esp,8
	
	push offset B//swtch(&A, &B);
	push offset A
	call swtch
	add esp,8

	jmp L3
L2:	
	mov eax,dword ptr [n]
	and eax,1
	cmp eax,0
	jne L4//odd
	mov eax,dword ptr [ebp-8]//f+=temp;
	add eax,dword ptr [temp]
	mov dword ptr [ebp-8],eax
	mov ecx,dword ptr [ebp-8]//temp =f;
	mov dword ptr [temp],ecx
	
	mov edx,dword ptr [temp]//printf("%d\n",temp);
	push edx
	push d//arg1 "%d "
	call printf
	add esp,8
	
	push offset M
	push offset A
	call swtch
	add esp,8
L4:
	mov esp,ebp
	pop ebp
	ret
}
}

void B_proc()
{
__asm{
	push ebp
	mov ebp,esp
    sub esp,8
	mov dword ptr [ebp-8],1//init var f=1 for B's fib
	mov dword ptr [ebp-4],1//init counter i=1 
	mov eax,dword ptr [ebp-8]
	mov dword ptr [temp],eax//temp=f
	push eax//arg2 f
	push dn//arg1 "%d "
	call printf
	add esp,8
	push offset A
	push offset B
	call swtch
	add esp,8
	jmp L0
L3:
	mov ecx,dword ptr[ebp-4]//i++
	add ecx,1
	mov dword ptr[ebp-4],ecx
L0:
	mov edx,dword ptr[round]
	sub edx,1
	cmp dword ptr[ebp-4],edx
	jge L2//i>=round-1
L1:	
	mov eax,dword ptr[ebp-8]//f
	add eax,dword ptr[temp]
	mov dword ptr[ebp-8],eax//f+=temp
	mov ecx,dword ptr[ebp-8]
	mov dword ptr[temp],ecx//temp=f
	
	mov edx,dword ptr [temp]//printf("%d\n",temp);
	push edx
	push dn//arg1 "%d\n"
	call printf
	add esp,8
	
	push offset A//swtch(&B, &A);
	push offset B
	call swtch
	add esp,8

	jmp L3
L2:	
	mov eax,dword ptr [ebp-8]//f+=temp;
	add eax,dword ptr [temp]
	mov dword ptr [ebp-8],eax
	mov ecx,dword ptr [ebp-8]//temp =f;
	mov dword ptr [temp],ecx
	
	mov edx,dword ptr [temp]//printf("%d\n",temp);
	push edx
	push dn//arg1 "%d "
	call printf
	add esp,8
	
	mov eax,dword ptr [n]
	and eax,1
	cmp eax,0
	jne L7//odd
L6:
	push offset A
	jmp L5
L7:
	push offset M
L5:
	push offset B
	call swtch
	add esp,8
L4:
	mov esp,ebp
	pop ebp
	ret
}
}

int main(int argc, char *argv[])
{
  int Astack[1024];
  int Bstack[1024];
  if (argc < 2) {
    printf("Usage: %s number(2<=N<40)\n", argv[0]);
    return -1;
  }
  n = atoi(argv[1]);
  round=(n+1)/2;
  A.eip = (int)A_proc;
  A.esp = (int)(&Astack[1023]);
  B.eip = (int)B_proc;
  B.esp = (int)(&Bstack[1023]);
  swtch(&M, &A);
  printf("\nfib(%d) = %d\n",n,temp);
  system("pause");
  return 0;
}