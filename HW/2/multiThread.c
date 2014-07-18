#include <stdio.h>
struct ctx {
  int eip, esp, ebx, ebp;
} M, A, B;

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
    printf("A: 1\n");
    swtch(&A, &B);
    printf("A: 2\n");
    swtch(&A, &B);
    printf("A: 3\n");
    swtch(&A, &M);
}

void B_proc()
{
    printf("B: 1\n");
    swtch(&B, &A);
    printf("B: 2\n");
    swtch(&B, &A);
}

int main()
{
  int Astack[1024];
  int Bstack[1024];
  A.eip = (int)A_proc;
  A.esp = (int)(&Astack[1023]);
  B.eip = (int)B_proc;
  B.esp = (int)(&Bstack[1023]);
  swtch(&M, &A);
  return 0;
}