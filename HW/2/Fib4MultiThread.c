#include <stdio.h>
struct ctx {
  int eip, esp, ebx, ebp;
} M, A, B;
int temp=0;
int n=5;
int round=0;
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
	
	int f=1;
	int i=1;
	printf("%d ",f);
	swtch(&A, &B);
	for(;i<round;i++){
		f+=temp;
		temp =f;
		printf("%d ",temp);
		swtch(&A, &B);	
	}
	if(n%2==0){
		f+=temp;
		temp =f;
		printf("%d\n",temp);
		swtch(&A, &M);
	}
    
}

void B_proc()
{
	int f=1;
	int j=1;
	temp =f;
	printf("%d\n",temp);
	swtch(&B, &A);
	for(;j<round-1;j++){
		f+=temp;
		temp =f;
		printf("%d\n",temp);
		swtch(&B, &A);
	}
	if(n%2==1){
		f+=temp;
		temp =f;
		printf("%d\n",temp);
		swtch(&B, &M);
	}else{
		f+=temp;
		temp =f;
		printf("%d\n",temp);
		swtch(&B, &A);
	}
}
/*
int main()
{
  int Astack[1024];
  int Bstack[1024];
  round=(n+1)/2;
  A.eip = (int)A_proc;
  A.esp = (int)(&Astack[1023]);
  B.eip = (int)B_proc;
  B.esp = (int)(&Bstack[1023]);
  swtch(&M, &A);
  printf("%d\n",temp);
  system("pause");
  return 0;
}*/