#include <windows.h>
char* hack= "I'm hacked!";
char code[]={0x55
	,0x8B,0xEC
	,0x6A,0x00
	,0x68,0x00,0x80,0x40,0x00
	,0x68,0x00,0x80,0x40,0x00
	,0x6A,0x00
	,0xE8,0xC4,0x87,0x94,0x77
	,0x5D
	,0xC3
};

void f(){
    MessageBoxA(0,hack,hack, MB_OK);
}
__declspec(naked) void main()
{
	int op;
    VirtualProtect(&code[0], sizeof(code), PAGE_EXECUTE_READWRITE, &op);
	
	__asm{
		call offset code
		add esp,16
	}
   /* __asm {
	   push ebp
	   mov ebp,esp
	   sub esp,8
	   mov  [ebp-0x14], 'h'
	   mov  [ebp-0x13], 'a'
	   mov  [ebp-0x12], 'c'
	   mov  [ebp-0x11], 'k'
	   mov  [ebp-0x10], 'e'
	   mov  [ebp-0x0f], 'd'
	   mov  [ebp-0x0e], '!'
	   mov  [ebp-0x0d], 0x0
	   lea  eax, [ebp-0x14]
	   push 0
	   push eax
	   push eax
	   push 0	   
       call offset code	   
	   add esp,16
	   add esp,8
	   ret
    }*/
} 
