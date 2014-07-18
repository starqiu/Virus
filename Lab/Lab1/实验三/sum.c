int sum(int i) 
{
    __asm {
		// 计算并返回 1+2+…+i的值
		mov ecx,dword ptr[ebp+8]
		xor eax,eax
		mov ebx,0
		
	LOOP_ENTRY:
		inc ebx
		add eax,ebx
		loop LOOP_ENTRY	
    }
}