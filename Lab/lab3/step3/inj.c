//inj.c
#include <windows.h>
PBYTE pRemoteCode, pCode, pOrignCode;
DWORD dwSizeOfCode;

void code_start();
void _str_msgboxa();
void _addr_GetModuleHandleA();
DWORD GetIAFromImportTable(DWORD dwBase, LPCSTR lpszFuncName);
// code_start是二进制码的开始标记
__declspec(naked) void code_start()
{
    __asm {
        push ebp
        mov  ebp, esp
        push ebx
//Local variables
        sub  esp, 0x10
        // ebp - 0x0C ===> ImageBase
// self-locating 自定位 请阅读并理解下面3条指令的含义
        call _delta
_delta:
        pop  ebx
        sub  ebx, offset _delta
// 调用GetModuleHandleA()
        push 0
        lea  ecx, [ebx + _addr_GetModuleHandleA]
        call dword ptr [ecx]
        cmp  eax, 0x0
        jne  _cont1
        mov  eax, 0x1
        jmp  _ret
_cont1:
        mov  [ebp-0x0C], eax
// 调用GetIAFromImportTable();
        lea  ecx, [ebx + _str_msgboxa]
        push ecx
        push [ebp-0x0C]
        call offset GetIAFromImportTable
        add  esp, 0x8
        cmp  eax, 0x0
        jne  _ret
        mov  eax, 0x2
_ret:
        add  esp, 0x20
        pop  ebx
        mov  esp, ebp
        pop  ebp
        ret
    }
}
// _str_msgboxa是字符串”MessageBoxA”的地址
__declspec(naked) void _str_msgboxa()
{
    __asm {
        _emit 'M'
        _emit 'e'
        _emit 's'
        _emit 's'
        _emit 'a'
        _emit 'g'
        _emit 'e'
        _emit 'B'
        _emit 'o'
        _emit 'x'
        _emit 'A'
        _emit 0x0
    }
}
// _addr_GetModuleHandleA是存放GetModuleHandleA()的全局变量
__declspec(naked) void _addr_GetModuleHandleA()
{
    __asm {
        _emit 0xAA
        _emit 0xBB
        _emit 0xAA
        _emit 0xEE
    }
}

DWORD GetIAFromImportTable(DWORD dwBase, LPCSTR lpszFuncName)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADER32 pOptHeader;
    DWORD dwRVAImpTbl;
    DWORD dwSizeOfImpTbl;
    PIMAGE_IMPORT_DESCRIPTOR pImpTbl, p;
	DWORD pthunk;
    
    DWORD dwIA = 0;
    pDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    pNtHeaders = (PIMAGE_NT_HEADERS)(dwBase + pDosHeader->e_lfanew);
    pOptHeader = &(pNtHeaders->OptionalHeader);
    dwRVAImpTbl = pOptHeader->DataDirectory[1].VirtualAddress;
    dwSizeOfImpTbl = pOptHeader->DataDirectory[1].Size;
    pImpTbl = (PIMAGE_IMPORT_DESCRIPTOR)(dwBase + dwRVAImpTbl);
	
    for (p = pImpTbl; (DWORD)p < ((DWORD)pImpTbl + dwSizeOfImpTbl); p++){
	  pthunk = GetIAFromImpDesc(dwBase, lpszFuncName, p) ;   
	  if(pthunk !=0) break;
    }
	return pthunk;
} 

DWORD GetIAFromImpDesc(DWORD dwBase, LPCSTR lpszName, 
        PIMAGE_IMPORT_DESCRIPTOR pImpDesc) 
{
    PIMAGE_THUNK_DATA pthunk, pthunk2;
    PIMAGE_IMPORT_BY_NAME pOrdinalName;
    if (pImpDesc->Name == 0) return 0;
    pthunk = (PIMAGE_THUNK_DATA) (dwBase + pImpDesc->OriginalFirstThunk);
    pthunk2 = (PIMAGE_THUNK_DATA) (dwBase + pImpDesc->FirstThunk);
    for (; pthunk->u1.Function != 0; pthunk++, pthunk2++) {
        if (pthunk->u1.Ordinal & 0x80000000) continue;
        pOrdinalName = (PIMAGE_IMPORT_BY_NAME) (dwBase + pthunk->u1.AddressOfData);
        if (CompStr((LPSTR)lpszName, (LPSTR)&pOrdinalName->Name)) 
            return (DWORD)pthunk2;
    }
    return 0;
}

BOOL CompStr(LPSTR s1, LPSTR s2)
{
    PCHAR p, q;
    for (p = s1, q = s2; (*p != 0) && (*q != 0); p++, q++) {
        if (*p != *q) return FALSE;
    }
    return TRUE;
}

// 这里请填入GetIAFromImportTable()函数的相关代码
// code_end是二进制码的结束标记 int 3
__declspec(naked) void code_end()
{
    __asm _emit 0xCC
}
// make_code()函数是将开始标记和结束标记之间的所有二进制数据拷贝到一个缓冲区中
DWORD make_code()
{
    int off; 
    DWORD func_addr;
    HMODULE hModule;
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
    hModule = LoadLibrary("kernel32.dll");
    if (hModule == NULL) {
        printf("[E]: kernel32.dll cannot be loaded. \n");
        return 0;
    }
    func_addr = (DWORD)GetProcAddress(hModule, "GetModuleHandleA");
    if (func_addr == 0) {
        printf("[E]: GetModuleHandleA not found. \n");
        return 0;
    }
    off = (DWORD)pCode - (DWORD)pOrignCode;
	printf("off:0x%08x \n",off);
	printf("func_addr:0x%08x \n",func_addr);
    *(PDWORD)((PBYTE)_addr_GetModuleHandleA + off) = func_addr;
	printf("_addr_GetModuleHandleA:0x%08x \n",_addr_GetModuleHandleA);
    return dwSizeOfCode;
}

// inject_code()函数是存放在pCode所指向的缓冲区中的二进制代码注入到远程进程中
int inject_code(DWORD PID)
{
    //请填入代码，完成注入过程
	int TID=0;
	DWORD hproc, hthrd;
	int rstr, rcode, old, numx,nWrite;
	DWORD pthunkOfMBA = 0;
	
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
	
	GetExitCodeThread(hthrd, &pthunkOfMBA);
	printf("pthunk Of MessageBoxA in the ImportTable of hello.exe: 0x%08x\n", pthunkOfMBA);
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