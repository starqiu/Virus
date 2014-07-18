#include <windows.h>

BYTE code[]={0x68,0xCC,0xDD,0xAA,0xBB
	,0xB8,0x7b,0x1d,0x80,0x7c
	,0xFF,0xD0
	,0xC3
};

int main(int argc, char *argv[])
{	

    int     PID         = 7536;
    int     TID         = 0;
	DWORD hproc,hthrd;
	int rstr,rcode,base_addr,old,numx;
	
    HANDLE  hProcess    = 0; 
    PBYTE   pCodeRemote = NULL;
    DWORD   dwNumBytesXferred = 0;
    
    PBYTE   pCode      = NULL;
    DWORD   dwSizeOfCode = 0;
    
    HANDLE  hThread	   = 0;
    DWORD   dwThreadId = 0;
    int	    exitcode   = 0;
	char* hstr = "hello.exe";
	int hsize=strlen(hstr);
	
	

    if (argc < 2) {
        printf("Usage: %s pid\n", argv[0]);
        return -1;
    }
    PID = atoi(argv[1]);
    if (PID <= 0) {
        printf("[E]: pid should be greater than zero!\n"); 
        return -1;
    }
	
    pCode = (PBYTE)code;
    dwSizeOfCode = sizeof(code);

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
	
	//inject "hello.exe"
	 printf("[I]: Allocating remote memory with size of 0x%08x ......", 
        hsize);

    pStrRemote = (PBYTE) VirtualAllocEx(hProcess, 
            0, 
            hsize, 
            MEM_COMMIT, 
            PAGE_EXECUTE_READWRITE);		
    if (pStrRemote == NULL) {
        printf("failed.\n");
        CloseHandle(hProcess);
        return -1;
    }
    printf("ok at 0x%08x.\n", pStrRemote);

    printf("[I]: Writing code ......");
    if (WriteProcessMemory(hProcess, 
            pStrRemote, 
            hstr, 
            hsize, 
            &dwNumBytesXferred) == 0) {
        printf("failed.\n");
        VirtualFreeEx(hProcess, pStrRemote,
                hsize, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    };
    printf("ok (%d bytes were written).\n", dwNumBytesXferred);
        
    printf("[I]: Creating a remote thread ......");
    hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE) pStrRemote,
            pStrRemote, 0 , &dwThreadId);
    if (hThread == 0) {
        printf("failed.\n");
        if ( pStrRemote != 0 )	
            VirtualFreeEx(hProcess, pStrRemote, 0, MEM_RELEASE);
        if ( hThread != 0 )			
            CloseHandle(hThread);
        return -1;
    }
    printf("ok.\n");
	
	//inject code
	

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
    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, (PDWORD) &exitcode);
    printf("exited with 0x%08X\n", exitcode);
 
    VirtualFreeEx(hProcess, pCodeRemote, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
	
	__asm{
		push 0xBBAADDCC
		mov eax,0xAABBCCDD
		call eax
		ret
	}
}