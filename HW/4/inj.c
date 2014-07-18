#include <windows.h>
char *hstr = "hello.exe";
char code[] = {//LoadLibraryA("hello.exe")
	0x68, 0xCC, 0xDD, 0xAA, 0xBB,//push the addr of "hello"
	0xB8, 0x7B, 0x1D, 0x80, 0x7C,//mov eax,...
	0xFF, 0xD0,//call eax
	0xC3
};
char code4Mod[]={0xEB,0xE7};//将条件跳转 变成无条件跳转
int main(int argc, char *argv[]){	
   int PID = 4180, TID=0;
   DWORD hproc, hthrd;
   int rstr, rcode, old, numx,nWrite;
   DWORD base_addr = 0;
   int offset4Mod=0x1D;//the offset from the code going to be modified to the base address of "hello.exe"
   if (argc < 2) {
        printf("Usage: %s PID\n", argv[0]);
        return -1;
    }
    PID = atoi(argv[1]);
    if (PID <= 0) {
        printf("[E]: PID must be positive (PID>0)!\n"); 
        return -2;
    }
   printf("code addr: 0x%08x\n", code);
   hproc = OpenProcess(
          PROCESS_CREATE_THREAD  | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION   | PROCESS_VM_WRITE 
        | PROCESS_VM_READ, FALSE, PID);
   if (!hproc) printf("openprocess error \n");
   else printf("openprocess ok \n");
   rstr = (PBYTE) VirtualAllocEx(hproc, 
        0, 12, MEM_COMMIT, PAGE_READWRITE);
	printf("rstr : 0x%08x\n", rstr);
   WriteProcessMemory(hproc, rstr, hstr, 10, &numx);
   __asm {
     mov ebx, offset code
     mov eax, dword ptr [rstr]
     mov [ebx+0x1], eax 
   }
   rcode = (PBYTE) VirtualAllocEx(hproc, 
        0, 20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);	
   printf("rcode : 0x%08x\n", rcode);
   WriteProcessMemory(hproc, rcode, code, sizeof(code), &numx);
   hthrd = CreateRemoteThread(hproc, 
      NULL, 0, (LPTHREAD_START_ROUTINE)rcode,
            0, 0 , &TID);
   if (!hthrd) printf("CreateRemoteThread error \n");
   else printf("CreateRemoteThread ok \n");
   WaitForSingleObject(hthrd, 0xFFFFFFFF);  
   printf("hthrd : 0x%08x\n", hthrd);
   GetExitCodeThread(hthrd, &base_addr);
   printf("base addr of %s: 0x%08x\n", hstr, base_addr);
   base_addr=base_addr+0x101A;
   if (!WriteProcessMemory(hproc, 
        base_addr, code4Mod, sizeof(code4Mod), &nWrite)) {
        printf("[E]: Write string to remote process failed at 0x%08x!\n", base_addr);
    } else {
        printf("[I]: Write string (size: %d) to remote process at 0x%08x.\n", nWrite, base_addr);
    }
   return 0;
}