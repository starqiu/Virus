#include <windows.h>

int main(){
	int code_addr=f;
	printf("code addr:%08x",code_addr);
	pid = atoi(argv[1]);
    if (pid <= 0) {
        printf("[E]: pid must be positive (pid>0)!\n"); 
        return -2;
    }

    hproc = OpenProcess(PROCESS_QUERY_INFORMATION 
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_VM_OPERATION, 0, pid);

    if (hproc == 0) {
        printf("[E]: Process (%d) cannot be opened !\n", pid);
        return -2;
    }
    printf("[I]: Process (%d) is opened --> 0x%08x\n", pid, hproc);

    if (!ReadProcessMemory(hproc, 
        pRemote, &buf, 4, &nRead)) {
        printf("[E]: Read DWORD from remote process failed at 0x%08x!\n", pRemote);
    }
    else {
        printf("[I]: Read DWORD from remote process (%d) from 0x%08x --> 0x%08x \n", pid, pRemote, buf);
    }

    if (!WriteProcessMemory(hproc, 
        pRemote, s, strlen(s)+1, &nWrite)) {
        printf("[E]: Write string to remote process failed at 0x%08x!\n", pRemote);
    } else {
        printf("[I]: Write string (size: %d) to remote process at 0x%08x.\n", nWrite, pRemote);
    }

    if (!CloseHandle(hproc)) {
        printf("[E]: Process (%d) cannot be closed !\n", pid);
        return 2;
    };
    printf("[I]: Process (%d) is closed. \n", pid);
    return 0;
	
	return 0;
	__asm{
	f:
		xor eax,eax
		ret
	}
}