#include <windows.h>
  
typedef struct _UNICODE_STRING {  
  USHORT  Length;  
  USHORT  MaximumLength;  
  PWSTR  Buffer;  
} UNICODE_STRING, *PUNICODE_STRING;  
  

/*

Official struct definition

see: http://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

*/

typedef struct _PEB_LDR_DATA  
{  
   DWORD Length;  
   BOOLEAN Initialized;  
   PVOID SsHandle;  
   LIST_ENTRY InLoadOrderModuleList;  
   LIST_ENTRY InMemoryOrderModuleList;  
   LIST_ENTRY InInitializationOrderModuleList;  
   PVOID EntryInProgress;  
}PEB_LDR_DATA,*PPEB_LDR_DATA;  


/*

Official struct definition 

See: http://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
*/

typedef struct _LDR_MODULE 
{  
   LIST_ENTRY InLoadOrderLinks;  
   LIST_ENTRY InMemoryOrderLinks;  
   LIST_ENTRY InInitializationOrderLinks;  
   PVOID DllBase;  
   PVOID EntryPoint;  
   DWORD SizeOfImage;  
   UNICODE_STRING FullDllName;  
   UNICODE_STRING BaseDllName;  
}LDR_MODULE,*PLDR_MODULE;  

/*

Official definition 

See: http://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  BYTE                          Reserved4[104];
  PVOID                         Reserved5[52];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved6[128];
  PVOID                         Reserved7[1];
  ULONG                         SessionId;
} PEB, *PPEB;
*/


typedef struct _PEB  
{  
    UCHAR InheritedAddressSpace;  
    UCHAR ReadImageFileExecOptions;  
    UCHAR BeingDebugged;  
    UCHAR SpareBool;  
    PVOID Mutant;  
    PVOID ImageBaseAddress;  
    PPEB_LDR_DATA Ldr;  
    DWORD ProcessParameters; //PRTL_USER_PROCESS_PARAMETERS ProcessParameters; 
    PVOID SubSystemData; 
    PVOID ProcessHeap; 
    PVOID FastPebLock; 
    DWORD FastPebLockRoutine; //PPEBLOCKROUTINE FastPebLockRoutine; 
    DWORD FastPebUnlockRoutine; //PPEBLOCKROUTINE FastPebUnlockRoutine; 
    ULONG EnvironmentUpdateCount; 
    PVOID KernelCallbackTable; 
    PVOID EventLogSection; 
    PVOID EventLog; 
    DWORD FreeList; //PPEB_FREE_BLOCK FreeList; 
    ULONG TlsExpansionCounter; 
    PVOID TlsBitmap; 
    ULONG TlsBitmapBits[0x2]; 
    PVOID ReadOnlySharedMemoryBase; 
    PVOID ReadOnlySharedMemoryHeap; 
    PVOID ReadOnlyStaticServerData; 
    PVOID AnsiCodePageData; 
    PVOID OemCodePageData; 
    PVOID UnicodeCaseTableData; 
    ULONG NumberOfProcessors; 
    ULONG NtGlobalFlag; 
    BYTE Spare2[0x4]; 
    LARGE_INTEGER CriticalSectionTimeout; 
    ULONG HeapSegmentReserve; 
    ULONG HeapSegmentCommit; 
    ULONG HeapDeCommitTotalFreeThreshold; 
    ULONG HeapDeCommitFreeBlockThreshold; 
    ULONG NumberOfHeaps; 
    ULONG MaximumNumberOfHeaps; 
    PVOID *ProcessHeaps; 
    PVOID GdiSharedHandleTable; 
    PVOID ProcessStarterHelper; 
    PVOID GdiDCAttributeList; 
    PVOID LoaderLock; 
    ULONG OSMajorVersion; 
    ULONG OSMinorVersion; 
    ULONG OSBuildNumber; 
    ULONG OSPlatformId; 
    ULONG ImageSubSystem; 
    ULONG ImageSubSystemMajorVersion; 
    ULONG ImageSubSystemMinorVersion; 
    ULONG GdiHandleBuffer[0x22]; 
    ULONG PostProcessInitRoutine; 
    ULONG TlsExpansionBitmap; 
    BYTE TlsExpansionBitmapBits[0x80]; 
    ULONG SessionId;
}PEB,*PPEB;  
  

PPEB GetPebBase()
{
    PPEB pPeb = NULL;  
    
    __asm  
    {  
        //1、通过fs:[30h]获取当前进程的_PEB结构  
        mov eax,dword ptr fs:[30h];  
        mov dword ptr [pPeb],eax  
    }
    return pPeb;  
}

PLDR_MODULE pLdrExeMod = NULL;  

int DumpPeb(PPEB pPeb)
{
    PLIST_ENTRY pListEntryStart = NULL,pListEntryEnd = NULL;  
    PPEB_LDR_DATA pPebLdrData = NULL;  
    PLDR_MODULE pLdrMod = NULL;
    
    
    if (pPeb == NULL) return -1;
    
    pPebLdrData = pPeb->Ldr;  
/*      
    pListEntryStart = pPebLdrData->InLoadOrderModuleList.Flink;  
    pListEntryEnd = pListEntryStart;

    pLdrExeMod = (PLDR_MODULE)CONTAINING_RECORD(pListEntryStart,
                LDR_MODULE,InLoadOrderLinks);
                
    printf("In Load-Order Module List:\n");
    do  
    {  
        pLdrMod  = (PLDR_MODULE)CONTAINING_RECORD(pListEntryStart,
                LDR_MODULE,InLoadOrderLinks);  
        
        printf("  %S\n", pLdrMod ->FullDllName.Buffer);
        printf("  Base: 0x%08x\n", pLdrMod ->DllBase);
        printf("  Entry: 0x%08x\n", pLdrMod ->EntryPoint);
                
        pListEntryStart = pListEntryStart->Flink;
          
    }while(pListEntryStart != pListEntryEnd);  
*/    

    pListEntryStart = pPebLdrData->InMemoryOrderModuleList.Flink;  
    pListEntryEnd = pListEntryStart;
      
    printf("In Memory Order Module List:\n");
    do  
    {  
        pLdrMod = (PLDR_MODULE)CONTAINING_RECORD(pListEntryStart,
                LDR_MODULE,InMemoryOrderLinks);
        
        printf("  %S\n", pLdrMod->FullDllName.Buffer);
        printf("  Base: 0x%08x\n", pLdrMod->DllBase);
        printf("  Entry: 0x%08x\n", pLdrMod->EntryPoint);
                
        pListEntryStart = pListEntryStart->Flink;
          
    }while(pListEntryStart != pListEntryEnd);  
    
    return 0;
}

PLDR_MODULE FindLdrMod(PPEB pPeb, DWORD dwBaseAddr)
{
    PLIST_ENTRY pListEntryStart = NULL,pListEntryEnd = NULL;  
    PPEB_LDR_DATA pPebLdrData = NULL;  
    PLDR_MODULE pLdrMod = NULL;
    
    
    if (pPeb == NULL) return NULL;
    
    pPebLdrData = pPeb->Ldr;  
      
    pListEntryStart = pPebLdrData->InLoadOrderModuleList.Flink;  
    pListEntryEnd = pListEntryStart;
    
    do  
    {  
        pLdrMod = (PLDR_MODULE)CONTAINING_RECORD(pListEntryStart,
                LDR_MODULE,InLoadOrderLinks);                  
        pListEntryStart = pListEntryStart->Flink;
        if ((DWORD)pLdrMod->DllBase == dwBaseAddr)
            return pLdrMod;
          
    } while(pListEntryStart != pListEntryEnd);  
    
    printf("[E] Module not found (baseaddr = 0x%08x)", dwBaseAddr);
    return NULL;
}

int BreakLdrLinks(PLDR_MODULE pLdrMod)
{
    PLDR_MODULE pBMod, pFMod;

    if (pLdrMod==NULL) {
        return -1;
    }

    if (pLdrMod->DllBase == 0) {
        return -2;
    }

	//断开InLoadOrderModuleList链
    pFMod = (PLDR_MODULE)CONTAINING_RECORD(pLdrMod->InLoadOrderLinks.Flink,
                LDR_MODULE,InLoadOrderLinks);
    printf("[I] InLoadOrderLinks Flink base=0x%08x name=%S  \n", pFMod->DllBase, pFMod->BaseDllName.Buffer);
    pBMod = (PLDR_MODULE)CONTAINING_RECORD(pLdrMod->InLoadOrderLinks.Blink,
                LDR_MODULE,InLoadOrderLinks);
    printf("[I] InLoadOrderLinks Blink base=0x%08x name=%S  \n", pBMod->DllBase, pBMod->BaseDllName.Buffer);
    pBMod->InLoadOrderLinks.Flink = (PLIST_ENTRY)&pFMod->InLoadOrderLinks;
    pFMod->InLoadOrderLinks.Blink = (PLIST_ENTRY)&pBMod->InLoadOrderLinks;
    printf("[I] Success\n");

    //断开InMemoryOrderModuleList链
    pFMod = (PLDR_MODULE)CONTAINING_RECORD(pLdrMod->InMemoryOrderLinks.Flink,
                LDR_MODULE,InMemoryOrderLinks);
    printf("[I] InMemoryOrder Flink base=0x%08x name=%S  \n", pFMod->DllBase, pFMod->BaseDllName.Buffer);
    pBMod = (PLDR_MODULE)CONTAINING_RECORD(pLdrMod->InMemoryOrderLinks.Blink,
                LDR_MODULE,InMemoryOrderLinks);
    printf("[I] InMemoryOrder Blink base=0x%08x name=%S  \n", pBMod->DllBase, pBMod->BaseDllName.Buffer);
    pBMod->InMemoryOrderLinks.Flink = (PLIST_ENTRY)&pFMod->InMemoryOrderLinks;
    pFMod->InMemoryOrderLinks.Blink = (PLIST_ENTRY)&pBMod->InMemoryOrderLinks;
    printf("[I] Success\n");
/*
   //断开InInitializationOrderModuleList链
    pFMod = (PLDR_MODULE)pLdrMod->InInitializationOrderLinks.Flink;
    pBMod = (PLDR_MODULE)pLdrMod->InInitializationOrderLinks.Blink;
    pBMod->InInitializationOrderLinks.Flink = (PLIST_ENTRY)pFMod;
    pFMod->InInitializationOrderLinks.Blink = (PLIST_ENTRY)pBMod;
    */
    return 0;
}

int main(void)  
{  
    PPEB pPeb = NULL;  
    
    PLDR_MODULE pMod;
    HMODULE hMod;

    char buf[128];

    pPeb = GetPebBase();
   
    hMod = LoadLibrary("msg.dll");

    sprintf(buf, "msg.dll baseaddr = 0x%08x\n", hMod);

    ShowMsg(&buf[0]);
    
    DumpPeb(pPeb);
    
    pMod = FindLdrMod(pPeb, (DWORD)hMod);
    
    if (pMod == NULL) {
        printf("[E]: LDR Module (base=0x%08x) not found. \n", hMod);
        return -1;
    }
    printf("[I]: LDR Module: 0x%08x\n", pMod);
    printf("[I]: LDR Module:   base = 0x%08x  name=%S \n", pMod->DllBase, pMod->FullDllName.Buffer);
    BreakLdrLinks(pMod);

    printf("---------------\n");
    
    DumpPeb(pPeb);
    
    sprintf(buf, "msg.dll is hidden \n msg.dll baseaddr = 0x%08x\n", hMod);
    ShowMsg(&buf[0]);

    return 0;
} 