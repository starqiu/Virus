#include <windows.h>

typedef struct _CLIENT_ID
{
     PVOID UniqueProcess;
     PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

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

typedef struct _TEB
{                // Size: 0xF88
/*000*/      NT_TIB NtTib;
/*01C*/      VOID *EnvironmentPointer;
/*020*/      DWORD dwProcessId;            
/*024*/      DWORD dwThreadId;             
/*028*/      HANDLE ActiveRpcHandle;
/*02C*/      VOID *ThreadLocalStoragePointer;
/*030*/      PPEB ProcessEnvironmentBlock;             // PEB
/*034*/      ULONG LastErrorValue;
/*038*/      ULONG CountOfOwnedCriticalSections;
/*03C*/      ULONG CsrClientThread;
/*040*/      ULONG Win32ThreadInfo;
/*044*/      UCHAR Win32ClientInfo[0x7C];
/*0C0*/      ULONG WOW32Reserved;
/*0C4*/      ULONG CurrentLocale;
/*0C8*/      ULONG FpSoftwareStatusRegister;
/*0CC*/      UCHAR SystemReserved1[0xD8];                // ExitStack ???
/*1A4*/      ULONG Spare1;
/*1A8*/      ULONG ExceptionCode;
/*1AC*/      UCHAR SpareBytes1[0x28];
/*1D4*/      UCHAR SystemReserved2[0x28];
/*1FC*/      UCHAR GdiTebBatch[0x4E0];
/*6DC*/      ULONG gdiRgn;
/*6E0*/      ULONG gdiPen;
/*6E4*/      ULONG gdiBrush;
/*6E8*/      CLIENT_ID RealClientId;
/*6F0*/      ULONG GdiCachedProcessHandle;
/*6F4*/      ULONG GdiClientPID;
/*6F8*/      ULONG GdiClientTID;
/*6FC*/      ULONG GdiThreadLocalInfo;
/*700*/      UCHAR UserReserved[0x14];
/*714*/      UCHAR glDispatchTable[0x460];
/*B74*/      UCHAR glReserved1[0x68];
/*BDC*/      ULONG glReserved2;
/*BE0*/      ULONG glSectionInfo;
/*BE4*/      ULONG glSection;
/*BE8*/      ULONG glTable;
/*BEC*/      ULONG glCurrentRC;
/*BF0*/      ULONG glContext;
/*BF4*/    ULONG LastStatusValue;
/*BF8*/    LARGE_INTEGER StaticUnicodeString;
/*C00*/    UCHAR StaticUnicodeBuffer[0x20C];
/*E0C*/    ULONG DeallocationStack;
/*E10*/    UCHAR TlsSlots[0x100];
/*F10*/    LARGE_INTEGER TlsLinks;
/*F18*/    ULONG Vdm;
/*F1C*/    ULONG ReservedForNtRpc;
/*F20*/    LARGE_INTEGER DbgSsReserved;
/*F28*/    ULONG HardErrorsAreDisabled;
/*F2C*/    UCHAR Instrumentation[0x40];
/*F6C*/    ULONG WinSockData;
/*F70*/    ULONG GdiBatchCount;
/*F74*/    ULONG Spare2;
/*F78*/    ULONG Spare3;
/*F7C*/    ULONG Spare4;
/*F80*/    ULONG ReservedForOle;
/*F84*/    ULONG WaitingOnLoaderLock;
} TEB, *PTEB;


int main()
{
    PPEB pPeb = NULL;
    
    __asm {
        mov ecx, fs:[0x30]
        mov dword ptr[pPeb], ecx
    }
    
    printf("peb base: 0x%08x\n", pPeb);
    printf("ImageBaseAddress: 0x%08x\n", pPeb->ImageBaseAddress);
    
    return 0;
}