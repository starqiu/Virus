/* 给Pe文件新增节    

/*	添加新节算法描述:
	1.建立文件映射
	2.移动到最后一个节表
	3.添加新节节表
	4.设置新节的VirtualAddress,VirtualSize,SizeOfRawData,PointerToRawData,Characteristics等属性
	5.将新节的内容写入文件
	6.增加NumberOfSections属性
	7.设置SizeOfImage,AddressOfEntryPoint属性
	8.将内存映射回文件
*/

#include <windows.h>
#include <stdio.h>
#define MAX_SECTION_NUM   16
#define MAX_IMPDESC_NUM   64

HANDLE  hHeap;
PIMAGE_DOS_HEADER	pDosHeader;
PCHAR   pDosStub;
DWORD   dwDosStubSize;
DWORD   dwDosStubOffset;
PIMAGE_NT_HEADERS           pNtHeaders;
PIMAGE_FILE_HEADER          pFileHeader;
PIMAGE_OPTIONAL_HEADER32    pOptHeader;
PIMAGE_SECTION_HEADER   pSecHeaders;
PIMAGE_SECTION_HEADER   pSecHeader[MAX_SECTION_NUM];
WORD  wSecNum;
PBYTE pSecData[MAX_SECTION_NUM];
DWORD dwSecSize[MAX_SECTION_NUM];
DWORD dwFileSize;
WORD  wInjSecNo;
DWORD dwSizeOfCode;
PBYTE pCode;

void _addr_orign_aoep();

__declspec(naked) void code_start()
{
    __asm 
    {
        pushad
        push    ebp
        mov     ebp, esp
// ebp-0x04 ====> hmodkern32
// ebp-0x08 ====> dwAddrOfGetProcAddress
// ebp-0x0C ====> dwAddrOfLoadLibraryA
// ebp-0x10 ====> hmoduser32
// ebp-0x14 ====> dwAddrOfMessageBoxA
// ebp-0x18 ====> dwAddrOfGetModuleHandleA
        sub     esp, 0x20
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

// dwAddrOfMessageBoxA = GetProcAddress(hmoduser32, "MessageBoxA");
        lea     ecx, [ebx + _str_mba]
        push    ecx
        push    dword ptr [ebp-0x10]
        call    dword ptr [ebp-0x08]
        mov     [ebp-0x14], eax

// MessageBoxA(0, "Hello", "", 0);
        push    0
        lea     ecx, [ebx + _str_emp]
        push    ecx
        lea     ecx, [ebx + _str_hello]
        push    ecx
        push    0
        call    dword ptr [ebp-0x14]

// dwAddrOfGetModuleHandleA = GetProcAddress(hmodkern32, "GetModuleHandleA")
        lea     ecx, [ebx + _str_gmha]
        push    ecx
        push    [ebp - 0x04]
        call    dword ptr [ebp - 0x08]
        mov     [ebp - 0x18], eax

// GetModuleHandleA(0);
        push    0
        call    dword ptr [ebp - 0x18]

        mov     esp, ebp
        pop     ebp

        add     eax,dword ptr [ebx + _addr_orign_aoep]
        mov     dword ptr [esp + 0x1C], eax     // save (dwBaseAddress + orign) to eax-location-of-context
        popad                                   // load registers context from stack
        push    eax
        xor     eax, eax
        retn                                    // >> jump to the Original AOEP
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
_str_mba:
		_emit   'M'
        _emit   'e'
        _emit   's'
        _emit   's'
        _emit   'a'
        _emit   'g'
        _emit   'e'
        _emit   'B'
        _emit   'o'
        _emit   'x'
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
_str_hello:
        _emit   'I'
        _emit   '\''
        _emit   'm'
        _emit   ' '
        _emit   'h'
        _emit   'a'
        _emit   'c'
        _emit   'k'
        _emit   'e'
        _emit   'd'
        _emit   '!'
_str_emp:
        _emit   0x0
  }
}

__declspec(naked) void _addr_orign_aoep()
{
    __asm {
        _emit   0xba
        _emit   0x11
        _emit   0x00
        _emit   0x00
    }
}

__declspec(naked) void code_end()
{
    __asm _emit 0xCC
}


static DWORD PEAlign(DWORD dwTarNum,DWORD dwAlignTo)
{	
    return (((dwTarNum+dwAlignTo - 1) / dwAlignTo) * dwAlignTo);
}

static DWORD RVA2Ptr(DWORD dwBaseAddress, DWORD dwRva)
{
    if ((dwBaseAddress != 0) && dwRva)
        return (dwBaseAddress + dwRva);
    else
        return dwRva;
}

//----------------------------------------------------------------
static PIMAGE_SECTION_HEADER RVA2Section(DWORD dwRVA)
{
    int i;
    for(i = 0; i < wSecNum; i++) {
        if ( (dwRVA >= pSecHeader[i]->VirtualAddress)
            && (dwRVA <= (pSecHeader[i]->VirtualAddress 
                + pSecHeader[i]->SizeOfRawData)) ) {
            return ((PIMAGE_SECTION_HEADER)pSecHeader[i]);
        }
    }
    return NULL;
}

//----------------------------------------------------------------
static PIMAGE_SECTION_HEADER Offset2Section(DWORD dwOffset)
{
    int i;
    for(i = 0; i < wSecNum; i++) {
        if( (dwOffset>=pSecHeader[i]->PointerToRawData) 
            && (dwOffset<(pSecHeader[i]->PointerToRawData + pSecHeader[i]->SizeOfRawData)))
        {
            return ((PIMAGE_SECTION_HEADER)pSecHeader[i]);
        }
    }
    return NULL;
}

//================================================================
static DWORD RVA2Offset(DWORD dwRVA)
{
    PIMAGE_SECTION_HEADER pSec;
    pSec = RVA2Section(dwRVA);//ImageRvaToSection(pimage_nt_headers,Base,dwRVA);
    if(pSec == NULL) {
        return 0;
    }
    return (dwRVA + (pSec->PointerToRawData) - (pSec->VirtualAddress));
}
//----------------------------------------------------------------
static DWORD Offset2RVA(DWORD dwOffset)
{
    PIMAGE_SECTION_HEADER pSec;
    pSec = Offset2Section(dwOffset);
    if(pSec == NULL) {
        return (0);
    }
    return(dwOffset + (pSec->VirtualAddress) - (pSec->PointerToRawData));
}

BOOL CopyPEFileToMem(LPCSTR lpszFilename)
{
    HANDLE  hFile;

    PBYTE   pMem;
    DWORD   dwBytesRead;
    int     i;

    DWORD   dwSecOff;

    PIMAGE_NT_HEADERS       pMemNtHeaders;   
    PIMAGE_SECTION_HEADER   pMemSecHeaders;

    hFile = CreateFile(lpszFilename, GENERIC_READ,
                FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[E]: Open file (%s) failed.\n", lpszFilename);
        return FALSE;
    }
    dwFileSize = GetFileSize(hFile, 0);
    printf("[I]: Open file (%s) ok, with size of 0x%08x.\n", lpszFilename, dwFileSize);
    if (hHeap == NULL) { 
        printf("[I]: Get the default heap of the process. \n");
        hHeap = GetProcessHeap();
    }
    if (hHeap == NULL) {
        printf("[E]: Get the default heap failed.\n");
        return FALSE;
    }

    pMem = (PBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwFileSize);

    if(pMem == NULL) {
        printf("[E]: HeapAlloc failed (with the size of 0x%08x).\n", dwFileSize);
        CloseHandle(hFile);
        return FALSE;
    }
  
    ReadFile(hFile, pMem, dwFileSize, &dwBytesRead, NULL);
    
    CloseHandle(hFile);

    // Copy DOS Header 
    pDosHeader = (PIMAGE_DOS_HEADER)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(IMAGE_DOS_HEADER));

    if(pDosHeader == NULL) {
        printf("[E]: HeapAlloc failed for DOS_HEADER\n");
        CloseHandle(hFile);
        return FALSE;
    }

    CopyMemory(pDosHeader, pMem, sizeof(IMAGE_DOS_HEADER));

    // Copy DOS Stub Code 
    dwDosStubSize = pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    dwDosStubOffset = sizeof(IMAGE_DOS_HEADER);
    pDosStub = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwDosStubSize);
    if ((dwDosStubSize & 0x80000000) == 0x00000000)
    {
        CopyMemory(pDosStub, (const void *)(pMem + dwDosStubOffset), dwDosStubSize);
    }

    // Copy NT HEADERS 
    pMemNtHeaders = (PIMAGE_NT_HEADERS)(pMem + pDosHeader->e_lfanew);
    
    pNtHeaders = (PIMAGE_NT_HEADERS)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(IMAGE_NT_HEADERS));

    if(pNtHeaders == NULL) {
        printf("[E]: HeapAlloc failed for NT_HEADERS\n");
        CloseHandle(hFile);
        return FALSE;
    }

    CopyMemory(pNtHeaders, pMemNtHeaders, sizeof(IMAGE_NT_HEADERS));

    pOptHeader = &(pNtHeaders->OptionalHeader);
    pFileHeader = &(pNtHeaders->FileHeader);

    // Copy SectionTable
    pMemSecHeaders = (PIMAGE_SECTION_HEADER) ((DWORD)pMemNtHeaders + sizeof(IMAGE_NT_HEADERS));
    wSecNum = pFileHeader->NumberOfSections;

    pSecHeaders = (PIMAGE_SECTION_HEADER)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, wSecNum * sizeof(IMAGE_SECTION_HEADER));

    if(pSecHeaders == NULL) {
        printf("[E]: HeapAlloc failed for SEC_HEADERS\n");
        CloseHandle(hFile);
        return FALSE;
    }

    CopyMemory(pSecHeaders, pMemSecHeaders, wSecNum * sizeof(IMAGE_SECTION_HEADER));

    for(i = 0; i < wSecNum; i++) {
        pSecHeader[i] = (PIMAGE_SECTION_HEADER) 
          ((DWORD)pSecHeaders + i * sizeof(IMAGE_SECTION_HEADER));
    }

    // Copy Section
    for(i = 0; i < wSecNum; i++) {
        dwSecOff = (DWORD)(pMem + pSecHeader[i]->PointerToRawData);
        
        dwSecSize[i] = PEAlign(pSecHeader[i]->SizeOfRawData, pOptHeader->FileAlignment);
        
        pSecData[i] = (PBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSecSize[i]);

        if (pSecData[i] == NULL) {
            printf("[E]: HeapAlloc failed for the section of %d\n", i);
            CloseHandle(hFile);
            return FALSE;
        }

        CopyMemory(pSecData[i], (PVOID)dwSecOff, dwSecSize[i]);
    }

    HeapFree(hHeap, 0, pMem);
    printf("[I]: Load PE from file (%s) ok\n", lpszFilename);

    return TRUE;
}

void DumpPEInMem()
{
    // 请在这里填入你的代码
	int i;
	
	//dump header
    printf("ImageBase: 0x%08x\n", pOptHeader->ImageBase);
    printf("AddressOfEntryPoint: 0x%08x\n", pOptHeader->AddressOfEntryPoint);
    printf("SizeOfImage: 0x%08x\n", pOptHeader->SizeOfImage);
	printf("NumberOfSections: 0x%08x\n", wSecNum);
	
	//dump section 	
	for(i=0; i<wSecNum; i++)
	{
		printf("Section Header[%d]: \n", i);
		printf("  Name: %c%c%c%c%c%c%c%c\n", pSecHeader[i]->Name[0]
			,pSecHeader[i]->Name[1],pSecHeader[i]->Name[2],pSecHeader[i]->Name[3]
			,pSecHeader[i]->Name[4],pSecHeader[i]->Name[5],pSecHeader[i]->Name[6]
			,pSecHeader[i]->Name[7]);
		printf("  VirtualSize: 0x%08x\n", pSecHeader[i]->Misc.VirtualSize);
		printf("  VirtualAddress: 0x%08x\n", pSecHeader[i]->VirtualAddress);
		printf("  SizeOfRawData: 0x%08x\n", pSecHeader[i]->SizeOfRawData);
		printf("  RawData Offset: 0x%08x\n", pSecHeader[i]->PointerToRawData);
		printf("  Characteristics: 0x%08x\n", pSecHeader[i]->Characteristics);
	}
		
    return;
}

//文件的PE结构增加一个新的节
BOOL AddNewSection()
{
    DWORD roffset,rsize,voffset,vsize;
    DWORD dwOffsetOfcode;
    PIMAGE_SECTION_HEADER pInjSecHeader;
    int   i;
	int   op;
	//DWORD aoep;
	
	__asm {
        mov edx, offset code_start
        mov dword ptr [pCode], edx
        mov eax, offset code_end
        sub eax, edx
        mov dword ptr [dwSizeOfCode], eax
    }
	
	//aoep = pOptHeader->AddressOfEntryPoint + pOptHeader->ImageBase;
	//printf("[I] AOEP:0x%08x\n",aoep);
	printf("[I] pCode:0x%08x\n",pCode);
	printf("[I] _addr_orign_aoep:0x%08x\n",_addr_orign_aoep);
	if(VirtualProtect(pCode, dwSizeOfCode, PAGE_EXECUTE_READWRITE, &op)){
		printf("[I] VirtualProtect succeed\n");
	}else{
		printf("[E] VirtualProtect fail\n");
	}
	
	printf("[I] dwSizeOfCode:0x%08x\n",dwSizeOfCode);
    wInjSecNo = wSecNum;

    if (wInjSecNo >= 64) {
        printf("[E]: Too many sections, wInjSecNo(%d) >= 63\n", wInjSecNo);
        return FALSE;
    }

    pInjSecHeader = (PIMAGE_SECTION_HEADER)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(IMAGE_SECTION_HEADER));
    if(pInjSecHeader == NULL) {
        printf("[E]: HeapAlloc failed for NEW_SEC_HEADER\n");
        return FALSE;
    }
    pSecHeader[wInjSecNo] = pInjSecHeader;

    // 请填入代码
    // rsize = 新的节的尺寸，按照FileAlignment对齐;	
    rsize = PEAlign(dwSizeOfCode, pOptHeader->FileAlignment);	

    // 请填入代码
    // vsize = 新的节的尺寸，按照SectionAlignment对齐;
	vsize = PEAlign(dwSizeOfCode, pOptHeader->SectionAlignment);

    roffset = PEAlign(pSecHeader[wInjSecNo-1]->PointerToRawData + pSecHeader[wInjSecNo-1]->SizeOfRawData,
            pOptHeader->FileAlignment);

    voffset = PEAlign(pSecHeader[wInjSecNo-1]->VirtualAddress + pSecHeader[wInjSecNo-1]->Misc.VirtualSize,
           pOptHeader->SectionAlignment);

	pOptHeader->AddressOfEntryPoint=voffset;//修改aoep为新section
    pSecHeader[wInjSecNo]->PointerToRawData     = roffset;
    pSecHeader[wInjSecNo]->VirtualAddress       = voffset;
    pSecHeader[wInjSecNo]->SizeOfRawData        = rsize;
    pSecHeader[wInjSecNo]->Misc.VirtualSize     = vsize;
    pSecHeader[wInjSecNo]->Characteristics      = 0x60000020;
    pSecHeader[wInjSecNo]->Name[0] = '.';
    pSecHeader[wInjSecNo]->Name[1] = 'm';
    pSecHeader[wInjSecNo]->Name[2] = 'y';
    pSecHeader[wInjSecNo]->Name[3] = 'c';
    pSecHeader[wInjSecNo]->Name[4] = 'o';
    pSecHeader[wInjSecNo]->Name[5] = 'd';
    pSecHeader[wInjSecNo]->Name[6] = 'e';
    pSecHeader[wInjSecNo]->Name[7] = '.';
    
    pSecData[wInjSecNo] = (PBYTE)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, rsize);
    dwSecSize[wInjSecNo] = pSecHeader[wInjSecNo]->SizeOfRawData;
    CopyMemory(pSecData[wInjSecNo], pCode, dwSizeOfCode);
    wSecNum++;
    pFileHeader->NumberOfSections = wSecNum;
    for(i = 0;i< wSecNum; i++) {
        pSecHeader[i]->VirtualAddress =
            PEAlign(pSecHeader[i]->VirtualAddress, pOptHeader->SectionAlignment);
        pSecHeader[i]->Misc.VirtualSize =
            PEAlign(pSecHeader[i]->Misc.VirtualSize, pOptHeader->SectionAlignment);
        
        pSecHeader[i]->PointerToRawData =
            PEAlign(pSecHeader[i]->PointerToRawData, pOptHeader->FileAlignment);
        
        pSecHeader[i]->SizeOfRawData = 
            PEAlign(pSecHeader[i]->SizeOfRawData, pOptHeader->FileAlignment);
    }
    pOptHeader->SizeOfImage = pSecHeader[wSecNum-1]->VirtualAddress + pSecHeader[wSecNum-1]->Misc.VirtualSize;
    dwFileSize = pSecHeader[wSecNum-1]->PointerToRawData + pSecHeader[wSecNum - 1]->SizeOfRawData;
    pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
    return TRUE;

}

//保存PE结构到PE文件的函数
BOOL SaveMemToPEFile(LPCSTR lpszFileName)
{
    DWORD   dwBytesWritten = 0;
    PBYTE   pMem = NULL;
    PBYTE   pMemSecHeaders;
    HANDLE  hFile;
    int i;

    //----------------------------------------
    pMem = (PBYTE) HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwFileSize);
    if(pMem == NULL) {
        return FALSE;
    }
    //----------------------------------------
    CopyMemory(pMem, pDosHeader, sizeof(IMAGE_DOS_HEADER));
    if((dwDosStubSize & 0x80000000) == 0x00000000) {
        CopyMemory(pMem + dwDosStubOffset, pDosStub, dwDosStubSize);
    }
    CopyMemory(pMem + pDosHeader->e_lfanew,
        pNtHeaders,
        sizeof(IMAGE_NT_HEADERS));

    pMemSecHeaders = pMem + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);

    //----------------------------------------
    for (i = 0; i < wSecNum; i++) {
        CopyMemory(pMemSecHeaders + i * sizeof(IMAGE_SECTION_HEADER),
        pSecHeader[i], sizeof(IMAGE_SECTION_HEADER));
    }

    for (i = 0; i < wSecNum; i++) {
        CopyMemory(pMem + pSecHeader[i]->PointerToRawData,
        pSecData[i],
        pSecHeader[i]->SizeOfRawData);
    }
    
    printf("[I]: The pieces of PE have been rearranged. \n");

    hFile = CreateFile(lpszFileName,
            GENERIC_WRITE,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        printf("[E]: Create file (%s) failed\n", lpszFileName);
        return FALSE;
    }
    printf("[I]: Create file (%s) ok\n", lpszFileName);
  

    // ----- WRITE FILE MEMORY TO DISK -----
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    WriteFile(hFile, pMem, dwFileSize, &dwBytesWritten, NULL);

    // ------ FORCE CALCULATED FILE SIZE ------
    SetFilePointer(hFile, dwFileSize, NULL, FILE_BEGIN);
    SetEndOfFile(hFile);
    CloseHandle(hFile);
    //----------------------------------------

    HeapFree(hHeap, 0, pMem);
    
    printf("[I]: Save PE to file (%s) ok\n", lpszFileName);
    return TRUE;
}


int main()
{
    LPCSTR lpszFileName = "hello.exe";
    LPCSTR lpszInjFileName = "hello_inj.exe";

    if (! CopyPEFileToMem(lpszFileName)) {
        return -1;
    }
	DumpPEInMem();
	if(AddNewSection()){
		printf("[I] Add new section success!\n");
		SaveMemToPEFile(lpszInjFileName);
	}else{
		printf("[E] Add new section failed!\n");
	} 
	DumpPEInMem();
    return 0;
}
