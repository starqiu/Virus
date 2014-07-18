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

int main()
{
    LPCSTR lpszFileName = "hello.exe";
    LPCSTR lpszInjFileName = "hello_inj.exe";

    if (! CopyPEFileToMem(lpszFileName)) {
        return -1;
    }
	DumpPEInMem();
    return 0;
}
