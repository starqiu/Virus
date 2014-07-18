#include <windows.h>


	BOOL CompStr(LPSTR s1, LPSTR s2)
    { 
    PCHAR p, q;
       for (p = s1, q = s2; (*p != 0) && (*q != 0); p++, q++) {
           if (*p != *q) return FALSE;
       }
    return TRUE;
    }

    DWORD GetIAFromImportTable(DWORD dwBase, LPCSTR lpszFuncName)
    {
	int i;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADER32 pOptHeader;
    DWORD dwRVAImpTbl;
    DWORD dwSizeOfImpTbl;
    PIMAGE_IMPORT_DESCRIPTOR pImpTbl, p;

	PIMAGE_IMPORT_BY_NAME pOrdinalName;
    PIMAGE_THUNK_DATA pthunk, pthunk2;

    DWORD dwIA = 0;
    pDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    pNtHeaders = (PIMAGE_NT_HEADERS)(dwBase + pDosHeader->e_lfanew);
    pOptHeader = &(pNtHeaders->OptionalHeader);
    dwRVAImpTbl = pOptHeader->DataDirectory[1].VirtualAddress;
    dwSizeOfImpTbl = pOptHeader->DataDirectory[1].Size;
    pImpTbl = (PIMAGE_IMPORT_DESCRIPTOR)(dwBase + dwRVAImpTbl);

	printf("The original Name : %s\n", dwBase + pImpTbl->Name);

	printf("Import Desc Address: 0x%08x\n", pImpTbl);


	
	
	

	p = pImpTbl;
	printf("the current Name : %s\n", dwBase + p->Name);

	pthunk = (PIMAGE_THUNK_DATA) (dwBase + p->OriginalFirstThunk);
	 pthunk2 = (PIMAGE_THUNK_DATA) (dwBase + p->FirstThunk);

	 

	   for (i = 0; pthunk->u1.Function != 0; pthunk++, pthunk2++, i++) {
        if (pthunk->u1.Ordinal & 0x80000000) continue;
        pOrdinalName = (PIMAGE_IMPORT_BY_NAME)
                          (dwBase + pthunk->u1.AddressOfData);

        if (CompStr((LPSTR)lpszFuncName, (LPSTR)&pOrdinalName->Name))
            return (DWORD)pthunk2;
        }

		return 0;
	  

    }

	

    

int main(int argc, char *argv[])
{   
	
    DWORD dwBase , finalAddr;

	 dwBase = (DWORD)GetModuleHandleA("buzhou1.exe");
	 printf("Base Address: 0x%08x\n", dwBase);
    
	 finalAddr =  GetIAFromImportTable(dwBase  , "MessageBoxA");
 	 printf("=====================================\n");
     printf("Import Desc Address: 0x%08x\n", finalAddr);

     MessageBoxA(NULL, "hello", "msg", MB_OK);
    return 0;
}