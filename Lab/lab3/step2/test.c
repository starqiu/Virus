#include <windows.h>

char* hack ="I'm hacked!";
DWORD addrOfMBA;
__declspec(naked) MyMessageBoxA(HWND hwnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType)
{
     //请在这里补全代码
	 //MessageBoxA(hwnd,hack,lpCaption,uType);
	 __asm{
		push ebp
		mov ebp,esp
		push dword ptr[ebp+0x14]
		push dword ptr[ebp+0x10]
		push dword ptr[hack]
		push dword ptr[ebp+0x08]
		mov eax ,dword ptr[addrOfMBA]
		call eax
		mov esp,ebp
		pop ebp
		ret 16
	 }
}
	 
void main()
{
    //请在这里补全代码  
	PIMAGE_THUNK_DATA pthunkOfMBA;
	DWORD dwBase;
	int op;
	LPCSTR lpszFuncName ="MessageBoxA";
     //定位MessageBoxA的导入地址表表项
	dwBase = (DWORD)GetModuleHandleA(NULL);
	pthunkOfMBA = (PIMAGE_THUNK_DATA)GetIAFromImportTable(dwBase,lpszFuncName);
     //修改导入地址表表项
	//printf("0x%08x => 0x%08x\n",pthunkOfMBA,pthunkOfMBA->u1.Function);
	addrOfMBA=pthunkOfMBA->u1.Function;
	//printf("addrOfMBA=> 0x%08x\n",addrOfMBA);
    VirtualProtect(pthunkOfMBA, sizeof(pthunkOfMBA), PAGE_EXECUTE_READWRITE, &op);
	pthunkOfMBA->u1.Function= MyMessageBoxA;
	//printf("MyMessageBoxA=> 0x%08x\n",pthunkOfMBA->u1.Function);
	//printf("0x%08x => 0x%08x\n",pthunkOfMBA,pthunkOfMBA->u1.Function);
    MessageBoxA(NULL, "Happyday", "hello", MB_OK);
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
      // 请在这里补全代码	  
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
