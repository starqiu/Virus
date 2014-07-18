#include <windows.h>

int main()
{
    PNT_TIB pTib = NULL;
    
    __asm {
        mov eax, fs:[0x18]
        mov dword ptr [pTib], eax
    }
    
    printf("stack base: 0x%08x\n", pTib->StackBase);
    printf("teb base: 0x%08x\n", pTib->Self);
    return 0;
}