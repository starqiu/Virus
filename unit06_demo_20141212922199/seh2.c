//
//  c:\> cl /c seh.c
//  c:\> link /safeseh:no seh.obj 
//
#include <windows.h>
#include <stdio.h>

DWORD  scratch;

EXCEPTION_DISPOSITION __cdecl exception_handler(
    struct _EXCEPTION_RECORD *ExceptionRecord,
    void * EstablisherFrame,
    struct _CONTEXT *ContextRecord,
    void * DispatcherContext)
{
    unsigned i;

    printf( "Hello from an exception handler\n" );

    ContextRecord->Eax = (DWORD)&scratch;

    return ExceptionContinueExecution;
}

int main()
{
    DWORD handler = (DWORD)exception_handler;

    __asm
    {                           
       // Build EXCEPTION_REGISTRATION record:
        push    exception_handler 
        push    FS:[0]          // Address of previous handler
        mov     FS:[0],ESP      // Install new EXECEPTION_REGISTRATION
    }

    __asm
    {
        mov     eax,0           // Zero out EAX
        mov     [eax], 1        // Write to EAX to deliberately cause a fault
    }

    printf( "After writing!\n" );

    __asm
    {                           // Remove our EXECEPTION_REGISTRATION record
        mov     eax,[ESP]       // Get pointer to previous record
        mov     FS:[0], EAX     // Install previous record
        add     esp, 8          // Clean our EXECEPTION_REGISTRATION off stack
    }

    return 0;
}