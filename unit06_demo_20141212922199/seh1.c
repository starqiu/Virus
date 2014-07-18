//
//  c:\> cl /c seh.c
//  c:\> link /safeseh:no seh.obj 
//
#include <windows.h>
#include <stdio.h>

DWORD  scratch;


typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *prev;
    PEXCEPTION_ROUTINE handler;
} EXCEPTION_REGISTRATION_RECORD, 
    *PEXCEPTION_REGISTRATION_RECORD;


EXCEPTION_DISPOSITION __cdecl exception_handler(
    struct _EXCEPTION_RECORD *ExceptionRecord,
    void * EstablisherFrame,
    struct _CONTEXT *ContextRecord,
    void * DispatcherContext)
{
    printf( "Hello from an exception handler!\n" );

    ContextRecord->Eip++;

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
    
    printf( "Before the breakpoint!\n" );

    __asm
    {
        _emit 0xCC
    }

    printf( "After the breakpoint!\n" );

    __asm
    {                           // Remove our EXECEPTION_REGISTRATION record
        mov     eax,[ESP]       // Get pointer to previous record
        mov     FS:[0], EAX     // Install previous record
        add     esp, 8          // Clean our EXECEPTION_REGISTRATION off stack
    }

    return 0;
}