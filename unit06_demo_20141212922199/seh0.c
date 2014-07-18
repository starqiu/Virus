//
//  c:\> cl /c seh.c
//  c:\> link seh.obj 
//
#include <windows.h>
#include <stdio.h>

int main()
{    
    printf( "Before the breakpoint!\n" );

    __asm
    {
        _emit 0xCC
    }

    printf( "After the breakpoint!\n" );

    return 0;
}