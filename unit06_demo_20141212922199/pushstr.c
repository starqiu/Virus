#include <stdio.h>

int main()
{
  __asm 
  {
     call _func
     _emit 'h'
     _emit 'o'
     _emit 0x0
_func:
     call printf
     add esp, 0x4
  }

}