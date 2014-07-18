#include <windows.h>

#pragma comment(linker, "/EXPORT:_ShowMsg")
#pragma comment(lib, "user32.lib")

void ShowMsg(char* s)
{
   MessageBoxA(0x0, s, "Msg", 0x0);
   return;
}
