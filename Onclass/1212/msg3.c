#include <windows.h>

#pragma comment(linker,"/EXPORT:_ShowMsg")
#pragma comment(lib,"user32.lib")

void ShowMsg(LPSTR s){
	MessageBoxA(NULL,s,"Msg",MB_OK);
	return;
}