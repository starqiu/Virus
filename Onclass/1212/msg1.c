#include <windows.h>

void ShowMsg(LPSTR s){
	MessageBoxA(NULL,s,"Msg",MB_OK);
	return;
}