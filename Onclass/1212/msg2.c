#include <windows.h>

__declspec(DLLEXPORT)
void ShowMsg(LPSTR s){
	MessageBoxA(NULL,s,"Msg",MB_OK);
	return;
}