#pragma comment(linker,"/EXPORT:_ShowMsg")
#pragma comment(lib,"user32.lib")

int __stdcall MessageBoxA(
	int hwnd,
	char* lpText,
	char* lpCap,
	int uType
);

void ShowMsg(char* s){
	MessageBoxA(0x0,s,"Msg",0x0);
	return;
}