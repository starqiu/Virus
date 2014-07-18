#include <windows.h>
#include <stdio.h>

#pragma comment(linker,"/export:_myprint")
#pragma comment(lib,"user32.lib")

int myprint(LPSTR s){
	int result = MessageBoxA(NULL,s,"Message",MB_OKCANCEL);
	if(result == IDCANCEL){
		return 0;
	}else if(result == IDOK){
		return 1;
	}else{
		return -1;
	}
}