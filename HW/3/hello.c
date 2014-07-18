#include <windows.h>

int myprint(char *s);

char *s = "Hello world!";
char buf[100];

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    int pid = 0;
    pid = GetCurrentProcessId();
	sprintf(buf, "base=0x%08x\npid=%d\n%s", hInstance, pid, s);
    while (myprint(buf)){
		sprintf(buf, "base=0x%08x\npid=%d\n%s", hInstance, pid, s);
	}
    return 0;
}
