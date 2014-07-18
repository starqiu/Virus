#include <windows.h>

BYTE code[]={0x68,0xCC,0xDD,0xAA,0xBB
	,0xB8,0x7b,0x1d,0x80,0x7c
	,0xFF,0xD0
	,0xC3
};

int main(int argc, char *argv[])
{	

    int     PID         = 7536;
    int     TID         = 0;
	DWORD hproc,hthrd;
	int rstr,rcode,base_addr,old,numx;
	return 0;
}