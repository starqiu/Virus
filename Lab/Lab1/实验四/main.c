/* main.c */
#include <stdio.h>
#include <windows.h>
//extern int fib(int);
typedef int (*fib)(int);

int main(int argc, char **argv) 
{
	fib fib222;
	HINSTANCE hInstLibrary = LoadLibrary("fib.dll");
	if (hInstLibrary == NULL)
    {
         printf("载入dll失败\n");
         FreeLibrary(hInstLibrary); 
         system("pause");
         return 1;
    }
	 fib222 = (fib)GetProcAddress(hInstLibrary,"fib");
	 if (fib222 == NULL)
    {
         printf("载入dll失败\n");
         FreeLibrary(hInstLibrary); 
         system("pause");
         return 1;
    }
    printf("%d\n",fib222(7));
	return 0;
}
