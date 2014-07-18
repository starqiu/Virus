#include <stdio.h>

extern int sum(int);

int main(int argc, char **argv) 
{
  int i;
  char* format = "sum(%d)=%d\n";
  if (argc < 2) {
    printf("usage: main number\n");
    return -1;
  }
  i = atoi(argv[1]);
    __asm {
        // 计算并输出sum(i)的值
		push dword ptr[i]
		call sum
		add esp,4
		push eax
		push dword ptr[i]
		push dword ptr[format]
		call printf
		add esp,12
    }
}
