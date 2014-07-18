#include <stdio.h>
int fac(int n){
	if(n<0) return 0;
	else if (n==0||n==1) return 1;
	else return fac(n-1)+fac(n-2);
}
int main(){
	printf("%d\n",fac(5));
	return 0;
}