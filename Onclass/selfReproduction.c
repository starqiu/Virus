//self-reproduction program
int main(){
	char* a = "int main(){char* a=%c%s%c;int b='%c';printf(a,b,a,b,b);}";
	int b='"';
	printf(a,b,a,b,b);
}