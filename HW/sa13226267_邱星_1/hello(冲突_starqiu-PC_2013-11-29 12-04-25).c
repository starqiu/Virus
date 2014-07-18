int main (int argc, char *argv[])
{
    char* hello="hello\n";
	my_print(hello);
	printf("hello's addr is :%p\n",&hello);
	printf("main's addr is :%p\n",&main);
	printf("my_print's addr is :%p\n",&my_print);
	printf("printf's addr is :%p\n",&printf);
    return 0;
}