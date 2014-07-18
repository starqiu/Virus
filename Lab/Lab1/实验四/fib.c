/* fib.c */
extern int add(int, int);

int fib(int n) 
{
    if (n == 0)
        return 0;
    else if (n == 1)
        return 1;
    else
        return add(fib(n-1), fib(n-2));  
}