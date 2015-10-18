int foo(void)
{
    return 2;
}

int bar(void)
{
    printf("Hello\n");
}

int main(void)
{
    bar();
    return foo() - 2;
}
