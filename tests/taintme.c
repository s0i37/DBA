#include <stdio.h>

void use(char *taint_me)
{
	char a;
	a = taint_me[4];
}

void fill(char *buf)
{
	buf[0] = 't';
	buf[1] = 'e';
	buf[2] = 's';
	buf[3] = 't';
	buf[4] = 't';
	buf[5] = 'e';
	buf[6] = 's';
	buf[7] = 't';
}

char buf[] = "01234567";

void main(void)
{
	fill(buf);
	use(buf);
	printf("%s\n", buf);
}