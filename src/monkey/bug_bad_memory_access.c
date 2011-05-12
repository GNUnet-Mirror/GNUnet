#include <stdio.h>
#include <string.h>


void badMemoryAccess()
{
	int *p = (int*) 0x4252352;
	printf("Bad memory access now!\n");
	*p = 5;
}

int main(int argc, char *argv[])
{
	badMemoryAccess();
	return 0;
}
