#include <stdio.h>
#include <assert.h>

void assertionFailure()
{
	int x = 5;
	printf("Assertion Failure Now!\n");
	assert(x < 4);
}

int main(int argc, char *argv[])
{
	assertionFailure();
	return 0;
}
