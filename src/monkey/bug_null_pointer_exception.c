#include <stdio.h>
#include <string.h>

void crashFunction() 
{
	char *nullString = NULL;
	printf("Now the program will crash!\n");
	if (strcmp(nullString, "A string to compare with") == 0) {
		printf("How come?! It had to crash!\n");
	}
}

int main(int argc, char *argv[]) 
{
	crashFunction();
	return 0;
}
