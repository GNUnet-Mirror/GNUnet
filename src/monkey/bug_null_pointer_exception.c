#include <stdio.h>
#include <string.h>


struct CrashStruct {
	const char *crashValue;
};

void crashFunction() 
{
	struct CrashStruct *crashStruct;
	crashStruct = NULL;
	printf("Now the program will crash!\n");
	crashStruct->crashValue = "hello!";
}

int main(int argc, char *argv[]) 
{
	crashFunction();
	return 0;
}
