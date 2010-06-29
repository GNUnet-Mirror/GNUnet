#include <stdio.h>
#include <string.h>

void crashFunction() 
{
	//char *stringCannotBeChanged = "String cannot be changed!";
	char *nullString = NULL;
	
	printf("Now the program will crash! Take a cover! \n");
	//*stringCannotBeChanged = 'h';
	printf("Nonsense!\n");
	if (strcmp(nullString, "A string to compare with") == 0) {
		printf("How come?! It had to be crashed!\n");
	}
}

int main(int argc, char *argv[]) 
{
	int i = 0;
	printf("arguments: %d\n", argc);
	for (i=0; i<argc; i++)
		printf("%d: %s\n", i, argv[i]);
	printf("Press ENTER\n");
	getchar();
	crashFunction();
	return 0;
}
