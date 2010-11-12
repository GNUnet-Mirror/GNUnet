/**
 * @file seaspider/SeaspiderTest.c
 * @brief C file to test Seaspider's parsing
 */

/* include */
#include <stdio.h>


#define PRE_PROC_DIR 0
#define MACRO_fun(arg1, arg2) (arg1 + arg2)

struct MyStruct {
	int member;
	struct MyStruct *part;
};


enum  MyEnum{
	enumMember1,
	enumMember2,
	enumMember3
};


static int fun(int arg1, int arg2)
{
	return arg1 + arg2;
}


int main(int args, const char * argv[])
{
	/* variables declarations */
	struct MyStruct whole;
	struct MyStruct part;
	enum MyEnum myEnum;
	int i;
	int x, y;
	
	/* Allocations and assignments */
	whole.member = 1;
	whole.part = &part;
	whole.part->member = 2;
	myEnum = enumMember3;
	x = 0, y = 1;
	
	/* block */
	{
		/* arithmetic and logic operations */
		float f = 20.0;		
		whole.part->member = (int)(whole.part->member + 5) - 6; // cast - multilevel assignment
	}
	
	/* for loop */
	for (i = 0; i < 2; i++) {
		/* conditional expressions */
		if ( x > 0) {
			while (y < 5) {
				y++;
			}
		} else if (x > 0 || y == 4) {
			do {
				y--;
			} while (y != 1);
		}
		else {
			switch (myEnum) {
			case enumMember1:
				fun(enumMember1, enumMember2);
				break;
			case enumMember2:
				fun(enumMember1, enumMember2 ? enumMember2 : enumMember1); // ternary operator
				break;
			default:
				MACRO_fun(enumMember1, PRE_PROC_DIR); // preprocessing directive
				break;
			}
		}
	}
	
	return 1;
}
