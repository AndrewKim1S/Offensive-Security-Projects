#include <stdio.h>
#include <stdlib.h>

int main() {
	printf("This program is to find the location of environment variables\n");

	const char* location = getenv("SHELL");
	if(location == NULL) {
		printf("Error with env var location\n");
		exit(-1);
	}

	printf("SHELL: %p\n", location); 

	return 0;
}
