#include <unistd.h>

int main() {
	setuid(0);
	setgid(0);
	system("ps");
}
