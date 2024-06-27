#include <stdio.h>
#include <stdint.h>

typedef struct {
  unsigned char e_ident[16];     // 16 bytes
	uint16_t e_type;               // 2 bytes 
	uint16_t e_machine;            // 2 bytes
	uint32_t e_version;            // 4 bytes 
	uint64_t e_entry;              // 8 bytes 
	uint64_t e_phoff;              // 8 bytes 
	uint64_t e_shoff;              // 8 bytes 
	uint32_t e_flags;              // 4 bytes 
	uint16_t e_ehsize;             // 2 bytes 
	uint16_t e_phentsize;          // 2 bytes 
	uint16_t e_phnum;              // 2 bytes 
	uint16_t e_shentsize;          // 2 bytes 
	uint16_t e_shnum;              // 2 bytes 
	uint16_t e_shstrndx;           // 2 bytes 
} ELF_ExecHdr;


int main() {
	ELF_ExecHdr test;

	printf("Size of ELF Executable Header is: %d\n", sizeof(ELF_ExecHdr));
	printf("Size of ELF Executable Header struct is: %d\n", sizeof(test));
	return 0;
}
