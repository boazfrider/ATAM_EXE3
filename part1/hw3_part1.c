#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file
#define ET_DYN 3	// Shared object file
#define ET_CORE 4	// Core file

#define STB_GLOBAL 1

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char *symbol_name, char *exe_file_name, int *error_val)
{
	FILE *fptr = fopen(exe_file_name, "r");
	if (fptr == NULL)
	{
		*error_val = -3;
		return 0;
	}

	Elf64_Ehdr ehdr;
	fread(&ehdr, sizeof(Elf64_Ehdr), 1, fptr);

	if (ehdr.e_type != ET_EXEC)
	{
		printf("Not an executable! :( \n %d", ehdr.e_type);
		*error_val = -3;
		return 0;
	}

	Elf64_Shdr shdr;
	fseek(fptr, ehdr.e_shoff, SEEK_SET);
	fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

	Elf64_Shdr shstrtab;
	fseek(fptr, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
	fread(&shstrtab, sizeof(Elf64_Shdr), 1, fptr);

	char *shstrtab_buf = malloc(shstrtab.sh_size);
	fseek(fptr, shstrtab.sh_offset, SEEK_SET);
	fread(shstrtab_buf, shstrtab.sh_size, 1, fptr);

	Elf64_Shdr symtab;
	Elf64_Shdr strtab;
	for (int i = 0; i < ehdr.e_shnum; i++)
	{
		fseek(fptr, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET);
		fread(&shdr, sizeof(Elf64_Shdr), 1, fptr);

		if (strcmp(shstrtab_buf + shdr.sh_name, ".symtab") == 0)
		{
			symtab = shdr;
		}
		else if (strcmp(shstrtab_buf + shdr.sh_name, ".strtab") == 0)
		{
			strtab = shdr;
		}
	}

	Elf64_Sym sym;
	char *strtab_buf = malloc(strtab.sh_size);
	fseek(fptr, strtab.sh_offset, SEEK_SET);
	fread(strtab_buf, strtab.sh_size, 1, fptr);

	Elf64_Sym symtab_buf[symtab.sh_size / sizeof(Elf64_Sym)];
	fseek(fptr, symtab.sh_offset, SEEK_SET);
	fread(symtab_buf, symtab.sh_size, 1, fptr);

	for (int i = 0; i < symtab.sh_size / sizeof(Elf64_Sym); i++)
	{
		if (strcmp(strtab_buf + symtab_buf[i].st_name, symbol_name) == 0)
		{
			sym = symtab_buf[i];
			break;
		}
	}

	if (sym.st_shndx == SHN_UNDEF)
	{
		*error_val = -1;
		return 0;
	}

	// if local symbol
	printf("%d", ELF64_ST_BIND(sym.st_info));
	if (ELF64_ST_BIND(sym.st_info) != STB_GLOBAL)
	{
		*error_val = -2;
		return 0;
	}

	*error_val = 1;
	return sym.st_value;
}

int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err > 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}