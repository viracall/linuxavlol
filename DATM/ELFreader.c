#include "stdio.h"
#include "assert.h"
#include "fcntl.h"
#include "stdlib.h"
#include "unistd.h"
#include "string.h"
#include "errno.h"
#include "elf.h"

void read_elf_header(int32_t fd, Elf32_Ehdr *elf_header)
{
	assert(lseek(fd, (off_t)0, SEEK_SET) == (off_t)0);
	assert(read(fd, (void *)elf_header, sizeof(Elf32_Ehdr)) == sizeof(Elf32_Ehdr));
}

int check_ELF(Elf32_Ehdr elfheader){
	printf("\nBinary Format = ");
	if(!strncmp((char *)elfheader.e_ident,"\177ELF",4)){
		printf("Linux ELF binary detected\n");
		return 1;
	}
	else{
		printf("Not a Linux ELF binary\n");
		return 0;
	}
}

void print_elf_header(Elf32_Ehdr eh){
	printf("###############################\nElf_header_entries\tValue\n###############################\n");
	printf("elf_hdr_entry\t\t%x\n",eh.e_entry);
	printf("program_hdr_nmbr\t%x\n",eh.e_phnum);
	printf("section_hdr_nmbrt\t%x\n",eh.e_shnum);
	printf("section_hdr_strnIndex\t%x\n",eh.e_shstrndx);
	printf("program_hdr_entsize\t%x\n",eh.e_phentsize);
	printf("###############################\n");
}

void type_ELF_storage(Elf32_Ehdr elftype){
	printf("Storage class = ");
	switch(elftype.e_ident[EI_CLASS]){
		
		case ELFCLASS32:
			printf("32 bit Linux binary\n");
			break;

		case ELFCLASS64:
			printf("64 bit Linux binary\n");
			break;

		default:
			printf("class unknown\n");
	}
	printf("\nELF header size\t= 0x%08x\n\n", elftype.e_ehsize);
}

void read_section_header_table(int32_t fd, Elf32_Ehdr eh, Elf32_Shdr sh_table[])
{
	uint32_t i;

	assert(lseek(fd, (off_t)eh.e_shoff, SEEK_SET) == (off_t)eh.e_shoff);

	for(i=0; i<eh.e_shnum; i++) {
		assert(read(fd, (void *)&sh_table[i], eh.e_shentsize) == eh.e_shentsize);
	}
}

char *read_section(int32_t fd, Elf32_Shdr sh){
 
         char *buff = malloc(sh.sh_size);
 
         if(!buff){
                 printf("failed to allocate size\n");
         }
	 assert(buff!=NULL);
	 assert(lseek(fd, (off_t)sh.sh_offset, SEEK_SET) == (off_t)sh.sh_offset);
         assert(read(fd,(void *)buff,sh.sh_size) == sh.sh_size);
         return buff;
}

void print_sections(int32_t fd, Elf32_Ehdr eh, Elf32_Shdr sh_table[])
{
         uint32_t i;
         char *sh_str;
         sh_str = read_section(fd, sh_table[eh.e_shstrndx]);
         printf("\n####################################################################################################################################\n");
         printf("Sl.no\tSection type\tSection flags\tSection size\tSection link\t Section info\tAddress align\tEntry size\tSection name\n");
         printf("####################################################################################################################################\n");
 
         for(i=1; i<eh.e_shnum; i++){
                 printf(" %3d\t", i);
                 printf("%08x\t", sh_table[i].sh_type);
		 printf("%x\t\t", sh_table[i].sh_flags);
		 printf("%x\t\t", sh_table[i].sh_size);
		 printf("%x\t\t", sh_table[i].sh_link);
		 printf("%x\t\t", sh_table[i].sh_info);
		 printf("%d\t\t", sh_table[i].sh_addralign);
		 printf("%08x\t", sh_table[i].sh_entsize);
		 printf("%s\t", (sh_str + sh_table[i].sh_name));
		 printf("\n");
         }
         printf("####################################################################################################################################\n");
}

void read_program_header_table(int32_t fd, Elf32_Ehdr eh, Elf32_Phdr ph_table[])
{
	uint32_t i;

	assert(lseek(fd, (off_t)eh.e_phoff, SEEK_SET) == (off_t)eh.e_phoff);

	for(i=0; i<eh.e_phnum; i++) {
		assert(read(fd, (void *)&ph_table[i], eh.e_phentsize) == eh.e_phentsize);
	}
}

char *read_segments(int32_t fd, Elf32_Phdr ph, Elf32_Ehdr eh){
 
         char *buff = malloc(eh.e_phnum * eh.e_phentsize);
 
         if(!buff){
                 printf("failed to allocate size\n");
         }
	 assert(buff!=NULL);
	 assert(lseek(fd, (off_t)eh.e_phoff, SEEK_SET) == (off_t)eh.e_phoff);
         assert(read(fd,(void *)buff,eh.e_phentsize) == eh.e_phentsize);
         return buff;
}

void print_segments(int32_t fd, Elf32_Ehdr eh, Elf32_Phdr ph_table[])
{
         uint32_t i;
         char *ph_str;
         ph_str = read_segments(fd, ph_table[eh.e_phoff], eh);
         printf("\n####################################################################################################################################\n");
         printf("Sl.no\tSegment type\tSegment offset\tSegment vaddr\tSegment paddr\tSegment filesz\tSeg memsz\tSeg flags\tSeg allign\n");
         printf("####################################################################################################################################\n");
 
         for(i=0; i<eh.e_phnum; i++){
                 printf(" %3d\t", i);
                 printf("%08x\t", ph_table[i].p_type);
		 printf("%x\t\t", ph_table[i].p_offset);
		 printf("%x\t\t", ph_table[i].p_vaddr);
		 printf("%x\t\t", ph_table[i].p_paddr);
		 printf("%x\t\t", ph_table[i].p_filesz);
		 printf("%d\t\t", ph_table[i].p_memsz);
		 printf("%08x\t", ph_table[i].p_flags);
		 printf("%x\t", ph_table[i].p_align);
		 printf("\n");
         }
         printf("####################################################################################################################################\n");
}

int32_t main(int32_t argc, char *argv[]){

	int32_t fd;
	Elf32_Ehdr eh;
	Elf32_Shdr* sh_tbl;
	Elf32_Phdr* ph_tbl;

	if(argc!=2){
		printf("Specify an executable file as an argument\n");

	}
	fd=open(argv[1],O_RDONLY|O_SYNC);
	if(fd<0){
		printf("unable to open:%s\n",argv[1]);
		return 0;
	}
	read_elf_header(fd, &eh);	
	if(check_ELF(eh)!=1){
		type_ELF_storage(eh);
		return 0;
	}
	type_ELF_storage(eh);
	sh_tbl = malloc(eh.e_shentsize * eh.e_shnum);
	read_section_header_table(fd, eh, sh_tbl);
	print_elf_header(eh);
	print_sections(fd, eh, sh_tbl);
	ph_tbl = malloc(eh.e_phentsize * eh.e_phnum);
	read_program_header_table(fd, eh, ph_tbl);
	print_segments(fd, eh, ph_tbl);
	printf("\nEOP!\n");
	return 0;
}

