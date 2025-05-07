#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "elf_minimal.h"

void print_magic(unsigned char *e_ident) {
    printf("Magic ELF : ");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", e_ident[i]);
    }
    printf("  (");
    for (int i = 1; i < 4; i++) {
        printf("%c", e_ident[i]);
    }
    printf(")\n");
}

const char *get_section_type_name(uint32_t type) {
    switch (type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA";
        case SHT_HASH: return "HASH";
        case SHT_DYNAMIC: return "DYNAMIC";
        case SHT_NOTE: return "NOTE";
        case SHT_NOBITS: return "NOBITS";
        case SHT_REL: return "REL";
        case SHT_SHLIB: return "SHLIB";
        case SHT_DYNSYM: return "DYNSYM";
        case SHT_INIT_ARRAY: return "INIT_ARRAY";
        case SHT_FINI_ARRAY: return "FINI_ARRAY";
        case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
        case SHT_GROUP: return "GROUP";
        case SHT_SYMTAB_SHNDX: return "SYMTAB_SHNDX";
        default: return "UNKNOWN";
    }
}

const char *get_ph_type(uint32_t type) {
    switch (type) {
        case 0: return "NULL";
        case 1: return "LOAD";
        case 2: return "DYNAMIC";
        case 3: return "INTERP";
        case 4: return "NOTE";
        case 6: return "PHDR";
        case 0x6474e550: return "GNU_EH_FRAME";
        case 0x6474e551: return "GNU_STACK";
        case 0x6474e552: return "GNU_RELRO";
        default: return "UNKNOWN";
    }
}


void print_program_headers64(FILE *file, Elf64_Ehdr *ehdr) {
    fseek(file, ehdr->e_phoff, SEEK_SET);

    printf("\nProgram Headers (64-bit):\n");
    printf("%-14s %-10s %-10s %-10s %-8s %-8s %-4s %-6s\n",
           "Type", "Offset", "VirtAddr", "PhysAddr", "FileSz", "MemSz", "Flg", "Align");
    printf("--------------------------------------------------------------------------------\n");

    for (int i = 0; i < ehdr->e_phnum; ++i) {
        Elf64_Phdr ph;
        fread(&ph, 1, sizeof(ph), file);

        printf("%-14s 0x%08lx 0x%08lx 0x%08lx 0x%06lx 0x%06lx %3c%c%c 0x%lx\n",
               get_ph_type(ph.p_type),
               ph.p_offset,
               ph.p_vaddr,
               ph.p_paddr,
               ph.p_filesz,
               ph.p_memsz,
               (ph.p_flags & 4) ? 'R' : ' ',
               (ph.p_flags & 2) ? 'W' : ' ',
               (ph.p_flags & 1) ? 'X' : ' ',
               ph.p_align);
    }
}

void print_program_headers32(FILE *file, Elf32_Ehdr *ehdr) {
    fseek(file, ehdr->e_phoff, SEEK_SET);

    printf("\nProgram Headers (32-bit):\n");
    printf("%-14s %-10s %-10s %-10s %-8s %-8s %-4s %-6s\n",
           "Type", "Offset", "VirtAddr", "PhysAddr", "FileSz", "MemSz", "Flg", "Align");
    printf("--------------------------------------------------------------------------------\n");

    for (int i = 0; i < ehdr->e_phnum; ++i) {
        Elf32_Phdr ph;
        fread(&ph, 1, sizeof(ph), file);

        printf("%-14s 0x%08x 0x%08x 0x%08x 0x%06x 0x%06x %3c%c%c 0x%x\n",
               get_ph_type(ph.p_type),
               ph.p_offset,
               ph.p_vaddr,
               ph.p_paddr,
               ph.p_filesz,
               ph.p_memsz,
               (ph.p_flags & 4) ? 'R' : ' ',
               (ph.p_flags & 2) ? 'W' : ' ',
               (ph.p_flags & 1) ? 'X' : ' ',
               ph.p_align);
    }
}


typedef struct {
    uint64_t addr;
    const char *name;
    uint8_t type;
} ElfSymbol;


ElfSymbol *load_symbols64(FILE *file, Elf64_Shdr *sh_table, int shnum, int *symbol_count_out, char **strtab_base) {
    ElfSymbol *symbols_out = NULL;
    *symbol_count_out = 0;
    *strtab_base = NULL;

    for (int i = 0; i < shnum; ++i) {
        if (sh_table[i].sh_type == SHT_SYMTAB) {
            Elf64_Shdr symtab = sh_table[i];
            Elf64_Shdr strtab = sh_table[symtab.sh_link];

            int sym_count = symtab.sh_size / sizeof(Elf64_Sym);
            Elf64_Sym *symbols_buffer = malloc(symtab.sh_size);
            fseek(file, symtab.sh_offset, SEEK_SET);
            fread(symbols_buffer, sizeof(Elf64_Sym), sym_count, file);

            char *strtab_data = malloc(strtab.sh_size);
            fseek(file, strtab.sh_offset, SEEK_SET);
            fread(strtab_data, 1, strtab.sh_size, file);
            *strtab_base = strtab_data;

            symbols_out = malloc(sizeof(ElfSymbol) * sym_count);
            for (int j = 0; j < sym_count; ++j) {
                if (symbols_buffer[j].st_size > 0 && symbols_buffer[j].st_value != 0) {
                    symbols_out[*symbol_count_out].addr = symbols_buffer[j].st_value;
                    symbols_out[*symbol_count_out].name = &strtab_data[symbols_buffer[j].st_name];
                    (*symbol_count_out)++;
                }
            }
            free(symbols_buffer);
            break;
        }
    }
    return symbols_out;
}


ElfSymbol *load_symbols32(FILE *file, Elf32_Shdr *sh_table, int shnum, int *symbol_count_out, char **strtab_base) {
    ElfSymbol *symbols_out = NULL;
    *symbol_count_out = 0;
    *strtab_base = NULL;

    for (int i = 0; i < shnum; ++i) {
        if (sh_table[i].sh_type == SHT_SYMTAB) {
            Elf32_Shdr symtab = sh_table[i];
            Elf32_Shdr strtab = sh_table[symtab.sh_link];

            int sym_count = symtab.sh_size / sizeof(Elf32_Sym);
            Elf32_Sym *symbols_buffer = malloc(symtab.sh_size);
            fseek(file, symtab.sh_offset, SEEK_SET);
            fread(symbols_buffer, sizeof(Elf32_Sym), sym_count, file);

            char *strtab_data = malloc(strtab.sh_size);
            fseek(file, strtab.sh_offset, SEEK_SET);
            fread(strtab_data, 1, strtab.sh_size, file);
            *strtab_base = strtab_data;

            symbols_out = malloc(sizeof(ElfSymbol) * sym_count);
            for (int j = 0; j < sym_count; ++j) {
                if (symbols_buffer[j].st_size > 0 && symbols_buffer[j].st_value != 0) {  
                    symbols_out[*symbol_count_out].addr = symbols_buffer[j].st_value;
                    symbols_out[*symbol_count_out].name = &strtab_data[symbols_buffer[j].st_name];
                    (*symbol_count_out)++;
                }
            }
            free(symbols_buffer);
            break;
        }
    }
    return symbols_out;
}


void disassemble_text_section64(FILE *file, Elf64_Shdr *text, const char *section_name, ElfSymbol *symbs, int symbs_count) {
    printf("\nDisassembly of section %s:\n", section_name);
    unsigned char *code = malloc(text->sh_size);
    fseek(file, text->sh_offset, SEEK_SET);
    fread(code, 1, text->sh_size, file);

    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        free(code);
        return;
    }

    count = cs_disasm(handle, code, text->sh_size, text->sh_addr, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            for (int j = 0; j < symbs_count; j++) {
                if (insn[i].address == symbs[j].addr) {
                    printf("\n%08lx <%s>:\n", insn[i].address, symbs[j].name);
                    break;
                }
            }
            printf("  %08lx:\t%-10s %s\n",
                   (unsigned long)insn[i].address,
                   insn[i].mnemonic,
                   insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        fprintf(stderr, "Failed to disassemble .text\n");
    }

    cs_close(&handle);
    free(code);
}

void disassemble_text_section32(FILE *file, Elf32_Shdr *text, const char *section_name, ElfSymbol *symbs, int symbs_count) {
    printf("\nDisassembly of section %s:\n", section_name);
    unsigned char *code = malloc(text->sh_size);
    fseek(file, text->sh_offset, SEEK_SET);
    fread(code, 1, text->sh_size, file);

    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        free(code);
        return;
    }

    count = cs_disasm(handle, code, text->sh_size, text->sh_addr, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            for (int j = 0; j < symbs_count; j++) {
                if (insn[i].address == symbs[j].addr) {
                    printf("\n%08x <%s>:\n", (unsigned int)insn[i].address, symbs[j].name);
                    break;
                }
            }
            printf("  %08x:\t%-10s %s\n",
                   (unsigned int)insn[i].address,
                   insn[i].mnemonic,
                   insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        fprintf(stderr, "Failed to disassemble .text\n");
    }

    cs_close(&handle);
    free(code);
}
void read_elf32(FILE *file, bool is_magic, bool is_sections, bool is_disas, bool is_program_headers){
    Elf32_Ehdr ehdr;
    fread(&ehdr, 1, sizeof(ehdr), file);

    if (is_magic) print_magic(ehdr.e_ident);
    if (!is_sections && !is_disas && !is_program_headers) return;

    if (ehdr.e_shnum == 0) {
        fseek(file, ehdr.e_shoff, SEEK_SET);
        Elf32_Shdr first;
        fread(&first, 1, sizeof(first), file);
        ehdr.e_shnum = first.sh_size;
    }


    Elf32_Shdr *sh_table = malloc(sizeof(Elf32_Shdr) * ehdr.e_shnum);
    fseek(file, ehdr.e_shoff, SEEK_SET);
    fread(sh_table, sizeof(Elf32_Shdr), ehdr.e_shnum, file);

    Elf32_Shdr sh_strtab = sh_table[ehdr.e_shstrndx];
    char *sh_str = malloc(sh_strtab.sh_size);
    fseek(file, sh_strtab.sh_offset, SEEK_SET);
    fread(sh_str, 1, sh_strtab.sh_size, file);

    ElfSymbol *symbs = NULL;
    int symbs_count = 0;
    char *strtab = NULL;
    symbs = load_symbols32(file, sh_table, ehdr.e_shnum, &symbs_count, &strtab);


    Elf32_Shdr *text_section = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (strcmp(&sh_str[sh_table[i].sh_name], ".text") == 0) {
            text_section = &sh_table[i];
        }
    }

    if (is_sections) {
        printf("Format : ELF 32 bits\n");
        printf("Nombre de sections : %d\n\n", ehdr.e_shnum);

        printf("%-4s %-20s %-10s %-10s %-10s\n", "ID", "Nom", "Offset", "Taille", "Type");
        printf("---------------------------------------------------------------\n");

        for (int i = 0; i < ehdr.e_shnum; i++) {
            printf("%-4d %-20s 0x%08x 0x%-8x %-10s\n",
                i,
                &sh_str[sh_table[i].sh_name],
                sh_table[i].sh_offset,
                sh_table[i].sh_size,
                get_section_type_name(sh_table[i].sh_type));
        }

        printf("\n");
    }

//   if (is_sections) {
//       printf("Format : ELF 32 bits\n");
//       printf("Nombre de sections : %d\n\n", ehdr.e_shnum);
//       for (int i = 0; i < ehdr.e_shnum; i++) {
//           printf("Section %2d: %s\n", i, &sh_str[sh_table[i].sh_name]);
//           printf("  Offset : 0x%x\n", sh_table[i].sh_offset);
//           printf("  Taille : 0x%x\n", sh_table[i].sh_size);
//           printf("  Type   : %s\n\n", get_section_type_name(sh_table[i].sh_type));
//       }
//   }

    if (is_disas && text_section) {
        disassemble_text_section32(file, text_section, ".text", symbs, symbs_count);
    }

    if (is_program_headers) {
        print_program_headers32(file, &ehdr);
    }



    free(sh_table);
    free(sh_str);
    free(symbs);
    free(strtab);
}

void read_elf64(FILE *file, bool is_magic, bool is_sections, bool is_disas, bool is_program_headers){
    Elf64_Ehdr ehdr;
    fread(&ehdr, 1, sizeof(ehdr), file);

    if (is_magic) print_magic(ehdr.e_ident);
    if (!is_sections && !is_disas && !is_program_headers) return;

    if (ehdr.e_shnum == 0) {
        fseek(file, ehdr.e_shoff, SEEK_SET);
        Elf64_Shdr first;
        fread(&first, 1, sizeof(first), file);
        ehdr.e_shnum = first.sh_size;
    }

    Elf64_Shdr *sh_table = malloc(sizeof(Elf64_Shdr) * ehdr.e_shnum);
    fseek(file, ehdr.e_shoff, SEEK_SET);
    fread(sh_table, sizeof(Elf64_Shdr), ehdr.e_shnum, file);

    Elf64_Shdr sh_strtab = sh_table[ehdr.e_shstrndx];
    char *sh_str = malloc(sh_strtab.sh_size);
    fseek(file, sh_strtab.sh_offset, SEEK_SET);
    fread(sh_str, 1, sh_strtab.sh_size, file);

    ElfSymbol *symbs = NULL;
    int symbs_count = 0;
    char *strtab = NULL;
    symbs = load_symbols64(file, sh_table, ehdr.e_shnum, &symbs_count, &strtab);

    Elf64_Shdr *text_section = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (strcmp(&sh_str[sh_table[i].sh_name], ".text") == 0) {
            text_section = &sh_table[i];
        }
    }

    if (is_sections) {
        printf("Format : ELF 64 bits\n");
        printf("Nombre de sections : %d\n\n", ehdr.e_shnum);

        printf("%-4s %-20s %-12s %-12s %-10s\n", "ID", "Nom", "Offset", "Taille", "Type");
        printf("---------------------------------------------------------------------\n");

        for (int i = 0; i < ehdr.e_shnum; i++) {
            printf("%-4d %-20s 0x%010lx 0x%-10lx %-10s\n",
                i,
                &sh_str[sh_table[i].sh_name],
                sh_table[i].sh_offset,
                sh_table[i].sh_size,
                get_section_type_name(sh_table[i].sh_type));
        }

        printf("\n");
    }


//   if (is_sections) {
//       printf("Format : ELF 64 bits\n");
//       printf("Nombre de sections : %d\n\n", ehdr.e_shnum);
//       for (int i = 0; i < ehdr.e_shnum; i++) {
//           printf("Section %2d: %s\n", i, &sh_str[sh_table[i].sh_name]);
//           printf("  Offset : 0x%lx\n", sh_table[i].sh_offset);
//           printf("  Taille : 0x%lx\n", sh_table[i].sh_size);
//           printf("  Type   : %s\n\n", get_section_type_name(sh_table[i].sh_type));
//       }
//   }

    if (is_disas && text_section) {
        disassemble_text_section64(file, text_section, ".text", symbs, symbs_count);
    }

    if (is_program_headers) {
        print_program_headers64(file, &ehdr);
    }



    free(sh_table);
    free(sh_str);
    free(symbs);
    free(strtab);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [options] <fichier ELF>\n", argv[0]);
        fprintf(stderr, "Options :\n");
        fprintf(stderr, "  -h             Afficher tout\n");
        fprintf(stderr, "  -m, --magic    Afficher le magic ELF\n");
        fprintf(stderr, "  -s             Afficher les sections\n");
        fprintf(stderr, "  -d, --disas    Désassembler .text\n");
        fprintf(stderr, "  -p             Afficher la Program Header Table\n");
        return 1;
    }

    bool is_magic = false;
    bool is_sections = false;
    bool is_all = false;
    bool is_disas = false;
    bool is_program_headers = false;

    const char *filename = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            is_all = true;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--magic") == 0) {
            is_magic = true;
        } else if (strcmp(argv[i], "-s") == 0) {
            is_sections = true;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--disas") == 0) {
            is_disas = true;
        } else if (strcmp(argv[i], "-p") == 0) {
            is_program_headers = true;
        } else if (argv[i][0] != '-') {
            filename = argv[i];
        } else {
            fprintf(stderr, "Option inconnue : %s\n", argv[i]);
            return 1;
        }
    }

    if (!filename) {
        fprintf(stderr, "Erreur : aucun fichier ELF fourni.\n");
        return 1;
    }

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur à l'ouverture du fichier");
        return 1;
    }

    unsigned char e_ident[EI_NIDENT];
    fread(e_ident, 1, EI_NIDENT, file);
    fseek(file, 0, SEEK_SET);

    if (!(e_ident[EI_MAG0] == ELFMAG0 &&
          e_ident[EI_MAG1] == ELFMAG1 &&
          e_ident[EI_MAG2] == ELFMAG2 &&
          e_ident[EI_MAG3] == ELFMAG3)) {
        fprintf(stderr, "Ce n’est pas un fichier ELF valide\n");
        fclose(file);
        return 1;
    }

    if (e_ident[EI_CLASS] == ELFCLASS32) {
        read_elf32(file, is_all || is_magic, is_all || is_sections, is_all || is_disas, is_all || is_program_headers);
    } else if (e_ident[EI_CLASS] == ELFCLASS64) {
        read_elf64(file, is_all || is_magic, is_all || is_sections, is_all || is_disas, is_all || is_program_headers);
    } else {
        fprintf(stderr, "Format ELF inconnu ou non supporté\n");
    }

    fclose(file);
    return 0;
}
