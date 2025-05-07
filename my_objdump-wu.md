# Projet C - my_objdump 

L’objectif de ce projet était de re-coder partiellement le binaire `objdump`. Il nous fallait au minimum que notre `objdump` permette d’afficher le magic number de l’ELF, le nombre de sections, leurs noms, et d’afficher pour chaque header de section : le nom de la section, sa taille et leur offset dans le fichier. Pour cela, la bibliothèque `elf.h` nous sera d’une grande aide.

## Magic Byte

La première chose qu’il fallait faire était d’afficher le magic byte. Il faut savoir que le magic byte d’un fichier `ELF` est `7F` suivi de `ELF` en hexadécimal, soit `7F 45 4C 46`.

`*e_ident*` est un tableau de bytes qui spécifie comment interpréter un fichier elf.

On crée d’abord un `e_indent` temporaire de 16 octets, donc pas celui des structures `Elf32_Ehdr` et `Elf64_Ehdr` de la librairie `elf.h`. Cela va nous permettre de vérifier que le fichier est bien un `elf` valide via une comparaison entre l’indice de `e_ident` et les constantes `ELFMAGX` qui indiquent le `magic number`.

```csharp
unsigned char e_ident[EI_NIDENT];

fread(e_ident, 1, EI_NIDENT, file); // Octet par octet

fseek(file, 0, SEEK_SET); // Curseur au début du fichier à partir du début du fichier (SEEK_SET)

if (!(e_ident[EI_MAG0] == ELFMAG0 &&
      e_ident[EI_MAG1] == ELFMAG1 &&
      e_ident[EI_MAG2] == ELFMAG2 &&
      e_ident[EI_MAG3] == ELFMAG3)) {
	fprintf(stderr, "Ce n’est pas un fichier ELF valide\n");
	fclose(file);
	return 1;
}
```

Sachant qu’il existe des architectures 32 et 64 bits, on va d’abord vérifier l’architecture avec `EI_CLASS`. Si `EI_CLASS = 1` alors c’est du `32 bits`, si `EI_CLASS = 2` alors c’est du `64 bits`.

Ils sont définis comme suit dans le fichier `elf.h` :

```jsx
#define EI_MAG0		0		/* File identification byte 0 index */
#define ELFMAG0		0x7f		/* Magic number byte 0 */
#define EI_MAG1		1		/* File identification byte 1 index */
#define ELFMAG1		'E'		/* Magic number byte 1 */
#define EI_MAG2		2		/* File identification byte 2 index */
#define ELFMAG2		'L'		/* Magic number byte 2 */
#define EI_MAG3		3		/* File identification byte 3 index */
#define ELFMAG3		'F'		/* Magic number byte 3 */
```

Si l’utilisateur choisit d’afficher le `magic number`, via une boucle sur `e_ident`, on va afficher chaque octet du `magic number` en hexadécimal mais sur deux chiffres avec `%02x` suivi d’un espace pour séparer par groupes de deux. Puis on en profite pour afficher la conversion de MAGX avec le format de string `%c` qui convertit l’hexadécimal en caractère (ELF).

```csharp
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
```

## Sections

### Afficher le nombre de sections

Tout d’abord, nous devions trouver et afficher le nombre de sections. On peut trouver ce dernier dans le header du fichier ELF, soit dans la variable `e_shnum` des structures `Elfxx_Ehdr`.

Ainsi, on peut établir la taille qu’il nous faudra allouer pour toutes les sections présentes avec `ehdr.e_shnum` :

```csharp
Elfxx_Ehdr ehdr;
```

*note : shdr signifie `section header`*

Cependant, si le nombre de sections ne s’y trouve pas, on trouvera `ehdr.e_shnum == 0`. Ainsi, on retrouve le nombre de sections dans la première section.

On se place donc à l’offset du début des sections avec `fseek`, offset que l’on retrouve dans la variable `e_shoff` des structures `Elfxx_Ehdr`, pour lire la première section dans une variable `first` de type `Elfxx_Shdr`. Puis on remplace le 0 de `ehdr.e_shnum` par la taille trouvée.

```csharp
if (ehdr.e_shnum == 0) {
    fseek(file, ehdr.e_shoff, SEEK_SET);
    Elf32_Shdr first;
    fread(&first, 1, sizeof(first), file);
    ehdr.e_shnum = first.sh_size;
}
```

Cela nous permet par la suite d’afficher le nombre de sections :

```csharp
printf("Nombre de sections : %d\n\n", ehdr.e_shnum);
```

### Afficher le nom, offset, taille et type des sections

Nous devons également afficher le nom, l’offset, la taille et le type des sections.

Pour cela, on peut allouer l’espace nécessaire pour stocker les `headers` de toutes les sections dans une variable `sh_table` de type `Elfxx_Shdr *` et on pointe la lecture du fichier à l’offset de section :

```csharp
Elf32_Shdr *sh_table = malloc(sizeof(Elf32_Shdr) * ehdr.e_shnum);
fseek(file, ehdr.e_shoff, SEEK_SET);
fread(sh_table, sizeof(Elf32_Shdr), ehdr.e_shnum, file);
```

\- Les noms des sections sont tous regroupés dans une **section spéciale** appelée **`.shstrtab`** (section header string table), dont l’index peut être trouvé via la variable `e_shstrndx`.

On peut créer une variable `sh_strtab` qui contient le `header` de cette section ainsi qu’une variable `sh_str` qui va en contenir le contenu, donc les noms.

```c
Elf32_Shdr sh_strtab = sh_table[ehdr.e_shstrndx];
char *sh_str = malloc(sh_strtab.sh_size);
fseek(file, sh_strtab.sh_offset, SEEK_SET);
fread(sh_str, 1, sh_strtab.sh_size, file);
```

Ainsi, on peut venir récupérer le nom, la taille et l’offset de chaque section.

```c
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
```

Avec `&sh_str[sh_table[i].sh_name]` je récupère la valeur à l’adresse, `sh_name` étant un index vers le premier caractère du nom d’une section. `printf` s’arrête d’afficher une chaîne de caractères `%s` lorsqu’elle atteint un caractère null. Or `.shstrtab` se compose comme suit :

```csharp
0   → '\0'  
1   → '.'  
2   → 't'  
3   → 'e'  
4   → 'x'  
5   → 't'  
6   → '\0'  
7   → '.'  
8   → 'd'  
9   → 'a'  
10  → 't'  
11  → 'a'  
12  → '\0'  
```

A partir de ces informations, on peut crée un buffer `sh_str`

- `ehdr` est l’en-tête ELF principal.
- Le champ `e_shstrndx` (section header string table index) contient un **index** : il indique **quelle section** contient les **noms de toutes les autres sections**.
- C’est souvent la dernière section du fichier (ex: `.shstrtab`).

### Désassembler la section `.text`

**Récupération des symboles**

Un bonus était de désassembler la fonction **`.text`**. Pour cela, on peut créer une variable `text_section` de type `Elf32_Shdr` qui contiendra donc le `header` de la section `.text`.

Pour cela, on va parcourir toute la table `sh_table` pour trouver la section `.text` :

```csharp
Elf32_Shdr *text_section = NULL;
for (int i = 0; i < ehdr.e_shnum; i++) {
    if (strcmp(&sh_str[sh_table[i].sh_name], ".text") == 0) {
        text_section = &sh_table[i];
    }
}
```

Il nous faudra récupérer les symboles pour plus de lisibilité lors de l’assemblage. Pour cela, on crée une structure pour stocker leur adresse, nom et type (bien que pour l’instant on n’utilise pas le type). Cela n’est pas forcément utile, mais il est plus simple de manipuler notre propre structure de symbole que la structure de symbole déjà existante dans l’`elf.h`.

```c
typedef struct {
    uint64_t addr;
    const char *name;
    uint8_t type;
} ElfSymbol;
```

Pour ne pas simplement avoir un affichage hexadécimal de la section `.text`, il va donc nous falloir trouver ces symboles de la section `.text` et récupérer leurs adresses, leurs noms et leur nombre total.

Pour cela, on va devoir lire la table des symboles, qui est une section nommée `.symtab`. Elle contient un tableau de symboles ayant tous cette structure :

```c
typedef struct {
    Elf32_Word st_name;   // ← offset dans .strtab (vers le nom)
    Elf32_Addr st_value;  // adresse du symbole (ex : 0x08048400)
    Elf32_Word st_size;   // taille en octets
    unsigned char st_info; // type (FUNC, OBJECT...) + binding
    unsigned char st_other;
    Elf32_Half st_shndx;  // index de la section associée
} Elf32_Sym;
```

Ainsi, avec une boucle `for`, on recherche dans la table des sections préalablement remplie, la section `.symtab`. C’est celle qui aura pour type `SHT_SYMTAB` :

```c
for (int i = 0; i < shnum; ++i) {
    if (sh_table[i].sh_type == SHT_SYMTAB) {
```

De cette section, on récupère sa taille et donc celle de tous les symboles combinés, pour la diviser par la taille d’un seul symbole, ce qui nous permet d’obtenir le nombre de symboles. On utilisera ce dernier pour savoir combien de symboles il faudra stocker dans notre variable `symbols_buffer`, qui elle est un pointeur de type `Elf64_Sym *`. Ainsi, on stocke tous les symboles dans ce `buffer`.

```c
int sym_count = symtab.sh_size / sizeof(Elf64_Sym);
Elf64_Sym *symbols_buffer = malloc(symtab.sh_size);
fseek(file, symtab.sh_offset, SEEK_SET);
fread(symbols_buffer, sizeof(Elf64_Sym), sym_count, file);
```

Mais ce buffer n’aura que pour but de remplir nos propres symboles avec notre structure personnalisée que l’on va stocker dans la variable `symbols_out` de notre type personnalisé `ElfSymbol`. Cette fois-ci, on ne stocke que l’adresse et le nom du symbole. C’est avec `symbol_count_out` que l’on va itérer sur chaque symbole.

```c
symbols_out = malloc(sizeof(ElfSymbol) * sym_count);
for (int j = 0; j < sym_count; ++j) {
    if (symbols_buffer[j].st_size > 0 && symbols_buffer[j].st_value != 0) {  // ignorer les symboles nuls
        symbols_out[*symbol_count_out].addr = symbols_buffer[j].st_value;
        symbols_out[*symbol_count_out].name = &strtab_data[symbols_buffer[j].st_name];
        (*symbol_count_out)++;
    }
}
```

---

### Désassemblage de la section `.text` avec les symboles

Enfin, on va pouvoir désassembler notre section `.text`, mais pour cela, on aura besoin de la bibliothèque `capstone` préalablement importée avec `#include <capstone/capstone.h>`.

Cette bibliothèque va nous permettre de traduire le code présent dans la section `.text` en instructions assembleur.

On va stocker tout le contenu de la section dans un pointeur `code` et s’assurer de placer notre curseur de fichier à l’offset auquel commence notre section. L’`unsigned char` nous permet de représenter un octet brut en C.

```c
unsigned char *code = malloc(text->sh_size);
fseek(file, text->sh_offset, SEEK_SET);
fread(code, 1, text->sh_size, file);
```

On va avoir besoin de déclarer un handle Capstone de type `csh`, qui est un type défini par Capstone et qui sert de descripteur (ou de session, si l’on préfère) et qui va permettre à Capstone de savoir quelle architecture on veut (x86, ARM…), en quel mode (32-bit, 64-bit, Thumb…). Ensuite, on va déclarer un tableau `insn` pour les instructions désassemblées. Il sera de type `cs_insn *`, un type qui permet de représenter une instruction désassemblée :

```c
typedef struct cs_insn {
    uint64_t address;
    char mnemonic[32];  // ex : "mov", "call"
    char op_str[160];   // ex : "eax, 0x1" (opérandes)
    ...
} cs_insn;
```

Et enfin une variable `count` de type `size_t`, qui est un type entier pouvant contenir la taille maximale d’un objet en mémoire. Il va nous permettre de compter le nombre d’instructions présentes dans notre section.

Tout d’abord, on va passer notre `handle` dans `cs_open` qui va permettre d’initialiser la session de désassemblage, puis nous allons calculer le nombre d’instructions et, par la même occasion, remplir notre buffer d’instruction `insn` avec `cs_disasm` :

```c
if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK) {
    fprintf(stderr, "Failed to initialize Capstone\n");
    return;
}

count = cs_disasm(handle, code, text->sh_size, text->sh_addr, 0, &insn);
```

Ainsi, pour chaque symbole, on va venir afficher l’adresse de l’instruction, son `mnemonic` et ses opérandes (`op_str`).

Enfin, on ferme notre `handle` avec `cs_close(&handle);`.

---

### Affichage de la Program Header Table

Enfin, il nous fallait afficher les informations de la Program Header Table.

Un Program Header décrit comment charger le programme en mémoire à l’exécution. Il est utilisé par le loader (ex : le noyau Linux), pas vraiment par les développeurs.

Là où la Program Header Table est obligatoirement présente et permet de charger l’ELF en mémoire (et est utilisée par le loader), la Section Header Table, elle, est utilisée par...

Pour afficher la Program Header, on va simplement afficher chaque élément de la structure `Elf64_Phdr`.

Pour cela, on récupère l’offset de la Program Header dans la Section Header afin d’y placer notre curseur :

```c
fseek(file, ehdr->e_phoff, SEEK_SET);
```

Puis on se contente de tout afficher sous forme de tableau :

```c
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
```

Avec comme spécificité le `RWX` qui va permettre d’indiquer les permissions d’un segment ELF via le champ `p_flags`. Pour trouver les permissions d’un segment, on va faire une opération bit à bit (`bitwise AND`) entre les valeurs individuelles de `R`, `W` et `X` et la valeur de `p_flags` (convertie en binaire) :

```c
  00000101   ← ph.p_flags
& 00000100   ← 4
------------
  00000100 → Résultat ≠ 0 ⇒ le bit est activé
```

---
