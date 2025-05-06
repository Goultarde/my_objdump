# Projet C - my_objdump 
L’objectif de ce projet était de re-coder partiellement le binaire `objdump`. Il nous fallait au minimum que notre `objdump`  permette d’afficher le magic number de l’ELF, le nombre de sections, et leurs noms et l’affichage pour chaque header de section, le nom de la section, sa taille et leurs offset dans le fichier. Pour cela, la bibliothèque `elf.h` nous sera d’une grande aide.

## Magic Byte

La première chose qu’il fallait faire était d’afficher le magic byte. Il faut savoir que le magic byte d’un fichier `ELF` est `7F` suivis de `ELF` en hexadécimal, soit `7F 45 4C 46`.

`*e_ident*` est un tableau de byte qui spécifies comment interpréter un ficher elf.

On crée d’abord un `e_indent` temporaire de 16 octet, donc pas celui des structure `Elf32_Ehdr` et `Elf64_Ehdr` de la librairie `elf.h` pour vérifier que le fichier est bien un `elf` valide via une comparaison entre l’indice de l’`e_ident` et les constant `ELFMAGX` qui indiquent le `magic number`. 

```csharp
unsigned char e_ident[EI_NIDENT];
fread(e_ident, 1, EI_NIDENT, file); // Octet par Octet
fseek(file, 0, SEEK_SET); // Curseur au début du fichier à partir du début du fichier (SEEK_SET)

if (!(e_ident[EI_MAG0] == ELFMAG0 &&
      e_ident[EI_MAG1] == ELFMAG1 &&
      e_ident[EI_MAG2] == ELFMAG2 &&
		    e_ident[EI_MAG3] == ELFMAG3)) {
		fprintf(stderr, "Ce n’est pas un fichier ELF valide\n");
		fclose(file);
		return 1;fichier ELF valide\n");
		fclose(file);
}
```

Sachant qu’il existe des architecture 32 et 64 bits, on  va d’abord vérifier l’architecture avec `EI_CLASS`. Si `EI_CLASS = 1` alors c’est du `32 bits` si `EI_CLASS = 2` alors c’est du `64 bits` . 

Ils sont définit comme suit dans le fichier `elf.h` 

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

Si l’utilisateur choisi d’afficher le `magic number`, via une boucle sur `e_ident`, on va afficher chaque octet du `magic number` en hexadécimal mais sur deux chiffre avec `%02x` suivis d’un espace pour séparer les groupes de deux. Puis on en profite pour afficher la conversion de MAGX avec le format de string `%c` qui convertie l’hexadécimal en caractère (ELF).

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

### Afficher le nombre des sections

Tout d’abord nous devions trouver et afficher le nombre de sections. On peut trouver ce dernier dans le header du fichier elf, soit dans la variable `e_shnum` des structures`Elfxx_Ehdr`.

Ainsi on peut établir la taille qu’il nous faudras alloquer pour toutes les sections présentes avec `ehdr.e_shnum` :

```csharp
Elfxx_Ehdr ehdr;
```

*note : shdr signifie `section header`*

Cependant si le nombre de sections ne s’y trouve pas on trouvera `ehdr.e_shnum == 0` ainsi, on retrouve le nombre de section dans la première section.
On ce place donc à l’offset du début des sections avec `fseek`, offset que l’on retrouve dans la variable `e_shoff` des structures`Elfxx_Ehdr`, pour lire la première sections dans une variable `first` de type `Elfxx_Shdr`. Puis on remplace le 0 de `ehdr.e_shnum` par la taille trouver.

```csharp
if (ehdr.e_shnum == 0) {
    fseek(file, ehdr.e_shoff, SEEK_SET);
    Elf32_Shdr first;
    fread(&first, 1, sizeof(first), file);
    ehdr.e_shnum = first.sh_size;
}
```

Cela nous permet par la suite d’afficher le nombre de section

```csharp
printf("Nombre de sections : %d\n\n", ehdr.e_shnum);
```

### Afficher le nom, offset taille et type des sections

Nous devons également afficher le nom, l’offset, la taille et le type des sections.

Pour cela, on peut allouer l’espace nécessaire pour stocker les `headers` de toutes les sections dans une variable `sh_table` de type `Elfxx_Shdr *` et on pointe la lecture du fichier à l’offset de section:

```csharp
Elf32_Shdr *sh_table = malloc(sizeof(Elf32_Shdr) * ehdr.e_shnum);
fseek(file, ehdr.e_shoff, SEEK_SET);
fread(sh_table, sizeof(Elf32_Shdr), ehdr.e_shnum, file);
```

- Les noms des section sont tous regroupés dans une **section spéciale** appelée **`.shstrtab`** (section header string table). Dont l’index peut être trouver via la variable `e_shstrndx`.

On peut crée une variable `sh_strtab` qui contient le `header` de cette section ainsi qu’une variable `sh_str` qui va en contenir le contenue de cette sections, donc les noms. 

```
Elf32_Shdr sh_strtab = sh_table[ehdr.e_shstrndx];
char *sh_str = malloc(sh_strtab.sh_size);
fseek(file, sh_strtab.sh_offset, SEEK_SET);
fread(sh_str, 1, sh_strtab.sh_size, file);
```

Ainsi on peut venir récupérer le nom, la taille et l’offset de chaque sections.

```csharp
for (int i = 0; i < ehdr.e_shnum; i++) {
            printf("Section %2d: %s\n", i, &sh_str[sh_table[i].sh_name]);
            printf("  Offset : 0x%x\n", sh_table[i].sh_offset);
            printf("  Taille : 0x%x\n", sh_table[i].sh_size);
            printf("  Type   : %s\n\n", get_section_type_name(sh_table[i].sh_type));
        }
```

avec `&sh_str[sh_table[i].sh_name]);` je récupère la valeur à l’adresse, `sh_name` étant un index vers le premier caractère du nom d’une section. printf s’arrète d’afficher une chaîne de caractère `%s` lorsqu’elle atteint un caractère null horst `.shstrtab` se compose comme suit :

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

Un bonus était de désassembler la fonction **`.text`**, pour cela, on peut crée un variable `text_section` de type `Elf32_Shdr` qui contiendra donc le `header` de la Section `.text`

Pour cela on va parcourir toute la table `sh_table` pour trouver la section `.text`

```csharp
Elf32_Shdr *text_section = NULL;
for (int i = 0; i < ehdr.e_shnum; i++) {
    if (strcmp(&sh_str[sh_table[i].sh_name], ".text") == 0) {
        text_section = &sh_table[i];
    }
}
```