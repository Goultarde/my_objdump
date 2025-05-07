# my_objdump

## Objectifs

L'objectif de ce projet était de reproduire partiellement `objdump`, avec certaines de ses fonctionnalités. Il fallait au minimum que mon `objdump` me permette d’afficher le *magic number* de l’ELF, le nombre de sections, leurs noms, ainsi que, pour chaque en-tête de section : le nom de la section, sa taille et son décalage (*offset*) dans le fichier. Pour cela, la bibliothèque `elf.h` nous sera d’une grande aide.
Ce projet m’a permis de développer mes compétences en C et d’avoir une meilleure compréhension du fonctionnement d’un binaire ELF. Ce fut une très bonne expérience.

Vous trouverez mon *write-up* dans le fichier `my_objdump-wu.md`.

## Compilation

Après avoir installer la biblothèque capstone avec `sudo apt install libcapstone-dev` si vous êtes sur débian,  
lancer cette commande pour la compilation:
```
gcc -Wall -Wextra -o my_objdump my_objdump.c -lcapstone
```
Ou lancer `make`.
