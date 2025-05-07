# Nom de l'exécutable
TARGET = my_objdump

# Fichiers source
SRC = my_objdump.c

# Fichiers objets
OBJ = $(SRC:.c=.o)

# Options de compilation
CFLAGS = -Wall -Wextra

# Bibliothèques à lier
LDLIBS = -lcapstone

# Règle par défaut
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# Nettoyage
clean:
	rm -f $(TARGET) $(OBJ)

# Pour forcer la reconstruction
re: clean all
