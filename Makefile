# Nom du compilateur
CC = gcc

# Options de compilation
CFLAGS = -Wall -Wextra

# Fichier source
SRC = my_objdump.c

# Fichier binaire final
BIN = my_objdump

# Librairies à lier
LIBS = -lcapstone

# Règle par défaut
all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $(BIN) $(SRC) $(LIBS)

# Nettoyage des fichiers compilés
clean:
	rm -f $(BIN)

.PHONY: all clean
