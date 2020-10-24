# Project: SEED

CC   = cc
OBJ  = seed.o KISA_SEED_CBC.o
INCS =  -I.
BIN  = seed
CFLAGS = $(INCS)  
RM = rm -f

.PHONY: all clean

all: $(BIN)

clean:
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $(BIN)

seed.o: seed.c
	$(CC) -c seed.c -o seed.o $(CFLAGS)

KISA_SEED_CBC.o: KISA_SEED_CBC.c
	$(CC) -c KISA_SEED_CBC.c -o KISA_SEED_CBC.o $(CFLAGS)
