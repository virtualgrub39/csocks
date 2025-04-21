SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

CSOCKS_CFLAGS = $(CFLAGS) -Wall -Werror -pedantic -Wextra -ggdb
# CSOCKS_LDFLAGS = $(LDFLAGS) -static
CSOCKS_LDFLAGS = $(LDFLAGS)

all: csocks

config.h: config.def.h
	cp config.def.h config.h

.c.o:
	$(CC) $(CSOCKS_CFLAGS) -c $<

utils.o: config.h utils.h
csocks.o: config.h

csocks: $(OBJ)
	$(CC) -o $@ $(OBJ) $(CSOCKS_LDFLAGS)

clean:
	rm -f csocks $(OBJ)

.PHONY: all clean
