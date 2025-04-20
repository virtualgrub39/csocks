C_FILES = $(wildcard *.c)
O_FILES = $(C_FILES:.c=.o)

CSOCKS_CFLAGS = $(CFLAGS) -Wall -Werror -pedantic -ggdb

csocks: csocks.o utils.o utils.h config.h
	gcc -o $@ $^ $(CSOCKS_CFLAGS)

%.o: %.c config.h
	gcc -c $^ $(CSOCKS_CFLAGS)

all: csocks

clean:
	-rm -f $(O_FILES)
	-rm -f csocks 

config.h: config.default.h
	cp config.default.h config.h

.PHONY: all clean
.DEFAULT: all
