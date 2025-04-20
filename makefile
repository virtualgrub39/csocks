C_FILES = $(wildcard *.c)
O_FILES = $(C_FILES:.c=.o)

csocks: csocks.o utils.o utils.h config.h
	gcc -o $@ $^ -ggdb

%.o: %.c
	gcc -c $^

all: csocks

clean:
	-rm -f $(O_FILES)
	-rm -f csocks 

config.h: config.default.h
	cp config.default.h config.h

.PHONY: all clean
.DEFAULT: all
