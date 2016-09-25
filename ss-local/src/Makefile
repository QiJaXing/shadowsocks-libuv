
PROJECT = shadow

# compiler
CC = gcc

# link
CFLAGS  = -Wall -g -I../include
LDFLAGS = -luv -Lopenssl -lcrypto

# file
SRC = $(shell find . -name "*.c" -type f)
OBJ = $(patsubst %.c, %.o, $(SRC)) 

# make
all: $(PROJECT)

$(PROJECT): $(OBJ)
	$(CC) $^ $(LDFLAGS) $(CFLAGS) -o $@

%.o: %.c
	$(CC) $< -c $(CFLAGS) -o $@

clean:
	$(RM) $(OBJ) $(PROJECT)
