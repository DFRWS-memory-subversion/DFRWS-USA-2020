CC=gcc
CFLAGS=-pthread -lrt -lcurl -ldl
INPUT=shared_memory_subversion.c
OUTPUT=shared_memory_subversion

all: shared_memory_subversion

shared_memory_subversion:
	$(CC) $(CFLAGS) $(INPUT) -o $(OUTPUT)
