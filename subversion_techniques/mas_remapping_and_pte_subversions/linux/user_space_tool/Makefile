CC=gcc

all:
	$(CC) -c -fpic mal-proc.c
	$(CC) -c -fpic benign-proc.c
	$(CC) -shared -o mallib.so mal-proc.o
	$(CC) -shared -o benignlib.so benign-proc.o
	$(CC) xor-encryptor.c -o xor-encryptor
	./xor-encryptor mallib.so xor-mallib.so
	./xor-encryptor benignlib.so xor-benignlib.so
	$(CC) norm-proc.c -ldl -o norm-process -lcurl -pthread -lrt
