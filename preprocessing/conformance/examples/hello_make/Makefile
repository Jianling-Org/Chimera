CC ?= cc
CFLAGS ?= -O1
hello: main.o util.o
	$(CC) -o $@ main.o util.o
main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o
util.o: util.c
	$(CC) $(CFLAGS) -c util.c -o util.o
clean:
	rm -f hello *.o
