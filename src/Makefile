TARGET = sps
CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic-errors -std=gnu11
LFLAGS = -lpthread

all: $(TARGET)

$(TARGET): main.o scanner.a sniffer.a
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o $@

main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@

sniffer.a: sniffer.o
	ar rcs $@ $^

scanner.a: scanner.o
	ar rcs $@ $^

scanner.o: src/scanner.c src/scanner.h
	$(CC) $(CFLAGS) -c -o $@ $<

sniffer.o: src/sniffer.c src/sniffer.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.a $(TARGET)