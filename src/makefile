TARGET = sps
CC = gcc
CFLAGS = -Wall -Wextra -pedantic-errors -std=gnu11
LFLAGS = -lpthread

all: $(TARGET)

$(TARGET): main.o scanner.a sniffer.a main
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o $@

main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@
main: main.c
	$(CC) $(CFLAGS) -c $< -o $@

sniffer.a: sniffer.o
	ar rcs $@ $^

scanner.a: scanner.o
	ar rcs $@ $^

scanner.o: scanner.c scanner.h
	$(CC) $(CFLAGS) -c -o $@ $<

sniffer.o: sniffer.c sniffer.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.a $(TARGET)
# TARGET = sps
# CC = gcc
# #CFLAGS = -Wall -Wextra -Werror -pedantic-errors -std=gnu11
# LFLAGS = -lpthread

# all: $(TARGET)

# $(TARGET): main.o scanner.a sniffer.a
# 	$(CC) $(LFLAGS) $^ -o $@
# #		$(CC) $(CFLAGS) $(LFLAGS) $^ -o $@

# main.o: main.c
# 	$(CC) -c $< -o $@

# sniffer.a: sniffer.o
# 	ar rcs $@ $^

# scanner.a: scanner.o
# 	ar rcs $@ $^

# scanner.o: scanner.c scanner.h
# 	$(CC) -c -o $@ $<

# sniffer.o: sniffer.c sniffer.h
# 	$(CC) -c -o $@ $<

# clean:
# 	rm -f *.o *.a $(TARGET)