CC = gcc
CFLAGS = -Wall -O2
AR = ar
ARFLAGS = -cr

SRC = sm2.c sm3.c sms4.c sm2alg.c
OBJ = sm2.o sm3.o sms4.o sm2alg.o

LIB = libsm2alg.a
TEST = sm2_test

.PHONY: all

all: $(LIB) $(TEST)

.c.o:
	$(CC) $(CFLAGS) -c $*.c -I. -I./miracl/ -o $*.o

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^

$(TEST): sm_test.o $(LIB)
	$(CC) -o $@ $< -L. -lsm2alg -L./miracl/ -lmiracl

.PHONY: clean distclean

clean:
	rm -rf *.o

distclean:
	rm -rf *.o $(LIB) $(TEST)
