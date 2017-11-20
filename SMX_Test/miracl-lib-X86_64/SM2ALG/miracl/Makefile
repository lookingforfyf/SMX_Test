CC = gcc
CFALGS = -c -m64 -O2
AR = ar
ARFLAGS = -cr

LIB = libmiracl.a

SRC = mrcore.c mrarth0.c mrarth1.c mrarth2.c mralloc.c mrsmall.c mrio1.c mrio2.c mrgcd.c 
SRC += mrjack.c mrxgcd.c mrarth3.c mrbits.c mrrand.c mrprime.c mrcrt.c mrscrt.c mrmonty.c
SRC += mrpower.c mrsroot.c mrcurve.c mrfast.c mrshs.c mrshs256.c mrshs512.c mrsha3.c mrfpe.c
SRC += mraes.c mrgcm.c mrlucas.c mrzzn2.c mrzzn2b.c mrzzn3.c mrzzn4.c mrecn2.c mrstrong.c
SRC += mrbrick.c mrebrick.c mrec2m.c mrgf2m.c mrflash.c mrfrnd.c mrdouble.c mrround.c
SRC += mrbuild.c mrflsh1.c mrpi.c mrflsh2.c mrflsh3.c mrflsh4.c
SRC += mrmuldv.c

OBJ = $(SRC:.c=.o)

.PHONY: all

all: $(LIB) 

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^

.c.o:
	$(CC) $(CFLAGS) -c $*.c -o $*.o

.PHONY: clean distclean

clean:
	rm -rf *.o

distclean:
	rm -rf *.o $(LIB)
