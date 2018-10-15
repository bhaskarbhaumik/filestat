# Makefile - src
#
#
CC		= gcc
#CFLAGS	= -Wall -O3 -I.
#LDFLAGS	=
CFLAGS	= -Wall -O3 -I. -I/usr/local/Cellar/openssl/1.0.2p/include
LDFLAGS	= -L/usr/local/Cellar/openssl/1.0.2p/lib -lssl -lcrypto
RM		= rm -f

OBJS	= filestat.o

.c.o:
		$(CC) -c $(CFLAGS) $*.c

all:		filestat

filestat:	$(OBJS)
		$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

filestat.o:	filestat.c

install:

clean:
		$(RM) $(OBJS) filestat core 2>/dev/null
