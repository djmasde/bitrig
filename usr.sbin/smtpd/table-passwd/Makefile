#	$OpenBSD: Makefile,v 1.3 2014/02/04 16:32:36 eric Exp $

.PATH: ${.CURDIR}/..

PROG=	table-passwd

SRCS=	table_passwd.c
SRCS+=	table_api.c
SRCS+=	dict.c
SRCS+=	log.c

MAN=	table_passwd.5

BINDIR=	/usr/libexec/smtpd

DPADD=	${LIBUTIL}
LDADD=	-lutil

CFLAGS+=	-g3 -ggdb -I${.CURDIR}/..
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
CFLAGS+=	-DNO_IO
#CFLAGS+=	-Werror # during development phase (breaks some archs) 

.include <bsd.prog.mk>
