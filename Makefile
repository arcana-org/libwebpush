# libwebpush, with base make(1) and bsd.*.mk:
#
#	make && make check
#	make install [DESTDIR=dir] [PREFIX=/usr/local]
#
# Build products go to obj/, mirroring the tree (Makefile.inc).  The
# tests (tests/, atf-c(3)) are built unless WITHOUT_TESTS is set; "make
# check" runs them in the build tree with kyua(1).  libwebpush_pic.a is
# built too, for a program that links it in whole.

.include "${.CURDIR}/Makefile.inc"

LIB=		webpush
SHLIB_MAJOR=	1
SRCS=		webpush.c
INCS=		webpush.h
MAN=		libwebpush.3
MLINKS=		libwebpush.3 webpush_b64url.3 \
		libwebpush.3 webpush_unb64url.3 \
		libwebpush.3 webpush_encrypt.3 \
		libwebpush.3 webpush_vapid.3
INSTALL_PIC_ARCHIVE=	yes

CFLAGS+=	-I${.CURDIR} ${SSL_CFLAGS}
LDADD+=		${SSL_LDFLAGS} -lcrypto

# No mtree(8) hierarchy outside the source tree: make the directories
# first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${LIBDIR} \
	    ${DESTDIR}${INCLUDEDIR} ${DESTDIR}${MANDIR}3

.include <bsd.opts.mk>

SUBDIR.${MK_TESTS}+= tests

# The tests where they are built, not installed first: "all" as a
# dependency would not recurse, so it is a make of its own.
check: .PHONY
	@${MAKE} -C ${.CURDIR} all
	@cd ${.OBJDIR}/tests && kyua test -k Kyuafile

.include <bsd.lib.mk>

# make -j: the tests link this library, so build them after it.
all_subdir_tests: lib${LIB}_pic.a
