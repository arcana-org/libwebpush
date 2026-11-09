.include "${.CURDIR}/../Makefile.inc"

TESTSDIR=	${TESTSBASE}/libwebpush
ATF_TESTS_C=	webpush_test

# The library linked in whole: the tests run from the build tree.
CFLAGS+=	-I${.CURDIR}/.. ${SSL_CFLAGS}
LDADD+=		${.OBJDIR:H}/libwebpush_pic.a ${SSL_LDFLAGS} -lcrypto
DPADD+=		${.OBJDIR:H}/libwebpush_pic.a

# atf.test.mk only knows LDADD_atf_c inside the source tree; base ships
# atf-c as a private library with its header in /usr/include.
LDADD_atf_c=	-lprivateatf-c

# No mtree(8) hierarchy outside the source tree: make the directory
# first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
