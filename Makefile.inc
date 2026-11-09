# Settings shared by libwebpush and its tests.

.if !target(__<webpush.inc>__)
__<webpush.inc>__:

WP_TOP:=	${.PARSEDIR:tA}

# Build in obj/ at the top of the tree, mirroring it, never in the
# source directories; MAKEOBJDIRPREFIX or MAKEOBJDIR, when given, take
# precedence.
.if !defined(MAKEOBJDIRPREFIX) && !defined(MAKEOBJDIR)
.if ${.CURDIR:tA} == ${WP_TOP}
_WP_OBJDIR=	${WP_TOP}/obj
.else
_WP_OBJDIR=	${WP_TOP}/obj/${.CURDIR:tA:S,^${WP_TOP}/,,}
.endif
.if ${.OBJDIR:tA} != ${_WP_OBJDIR}
__objdir!=	mkdir -p ${_WP_OBJDIR} && echo ${_WP_OBJDIR}
.OBJDIR:	${_WP_OBJDIR}
.endif
.endif

CSTD?=		c17
WARNS?=		6

PREFIX?=	/usr/local
LIBDIR?=	${PREFIX}/lib
SHLIBDIR?=	${LIBDIR}
INCLUDEDIR?=	${PREFIX}/include
MANDIR?=	${PREFIX}/share/man/man
TESTSBASE?=	${PREFIX}/tests

# OpenSSL's libcrypto: base's unless OPENSSLINC and OPENSSLLIB (the
# port's USES=ssl) name another.
.if defined(OPENSSLINC) && ${OPENSSLINC} != "/usr/include"
SSL_CFLAGS=	-I${OPENSSLINC}
.endif
.if defined(OPENSSLLIB) && ${OPENSSLLIB} != "/usr/lib"
SSL_LDFLAGS=	-L${OPENSSLLIB}
.endif
SSL_CFLAGS?=
SSL_LDFLAGS?=

.endif
