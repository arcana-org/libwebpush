/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

#ifndef WEBPUSH_H
#define	WEBPUSH_H

#include <sys/cdefs.h>
#include <sys/types.h>

#include <stdint.h>
#include <time.h>

#include <openssl/evp.h>

#define	WEBPUSH_KEYLEN	65	/* a subscription's p256dh: a P-256 point */
#define	WEBPUSH_AUTHLEN	16	/* a subscription's auth secret */
#define	WEBPUSH_SALTLEN	16	/* a message's salt */
#define	WEBPUSH_MAXLEN	3993	/* the longest message: 4096 bytes sent */

__BEGIN_DECLS
char		*webpush_b64url(const void *, size_t);
uint8_t		*webpush_unb64url(const char *, size_t *);
int		 webpush_encrypt(const uint8_t *, const uint8_t *, EVP_PKEY *,
		    const uint8_t *, const uint8_t *, size_t, uint8_t **,
		    size_t *);
char		*webpush_vapid(EVP_PKEY *, const char *, const char *, time_t);
__END_DECLS

#endif /* !WEBPUSH_H */
