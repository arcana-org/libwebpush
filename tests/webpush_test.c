/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * libwebpush against what the standards print: the worked example of
 * RFC 8291, section 5 and appendix A; a message of its own key and salt
 * that the receiver of that example decrypts; a VAPID token that
 * verifies under its own key; base64url as RFC 4648 has it.
 */

#define	OPENSSL_SUPPRESS_DEPRECATED

#include <sys/types.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>

#include <atf-c.h>

#include "webpush.h"

/* RFC 8291, appendix A. */
#define	UA_PRIV	"q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
#define	UA_PUB	"BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4" \
		"bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
#define	AS_PRIV	"yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"
#define	AS_PUB	"BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmY" \
		"WAmS6TlzAC8wEqKK6PBru3jl7A8"
#define	AUTH	"BTBZMqHH6r4Tts7J_aSIgg"
#define	SALT	"DGv6ra1nlYgDCS1FRnbzlw"
#define	PLAIN	"When I grow up, I want to be a watermelon"

static uint8_t *
unb64(const char *s, size_t want)
{
	uint8_t	*raw;
	size_t	 len;

	ATF_REQUIRE((raw = webpush_unb64url(s, &len)) != NULL);
	ATF_REQUIRE_EQ(want, len);
	return (raw);
}

/* A P-256 key from its private scalar, as the RFC gives them. */
static EVP_PKEY *
key_of(const char *b64priv)
{
	EC_KEY		*ec;
	EC_POINT	*pub;
	EVP_PKEY	*pk;
	BIGNUM		*d;
	uint8_t		*raw;

	raw = unb64(b64priv, 32);
	ATF_REQUIRE((ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) !=
	    NULL);
	ATF_REQUIRE((d = BN_bin2bn(raw, 32, NULL)) != NULL);
	ATF_REQUIRE((pub = EC_POINT_new(EC_KEY_get0_group(ec))) != NULL);
	ATF_REQUIRE(EC_POINT_mul(EC_KEY_get0_group(ec), pub, d, NULL, NULL,
	    NULL) == 1);
	ATF_REQUIRE(EC_KEY_set_private_key(ec, d) == 1);
	ATF_REQUIRE(EC_KEY_set_public_key(ec, pub) == 1);
	ATF_REQUIRE((pk = EVP_PKEY_new()) != NULL);
	ATF_REQUIRE(EVP_PKEY_assign_EC_KEY(pk, ec) == 1);
	EC_POINT_free(pub);
	BN_free(d);
	free(raw);
	return (pk);
}

static void
hkdf(const uint8_t *salt, size_t saltlen, const uint8_t *ikm, size_t ikmlen,
    const char *info, size_t infolen, uint8_t *out, size_t outlen)
{
	uint8_t		prk[32], t[32], buf[256];
	unsigned int	n;

	ATF_REQUIRE(HMAC(EVP_sha256(), salt, (int)saltlen, ikm, ikmlen, prk,
	    &n) != NULL);
	memcpy(buf, info, infolen);
	buf[infolen] = 0x01;
	ATF_REQUIRE(HMAC(EVP_sha256(), prk, sizeof(prk), buf, infolen + 1, t,
	    &n) != NULL);
	memcpy(out, t, outlen);
}

/*
 * The receiver's side, written here from the RFCs: body decrypted with
 * the subscription's private key and auth secret; its length, or -1.
 */
static int
decrypt(EVP_PKEY *ua, const uint8_t *auth, const uint8_t *body, size_t len,
    uint8_t *plain)
{
	EVP_PKEY	*peer;
	EVP_PKEY_CTX	*dctx;
	EVP_CIPHER_CTX	*cctx;
	unsigned char	*ua_pub;
	uint8_t		 secret[32], ikm[32], cek[16], nonce[12], info[160];
	uint8_t		 tag[16];
	size_t		 slen, n, clen;
	int		 out, fin;

	ATF_REQUIRE(len >= 86 + 16 + 1);
	ATF_REQUIRE_EQ(4096, (body[16] << 24) | (body[17] << 16) |
	    (body[18] << 8) | body[19]);
	ATF_REQUIRE_EQ(65, body[20]);
	ATF_REQUIRE((peer = EVP_PKEY_new()) != NULL);
	ATF_REQUIRE(EVP_PKEY_copy_parameters(peer, ua) == 1);
	ATF_REQUIRE(EVP_PKEY_set1_encoded_public_key(peer, body + 21, 65) ==
	    1);
	ATF_REQUIRE((dctx = EVP_PKEY_CTX_new(ua, NULL)) != NULL);
	ATF_REQUIRE(EVP_PKEY_derive_init(dctx) == 1);
	ATF_REQUIRE(EVP_PKEY_derive_set_peer(dctx, peer) == 1);
	slen = sizeof(secret);
	ATF_REQUIRE(EVP_PKEY_derive(dctx, secret, &slen) == 1);
	ATF_REQUIRE_EQ(65, EVP_PKEY_get1_encoded_public_key(ua, &ua_pub));

	n = sizeof("WebPush: info");
	memcpy(info, "WebPush: info", n);
	memcpy(info + n, ua_pub, 65);
	memcpy(info + n + 65, body + 21, 65);
	hkdf(auth, 16, secret, 32, (const char *)info, n + 130, ikm, 32);
	hkdf(body, 16, ikm, 32, "Content-Encoding: aes128gcm",
	    sizeof("Content-Encoding: aes128gcm"), cek, 16);
	hkdf(body, 16, ikm, 32, "Content-Encoding: nonce",
	    sizeof("Content-Encoding: nonce"), nonce, 12);

	clen = len - 86 - 16;
	ATF_REQUIRE((cctx = EVP_CIPHER_CTX_new()) != NULL);
	ATF_REQUIRE(EVP_DecryptInit_ex(cctx, EVP_aes_128_gcm(), NULL, cek,
	    nonce) == 1);
	ATF_REQUIRE(EVP_DecryptUpdate(cctx, plain, &out, body + 86,
	    (int)clen) == 1);
	memcpy(tag, body + len - 16, sizeof(tag));
	ATF_REQUIRE(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, 16, tag) ==
	    1);
	if (EVP_DecryptFinal_ex(cctx, plain + out, &fin) != 1)
		out = -1;
	EVP_CIPHER_CTX_free(cctx);
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(peer);
	OPENSSL_free(ua_pub);
	/* The last record's delimiter, then nothing but padding. */
	if (out > 0) {
		while (out > 0 && plain[out - 1] == 0)
			out--;
		ATF_REQUIRE(out > 0 && plain[out - 1] == 0x02);
		out--;
	}
	return (out);
}

ATF_TC_WITHOUT_HEAD(rfc8291);
ATF_TC_BODY(rfc8291, tc)
{
	static const char want[] =
	    "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml"
	    "mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT"
	    "pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";
	EVP_PKEY	*as;
	uint8_t		*ua, *auth, *salt, *out;
	char		*got, *aspub;
	unsigned char	*enc;
	size_t		 outlen;

	as = key_of(AS_PRIV);
	/* The key made from the scalar is the one the RFC names. */
	ATF_REQUIRE_EQ(65, EVP_PKEY_get1_encoded_public_key(as, &enc));
	aspub = webpush_b64url(enc, 65);
	ATF_CHECK_STREQ(AS_PUB, aspub);
	ua = unb64(UA_PUB, WEBPUSH_KEYLEN);
	auth = unb64(AUTH, WEBPUSH_AUTHLEN);
	salt = unb64(SALT, WEBPUSH_SALTLEN);

	ATF_REQUIRE(webpush_encrypt(ua, auth, as, salt,
	    (const uint8_t *)PLAIN, strlen(PLAIN), &out, &outlen) == 0);
	got = webpush_b64url(out, outlen);
	ATF_CHECK_STREQ(want, got);

	free(got);
	free(out);
	free(aspub);
	free(ua);
	free(auth);
	free(salt);
	OPENSSL_free(enc);
	EVP_PKEY_free(as);
}

ATF_TC_WITHOUT_HEAD(random);
ATF_TC_BODY(random, tc)
{
	EVP_PKEY	*uakey;
	uint8_t		*ua, *auth, *out1, *out2, plain[4096];
	size_t		 len1, len2;

	uakey = key_of(UA_PRIV);
	ua = unb64(UA_PUB, WEBPUSH_KEYLEN);
	auth = unb64(AUTH, WEBPUSH_AUTHLEN);

	/* A key and a salt of its own: not the same twice, of the same
	 * length, and the receiver reads it. */
	ATF_REQUIRE(webpush_encrypt(ua, auth, NULL, NULL,
	    (const uint8_t *)PLAIN, strlen(PLAIN), &out1, &len1) == 0);
	ATF_REQUIRE(webpush_encrypt(ua, auth, NULL, NULL,
	    (const uint8_t *)PLAIN, strlen(PLAIN), &out2, &len2) == 0);
	ATF_CHECK_EQ(len1, len2);
	ATF_CHECK_EQ(86 + strlen(PLAIN) + 1 + 16, len1);
	ATF_CHECK(memcmp(out1, out2, len1) != 0);
	ATF_REQUIRE_EQ((int)strlen(PLAIN), decrypt(uakey, auth, out1, len1,
	    plain));
	ATF_CHECK(memcmp(plain, PLAIN, strlen(PLAIN)) == 0);

	/* A byte changed is refused by the tag. */
	out1[100] ^= 1;
	ATF_CHECK_EQ(-1, decrypt(uakey, auth, out1, len1, plain));

	free(out1);
	free(out2);
	free(ua);
	free(auth);
	EVP_PKEY_free(uakey);
}

ATF_TC_WITHOUT_HEAD(limits);
ATF_TC_BODY(limits, tc)
{
	EVP_PKEY	*uakey;
	uint8_t		*ua, *auth, *big, *out, plain[4096];
	size_t		 len;

	uakey = key_of(UA_PRIV);
	ua = unb64(UA_PUB, WEBPUSH_KEYLEN);
	auth = unb64(AUTH, WEBPUSH_AUTHLEN);
	ATF_REQUIRE((big = calloc(1, WEBPUSH_MAXLEN + 1)) != NULL);
	memset(big, 'x', WEBPUSH_MAXLEN + 1);

	/* The longest message is 4096 bytes sent; one more is refused. */
	ATF_REQUIRE(webpush_encrypt(ua, auth, NULL, NULL, big, WEBPUSH_MAXLEN,
	    &out, &len) == 0);
	ATF_CHECK_EQ(4096, len);
	ATF_CHECK_EQ(WEBPUSH_MAXLEN, decrypt(uakey, auth, out, len, plain));
	free(out);
	out = NULL;
	ATF_CHECK_EQ(-1, webpush_encrypt(ua, auth, NULL, NULL, big,
	    WEBPUSH_MAXLEN + 1, &out, &len));
	ATF_CHECK(out == NULL);

	/* An empty one is a delimiter alone. */
	ATF_REQUIRE(webpush_encrypt(ua, auth, NULL, NULL, big, 0, &out,
	    &len) == 0);
	ATF_CHECK_EQ(86 + 1 + 16, len);
	ATF_CHECK_EQ(0, decrypt(uakey, auth, out, len, plain));
	free(out);
	out = NULL;

	/* A subscription key that is no point on the curve. */
	ua[1] ^= 1;
	ATF_CHECK_EQ(-1, webpush_encrypt(ua, auth, NULL, NULL,
	    (const uint8_t *)PLAIN, strlen(PLAIN), &out, &len));
	ATF_CHECK(out == NULL);

	free(big);
	free(ua);
	free(auth);
	EVP_PKEY_free(uakey);
}

ATF_TC_WITHOUT_HEAD(vapid);
ATF_TC_BODY(vapid, tc)
{
	EVP_PKEY	*key;
	EVP_MD_CTX	*md;
	ECDSA_SIG	*sig;
	uint8_t		*raw, *claims;
	unsigned char	*der, *pub;
	char		*hdr, *t, *k, *dot1, *dot2, *want, longsub[600];
	size_t		 len;
	int		 derlen;

	ATF_REQUIRE((key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")) !=
	    NULL);
	ATF_REQUIRE((hdr = webpush_vapid(key, "https://push.example",
	    "mailto:admin@console.example", 1700000000)) != NULL);
	ATF_REQUIRE(strncmp(hdr, "vapid t=", 8) == 0);
	t = hdr + 8;
	ATF_REQUIRE((k = strstr(t, ", k=")) != NULL);
	*k = '\0';
	k += 4;
	/* k is the key's public half. */
	ATF_REQUIRE_EQ(65, EVP_PKEY_get1_encoded_public_key(key, &pub));
	want = webpush_b64url(pub, 65);
	ATF_CHECK_STREQ(want, k);
	free(want);
	OPENSSL_free(pub);

	/* header.claims.signature; the claims say whom, until when, who. */
	ATF_REQUIRE((dot1 = strchr(t, '.')) != NULL);
	ATF_REQUIRE((dot2 = strchr(dot1 + 1, '.')) != NULL);
	*dot1 = '\0';
	ATF_REQUIRE((claims = webpush_unb64url(t, &len)) != NULL);
	claims[len] = '\0';
	ATF_CHECK_STREQ("{\"typ\":\"JWT\",\"alg\":\"ES256\"}", (char *)claims);
	free(claims);
	*dot1 = '.';
	*dot2 = '\0';
	ATF_REQUIRE((claims = webpush_unb64url(dot1 + 1, &len)) != NULL);
	claims[len] = '\0';
	ATF_CHECK_STREQ("{\"aud\":\"https://push.example\",\"exp\":1700043200,"
	    "\"sub\":\"mailto:admin@console.example\"}", (char *)claims);
	free(claims);

	/* The signature, r and s as they are, verifies under the key. */
	raw = unb64(dot2 + 1, 64);
	ATF_REQUIRE((sig = ECDSA_SIG_new()) != NULL);
	ATF_REQUIRE(ECDSA_SIG_set0(sig, BN_bin2bn(raw, 32, NULL),
	    BN_bin2bn(raw + 32, 32, NULL)) == 1);
	der = NULL;
	ATF_REQUIRE((derlen = i2d_ECDSA_SIG(sig, &der)) > 0);
	ATF_REQUIRE((md = EVP_MD_CTX_new()) != NULL);
	ATF_REQUIRE(EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, key) ==
	    1);
	ATF_CHECK_EQ(1, EVP_DigestVerify(md, der, (size_t)derlen,
	    (unsigned char *)t, strlen(t)));
	EVP_MD_CTX_free(md);
	OPENSSL_free(der);
	ECDSA_SIG_free(sig);
	free(raw);
	free(hdr);

	/* Claims too long for the token are refused, not cut short. */
	memset(longsub, 'a', sizeof(longsub) - 1);
	longsub[sizeof(longsub) - 1] = '\0';
	ATF_CHECK(webpush_vapid(key, "https://push.example", longsub,
	    1700000000) == NULL);
	EVP_PKEY_free(key);
}

ATF_TC_WITHOUT_HEAD(b64url);
ATF_TC_BODY(b64url, tc)
{
	/* RFC 4648, section 10, in base64url without its padding. */
	static const char *const vec[][2] = {
		{ "", "" }, { "f", "Zg" }, { "fo", "Zm8" }, { "foo", "Zm9v" },
		{ "foob", "Zm9vYg" }, { "fooba", "Zm9vYmE" },
		{ "foobar", "Zm9vYmFy" },
	};
	static const uint8_t bin[] = { 0xfb, 0xff, 0xbf };
	uint8_t		*raw;
	char		*s;
	size_t		 i, len;

	for (i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {
		ATF_REQUIRE((s = webpush_b64url(vec[i][0],
		    strlen(vec[i][0]))) != NULL);
		ATF_CHECK_STREQ(vec[i][1], s);
		free(s);
		ATF_REQUIRE((raw = webpush_unb64url(vec[i][1], &len)) !=
		    NULL);
		ATF_CHECK_EQ(strlen(vec[i][0]), len);
		ATF_CHECK(memcmp(raw, vec[i][0], len) == 0);
		free(raw);
	}
	/* - and _ where base64 has + and /; padding is taken too. */
	ATF_REQUIRE((s = webpush_b64url(bin, sizeof(bin))) != NULL);
	ATF_CHECK_STREQ("-_-_", s);
	free(s);
	ATF_REQUIRE((raw = webpush_unb64url("Zm8=", &len)) != NULL);
	ATF_CHECK_EQ(2, len);
	free(raw);
	/* What is not base64url. */
	ATF_CHECK(webpush_unb64url("Z", &len) == NULL);
	ATF_CHECK(webpush_unb64url("Zm9v!A", &len) == NULL);
	ATF_CHECK(webpush_unb64url("Zm 9v", &len) == NULL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, rfc8291);
	ATF_TP_ADD_TC(tp, random);
	ATF_TP_ADD_TC(tp, limits);
	ATF_TP_ADD_TC(tp, vapid);
	ATF_TP_ADD_TC(tp, b64url);
	return (atf_no_error());
}
