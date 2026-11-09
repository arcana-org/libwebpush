# libwebpush

The arithmetic of Web Push, in C on OpenSSL's libcrypto:

- **Message encryption** for one push subscription: RFC 8291, with the
  `aes128gcm` content coding of RFC 8188 (one record, record size 4096).
- **VAPID** (RFC 8292): the `Authorization: vapid t=..., k=...` header,
  an ES256 JWT signed with the application server's P-256 key.
- **base64url** without padding, as subscriptions and keys are written.

It speaks no HTTP: the caller posts the body it returns to the
subscription's endpoint, with libfetch, libcurl or whatever it has.
See libwebpush(3).

## Building

With FreeBSD's make(1) and bsd.*.mk; it needs nothing but base:

    make && make check
    make install [DESTDIR=dir] [PREFIX=/usr/local]

Build products go to `obj/`. `make check` runs the atf tests with
kyua(1) where they are built: RFC 8291's worked example (appendix A),
messages decrypted as a receiver would, the length limit, VAPID tokens
verified under their key, and RFC 4648's base64 vectors.
`WITHOUT_TESTS=yes` builds the library alone. `libwebpush_pic.a` is
built beside `libwebpush.so.1`, for a program that links it in whole.
OPENSSLINC and OPENSSLLIB name an OpenSSL other than base's.

## Example

    uint8_t *ua, *auth, *body;
    size_t ualen, authlen, len;
    char *hdr;

    ua = webpush_unb64url(p256dh, &ualen);
    auth = webpush_unb64url(authsecret, &authlen);
    /* check ualen == WEBPUSH_KEYLEN, authlen == WEBPUSH_AUTHLEN */
    webpush_encrypt(ua, auth, NULL, NULL, msg, msglen, &body, &len);
    hdr = webpush_vapid(vapid_key, "https://push.example.net",
        "mailto:admin@example.org", time(NULL));
    /* POST body with Authorization: hdr, Content-Encoding: aes128gcm,
     * and TTL. */

## License

BSD-2-Clause; see LICENSE.
