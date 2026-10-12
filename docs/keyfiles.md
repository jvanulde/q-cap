# Encrypted identity keyfiles

`qcap init` creates an encrypted identity file. The Ed25519 signing seed and
X25519 encryption secret are serialized together, encrypted with
XChaCha20-Poly1305, and never written as plaintext JSON fields.

The encryption key is derived from the identity passphrase with Argon2id
version 19 using a unique 16-byte salt, 64 MiB of memory, 3 passes, 4 lanes,
and a 32-byte output. These are the second recommended parameters from
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4). The keyfile
records its KDF parameters so a future release can raise them without making
existing identities unreadable. Q-Cap bounds parameters before allocating
memory when it opens a keyfile.

The identity name and public keys remain visible. They are authenticated as
associated data, and Q-Cap checks that decrypted private keys reproduce the
stored public keys before using them.

## Supplying a passphrase

In an interactive terminal, `qcap init` and commands that need a private key
prompt without echoing the passphrase. `qcap init` asks for confirmation.

Automation can use a file:

```bash
printf '%s' 'replace-with-a-strong-passphrase' > identity.passphrase
chmod 600 identity.passphrase

qcap init --name issuer --out issuer.identity.json \
  --passphrase-file identity.passphrase
qcap seal payload/ --issuer issuer.identity.json \
  --recipient recipient.identity.json --out dataset.qcap \
  --passphrase-file identity.passphrase
```

`QCAP_KEY_PASSPHRASE` is also supported for controlled automation. Environment
variables can be exposed by process inspection, logs, or inherited child
processes, so prefer an access-controlled passphrase file or interactive prompt.
Never commit either the keyfile or its passphrase file.

`--passphrase-file` applies to the private identity used by `pack`, `seal`,
`grant`, `open`, or `revoke`. Reading a recipient's public key during `seal`
does not require that recipient's passphrase.

## Compatibility and limits

Q-Cap continues to read legacy plaintext identity JSON for migration, but
`qcap init` no longer creates it. Move existing plaintext
identities to secure storage and replace them with newly generated encrypted
identities; there is not yet an in-place migration command.

Encrypted local files reduce the impact of accidental file disclosure. They do
not replace a strong passphrase, host security, memory protection, key rotation,
backup procedures, or KMS/HSM-backed production keys. The legacy `pack --key`
raw seed-file input also remains available for compatibility and must be
protected separately.
