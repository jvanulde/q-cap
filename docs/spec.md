# Q-Cap Preview Format Specification

This document specifies the wire formats implemented by Q-Cap `0.2.0`. It is
the interoperability reference for the current prototype, not a stable public
standard. A future schema revision may replace the signing encodings, identity
model, path policy, or encryption profile described here.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are to be interpreted as described by RFC 2119 and RFC 8174 when,
and only when, they appear in all capitals.

## 1. Scope and terminology

- **archive**: one ZIP file with a `.qcap` extension.
- **payload path**: the UTF-8 path below the archive's `payload/` directory,
  without the `payload/` prefix.
- **manifest bytes**: the exact bytes stored in `manifest.json`.
- **archive signer**: the Ed25519 public key in
  `signatures/manifest.sig.json`.
- **identity id**: the first 16 lowercase hexadecimal characters of an
  identity's Ed25519 public key. This is a prototype display identifier, not a
  collision-resistant principal identifier.
- **issuer**: the party that signs an archive, capability, or revocation list.
  In the current trust model, the full archive-signing public key is the trust
  anchor; the manifest's short `issuer` string is not.

All hexadecimal encodings written by Q-Cap use lowercase ASCII without a
`0x` prefix. Unless a section says otherwise, JSON strings are compared
byte-for-byte after UTF-8 decoding; comparisons are case-sensitive and no
Unicode normalization is performed.

## 2. Versioning and compatibility

`schema_version` versions the serialized Q-Cap document, independently of the
Rust, CLI, registry, Helm chart, or SDK package versions.

The current writers produce two archive profiles:

| Schema | Writer | Payload | Required signature algorithm |
| --- | --- | --- | --- |
| `0.1.0` | `qcap pack` | plaintext | `ed25519:manifest` |
| `0.2.0` | `qcap seal` | XChaCha20-Poly1305 ciphertext | `ed25519:manifest` |

Older checked-in `0.1.0` seed archives use the legacy `ed25519` algorithm,
which signs only the Merkle-root string. The Go registry accepts those seeds
for backward compatibility. The current Rust CLI accepts only
`ed25519:manifest`; it cannot verify the legacy seeds.

Current readers deserialize additive manifest fields using defaults, but they
do not consistently reject unknown schema versions. Producers MUST emit one
of the profiles above. Consumers MUST NOT infer compatibility merely because
JSON deserialization succeeds.

Until a stable format is declared, version changes follow this preview policy:

- a change to signed bytes, path semantics, cryptographic processing, or a
  required field increments the schema version;
- additive optional fields require an explicit compatibility decision;
- editorial changes do not change `schema_version`;
- package SemVer changes do not automatically change `schema_version`.

## 3. Archive container

The archive media type is `application/qcap+zip`. The implemented layout is:

```text
manifest.json
payload/<payload-path>
meta/
signatures/
signatures/manifest.sig.json
```

`manifest.json` and `signatures/manifest.sig.json` MUST each occur exactly
once. An archive MUST NOT contain duplicate normalized entry names. Files MAY
appear below `meta/`; their semantics are application-defined and they are not
covered by the payload Merkle root. Entries outside the four top-level names
shown above are invalid.

The current writer uses ZIP Deflate. ZIP compression method and entry order
are not security properties. Consumers MUST enforce resource limits before
decompression; the development registry currently limits the entry count,
individual manifest/signature sizes, and total uncompressed size.

### 3.1 Payload-path grammar

The interoperable producer grammar is:

```abnf
payload-path = segment *("/" segment)
segment      = 1*segment-char
segment-char = %x21-2E / %x30-39 / %x3B-5B / %x5D-7E /
               UTF8-2 / UTF8-3 / UTF8-4
```

`UTF8-2`, `UTF8-3`, and `UTF8-4` are the multibyte UTF-8 productions from
RFC 3629. The ASCII ranges above exclude control characters, `/`, `:`, `\`,
and DEL.

Additional rules:

1. A path MUST be valid UTF-8 and relative.
2. Empty segments, `.` segments, and `..` segments are forbidden.
3. A path MUST use `/`, never `\`, as its separator.
4. A path MUST NOT begin or end with `/`.
5. A path MUST NOT contain a platform drive or other path prefix.
6. Distinct UTF-8 byte sequences are distinct paths. Consumers MUST NOT apply
   case folding or Unicode normalization during hashing or authorization.

These rules define the portable subset accepted by both the Rust CLI and Go
registry. The Rust writer derives paths from the local filesystem, so
producers are responsible for avoiding platform-specific or non-portable
names.

## 4. Manifest

`manifest.json` is a UTF-8 JSON object. The current Rust writer emits pretty
JSON in the field order listed below. Field order and whitespace have no JSON
meaning, but they do matter to the current manifest signature because the
exact stored bytes are signed.

| Field | JSON type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Archive profile version. |
| `merkle_root` | string | yes | `blake3:` followed by 64 lowercase hex characters. |
| `issuer` | string or null | yes | Prototype short issuer id; sealed writers use the first 16 characters of the archive signer's public key. |
| `created_at` | string | yes | `unix-seconds:` followed by an unsigned decimal timestamp. |
| `metadata` | object | yes | Application metadata; Q-Cap does not interpret its members. |
| `package_id` | string or null | default `null` | Sealed-package id, written as `qcap_` plus 32 lowercase hex characters. |
| `encrypted` | boolean | default `false` | Whether payload entries contain ciphertext. |
| `files` | array | default `[]` | Encrypted payload metadata, one entry per sealed payload file. |
| `recipients` | array | default `[]` | Content-key wrapping stanzas. |
| `algorithms` | array of strings | default `[]` | Descriptive algorithm identifiers. |

Legacy manifests may omit fields that have defaults. Current writers serialize
all fields, including defaults. Unknown fields are ignored by the current Rust
deserializer and therefore MUST NOT be treated as security-critical unless a
future schema version defines their validation.

### 4.1 Plain manifest example (`0.1.0`)

```json
{
  "schema_version": "0.1.0",
  "merkle_root": "blake3:2a64e6e624c84d63b96f21cc0825bb0016f70edadb1d735f623955a4c195313c",
  "issuer": null,
  "created_at": "unix-seconds:1764954772",
  "metadata": {},
  "package_id": null,
  "encrypted": false,
  "files": [],
  "recipients": [],
  "algorithms": []
}
```

### 4.2 Sealed manifest fields (`0.2.0`)

Each `files` entry has this shape:

| Field | Type | Encoding |
| --- | --- | --- |
| `path` | string | payload path governed by section 3.1 |
| `size` | unsigned integer | ciphertext length in bytes, including the AEAD tag |
| `nonce` | string | 24-byte XChaCha20 nonce as 48 hex characters |
| `ciphertext_hash` | string | `blake3:` plus the 32-byte ciphertext digest |

Each `recipients` entry has this shape:

| Field | Type | Encoding |
| --- | --- | --- |
| `recipient` | string | recipient X25519 public key, 32 bytes as 64 hex characters |
| `ephemeral_public_key` | string | ephemeral X25519 public key, 32 bytes as 64 hex characters |
| `nonce` | string | 24-byte key-wrap nonce as 48 hex characters |
| `wrapped_key` | string | encrypted 32-byte content key plus 16-byte tag, as 96 hex characters |
| `algorithm` | string | `x25519-blake3-xchacha20poly1305` |

A sealed manifest sets `encrypted` to `true`, contains one `files` entry for
every payload file, and contains at least one recipient stanza. The writer's
current `algorithms` array is:

```json
[
  "xchacha20poly1305:file",
  "x25519-blake3-xchacha20poly1305:keywrap",
  "ed25519:signature"
]
```

The array is descriptive. Verifiers select algorithms from the fields that
directly govern an operation, not from this array.

### 4.3 Sealed manifest example (`0.2.0`)

This complete shape example uses placeholder cryptographic values and is not a
verification test vector:

```json
{
  "schema_version": "0.2.0",
  "merkle_root": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "issuer": "03a107bff3ce10be",
  "created_at": "unix-seconds:1764954772",
  "metadata": {
    "title": "Q-Cap MVP sealed package"
  },
  "package_id": "qcap_00112233445566778899aabbccddeeff",
  "encrypted": true,
  "files": [
    {
      "path": "reports/summary.txt",
      "size": 28,
      "nonce": "000000000000000000000000000000000000000000000000",
      "ciphertext_hash": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ],
  "recipients": [
    {
      "recipient": "1111111111111111111111111111111111111111111111111111111111111111",
      "ephemeral_public_key": "2222222222222222222222222222222222222222222222222222222222222222",
      "nonce": "333333333333333333333333333333333333333333333333",
      "wrapped_key": "444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444",
      "algorithm": "x25519-blake3-xchacha20poly1305"
    }
  ],
  "algorithms": [
    "xchacha20poly1305:file",
    "x25519-blake3-xchacha20poly1305:keywrap",
    "ed25519:signature"
  ]
}
```

## 5. Payload Merkle root

The root covers every regular file below `payload/`. Directory entries,
`manifest.json`, `meta/`, and `signatures/` are excluded. For sealed archives,
the payload bytes are ciphertext.

For each payload file:

1. Remove the `payload/` prefix to obtain `payload-path`.
2. Encode the path as UTF-8 without normalization.
3. Compute the 32-byte leaf digest:

   ```text
   BLAKE3(payload_path_utf8 || 0x00 || file_bytes)
   ```

4. The current implementation sorts local filesystem paths using the host
   platform's path ordering before converting separators to `/`.
5. At each tree level, hash adjacent raw 32-byte digests:

   ```text
   BLAKE3(left_digest || right_digest)
   ```

6. Promote an unpaired final digest unchanged to the next level.
7. Encode the final digest as `blake3:<lowercase-hex>`.

The root for an empty payload is `blake3:` followed by the BLAKE3 digest of
the empty byte string.

The preview schema does not yet define a platform-independent ordering for all
Unicode path sets. Portable producers SHOULD use names whose host-path order is
the same as bytewise UTF-8 order (ASCII names satisfy this on supported hosts).
A future schema should sort normalized UTF-8 path bytes directly.

## 6. Manifest signature

`signatures/manifest.sig.json` is a UTF-8 JSON object:

```json
{
  "merkle_root": "blake3:2a64e6e624c84d63b96f21cc0825bb0016f70edadb1d735f623955a4c195313c",
  "signature": "ca3c1db84eb5b37359b79a81ba86ec617601ac2c551f43165a2c79824ba844a23d6ac91e41940494ee47cc13d666ca5b666a988b26cc5863c5309f0f80b1fa05",
  "public_key": "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  "algorithm": "ed25519:manifest"
}
```

The signature value above illustrates the encoding and is not a verification
test vector.

| Field | Requirement |
| --- | --- |
| `merkle_root` | MUST equal `manifest.merkle_root`. |
| `signature` | 64-byte Ed25519 signature as 128 hex characters. |
| `public_key` | 32-byte Ed25519 public key as 64 hex characters. |
| `algorithm` | `ed25519:manifest` for current archives. |

For `ed25519:manifest`, the Ed25519 message is exactly `manifest bytes`. No
JSON canonicalization is performed. Reformatting, reordering keys, changing a
line ending, or semantically equivalent reserialization invalidates the
signature. Consumers MUST retain the original manifest bytes for signature
verification.

Legacy `ed25519` bundles use the UTF-8 bytes of `merkle_root` as the message.
That legacy mode does not authenticate other manifest fields and MUST NOT be
used for new archives.

## 7. Sealed-payload encryption

A sealed package contains one random 32-byte content key shared by all payload
files.

For each file, the producer:

1. generates a random 24-byte nonce;
2. uses XChaCha20-Poly1305 with the package content key;
3. uses `payload-path` UTF-8 bytes as associated data;
4. writes the resulting ciphertext and 16-byte tag to `payload/<path>`;
5. records the ciphertext length, nonce, and BLAKE3 ciphertext hash in
   `manifest.files`.

For each recipient, the producer:

1. generates an ephemeral X25519 key pair;
2. computes the 32-byte X25519 shared secret with the recipient public key;
3. derives the wrapping key as:

   ```text
   BLAKE3("qcap-wrap-key-v1" || shared_secret || package_id_utf8)
   ```

4. generates a random 24-byte nonce;
5. encrypts the 32-byte content key with XChaCha20-Poly1305, using
   `package_id` UTF-8 bytes as associated data;
6. stores the ephemeral public key, nonce, and wrapped key in the recipient
   stanza.

The current format provides package-level confidentiality, not cryptographic
per-path compartmentalization: any recipient that unwraps the content key can
decrypt every payload ciphertext if it bypasses the CLI's path checks.

## 8. Capability token

Capabilities are separate UTF-8 JSON files. They are signed prototype tokens,
not macaroons and not COSE tokens.

```json
{
  "cap_root": "blake3:2a64e6e624c84d63b96f21cc0825bb0016f70edadb1d735f623955a4c195313c",
  "allow": "read;path=reports/*;aud=03a107bff3ce10be",
  "expires": "unix-seconds:4102444800",
  "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "public_key": "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  "algorithm": "ed25519"
}
```

The all-zero signature above is illustrative and does not verify.

| Field | Requirement |
| --- | --- |
| `cap_root` | MUST equal the target archive's Merkle root. |
| `allow` | Prototype authorization string described below. |
| `expires` | `unix-seconds:<unsigned-decimal>`. |
| `signature` | 64-byte Ed25519 signature as 128 hex characters. |
| `public_key` | Full 32-byte issuer Ed25519 public key as 64 hex characters. |
| `algorithm` | `ed25519`. |

The signed message is the UTF-8 encoding of:

```text
cap_root || "|" || allow || "|" || expires
```

The current writer emits `allow` as:

```abnf
allow       = operation ";path=" path-pattern ";aud=" identity-id
operation   = "read"
identity-id = 16HEXDIG
```

Values are not escaped. `|`, `;`, carriage return, and line feed therefore
MUST NOT occur in producer-supplied values. The current parser defaults a
missing path to `*`, requires a non-empty audience, ignores unknown caveats,
and uses the last occurrence of a repeated `path` or `aud` caveat. Producers
MUST use the canonical order above; consumers SHOULD reject non-canonical or
ambiguous forms until structured capability signing replaces this encoding.

### 8.1 Path-pattern matching

The current matcher applies these rules in order:

1. `*` matches every path.
2. A pattern equal to the candidate matches that candidate.
3. A pattern ending in `*` matches candidates beginning with the preceding
   bytes.
4. Otherwise, a pattern beginning with `*` matches candidates ending with the
   following bytes.
5. No other pattern matches.

Matching is case-sensitive. `/` has no special wildcard behavior. There is no
escaping, recursive-glob operator, character class, deny rule, or policy
precedence. A pattern containing both a leading and trailing `*` does not act
as a contains match because the suffix-wildcard rule is evaluated first.

`qcap open` additionally requires the capability signer to equal the archive
signer, the operation to be `read`, the audience to equal the local identity
id, the expiry to be valid and not elapsed, and at least one path to match.

## 9. Revocation list

Revocation lists are separate UTF-8 JSON documents with media type
`application/qcap-revocations+json`:

```json
{
  "schema_version": "0.1.0",
  "revoked": [
    {
      "cap_root": "blake3:2a64e6e624c84d63b96f21cc0825bb0016f70edadb1d735f623955a4c195313c",
      "capability_signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "revoked_at": "unix-seconds:1764955000",
      "reason": "superseded"
    }
  ],
  "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
  "public_key": "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  "algorithm": "ed25519"
}
```

The all-zero signatures above are illustrative and do not verify.

The signed message is built in array order. It begins with:

```text
schema_version=<schema_version>
```

Each revoked entry appends one LF (`0x0a`) and:

```text
cap_root|capability_signature|revoked_at|reason
```

The Ed25519 signature covers the resulting UTF-8 bytes. The entry order is
therefore significant. Producer values MUST NOT contain `|`, carriage return,
or line feed. Revocation matches when both `cap_root` and
`capability_signature` equal the presented capability.

Revocation is soft and opt-in. `qcap open` checks it only when a revocation
file or URL is supplied. The list signer must equal the archive signer. The
format currently has no sequence number, validity interval, freshness proof,
or rollback protection.

The registry stores lists at:

```text
/revocations/<full-ed25519-public-key>/revocations.json
```

On upload, the path key must equal the list's `public_key` and the signature
must verify.

## 10. Trust and identity rules

The current CLI uses these bindings:

1. The manifest signature's full Ed25519 `public_key` is the archive signer.
2. A capability is trusted only when its `public_key` equals the archive
   signer's full key.
3. A revocation list is trusted only when its `public_key` equals the archive
   signer's full key.
4. A recipient stanza identifies a decrypting identity by its full X25519
   public key.
5. A capability audience identifies the local identity by the first 16 hex
   characters of its Ed25519 public key.

The manifest's `issuer` is signed metadata, but the verifier does not derive or
validate it against the archive signer's key. The short identity id is also
not collision-resistant. Neither value is suitable as a stable federated
identity or external trust anchor. Key rotation, multiple authorized issuers,
certification, delegation, and trust-anchor discovery are not defined by this
preview format.

The manifest signature is self-contained: it proves integrity relative to the
embedded public key, but it does not prove who controls that key. Authentic
provenance requires an external, authenticated binding to the full public key.

## 11. Validation procedure

A conforming current-profile verifier SHOULD perform these checks before
exposing payload bytes:

1. Apply ZIP entry-count and uncompressed-size limits.
2. Reject unsafe, duplicate, or out-of-layout archive paths.
3. Read and retain the exact `manifest.json` bytes.
4. Parse the manifest and reject unsupported schema/profile combinations.
5. Parse `signatures/manifest.sig.json`; verify field encodings and algorithm.
6. Verify the signature over the exact manifest bytes.
7. Recompute the payload Merkle root and compare it with both root fields.
8. For sealed archives, validate every file/stanza field before decrypting.
9. Verify capability signature, archive binding, signer binding, operation,
   audience, expiry, and path authorization.
10. If revocation input is configured, verify its signer and signature and
    reject a matching revoked capability.
11. Decrypt only matched files, verify each ciphertext hash, and write only
    through path-safe extraction.

The registry validates archive structure, required manifest fields, manifest
signature, and equality between the manifest and signature-bundle root fields
before persistence. It does not decrypt payloads, recompute the payload Merkle
tree, or evaluate capabilities.

## 12. Known compatibility and security limits

- The format, CLI output, registry API, and SDK interfaces remain unstable.
- Exact-byte manifest signing prevents semantic JSON reserialization.
- Capability and revocation signing use delimiter encodings without escaping.
- Path matching is a minimal string matcher, not a general glob language.
- One content key protects the entire sealed payload.
- Revocation lookup is optional and has no freshness or rollback protection.
- Local identity files contain unencrypted private key material.
- The registry is a single-replica development service without production
  reader authorization, namespaces, immutable valid uploads, or audit logs.
- The Rust CLI and Go registry do not yet have identical legacy-signature or
  archive-structure acceptance rules.

These limits are part of the current compatibility posture. Implementations
MUST NOT present this preview as a hardened or stable security format.
