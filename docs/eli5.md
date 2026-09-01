# Q-Cap Explained Simply

Imagine you have a locked lunchbox.

You can copy the lunchbox, move it around, or put it on a shelf where anyone can download it. But the food inside stays locked unless you are one of the people it was locked for.

That is the current Q-Cap prototype: a single `.qcap` file that carries encrypted data plus the information needed to check whether the file was changed.

## What Works Today

The current prototype can:

- put files into one `.qcap` package
- encrypt those files for a recipient
- sign the package manifest
- check whether the payload was changed
- issue a signed permission slip called a capability token
- export only the files allowed by that token
- optionally check whether the token was revoked
- publish and fetch packages through a small local development registry

## The Seal

Q-Cap uses cryptographic signatures and a Merkle root as tamper-evident seals.

If someone changes the payload or the manifest, verification should fail.

That does not prove the data is true or legal to use. It proves the package has not changed since it was signed.

## The Lock

Sealed Q-Cap packages encrypt payload files for intended recipients.

The current prototype uses one package content key. That means the cryptography controls who can decrypt the package, while the CLI controls which allowed paths get exported.

So the honest simple version is:

> The lock controls who can open the package. The permission slip controls what the current tool will export.

It is not yet hard cryptographic per-file sharing.

## The Permission Slip

A capability token is a separate signed JSON file.

It says something like:

> For this exact package, this recipient may read files under `reports/*` until this expiry time.

The current CLI checks that:

- the permission slip is signed by the same key that signed the package
- it is for the same package
- it names the recipient
- it has not expired
- it allows the requested path
- it has not been revoked, if revocation checking is provided

## What Does Not Exist Yet

Older explanations talked about a much richer future version of Q-Cap. Those ideas are not implemented in the current MVP.

Not implemented yet:

- tiny programs inside the file
- WASM lenses
- AI/vector indexes
- privacy budget meters
- policy graphs
- embedded Trust Anchors
- COSE tokens
- post-quantum/hybrid crypto
- full offline multi-agency governance

Those may be future design directions, but they are not current behavior.

## Simple Summary

Q-Cap is currently a prototype locked lunchbox for data: it can encrypt files, prove they were not changed, and use signed permission slips to control what the CLI exports.

The bigger vision is artifact-centric governance, but the current code is still an MVP.
