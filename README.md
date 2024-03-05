# SSH Sig

[![CI](https://github.com/wiktor-k/ssh-browser-test/actions/workflows/ci.yml/badge.svg)](https://github.com/wiktor-k/ssh-browser-test/actions/workflows/ci.yml)

Provides SSH signature parser and verifier for
[SSH file signatures](https://www.agwa.name/blog/post/ssh_signatures).

SSH signatures allow signing arbitrary files and can be used for
[signing git commits and tags](https://blog.dbrgn.ch/2021/11/16/git-ssh-signatures/).

All features are implemented using pure TypeScript and built-in
[SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto).

Since [`Ed25519` public keys](https://wicg.github.io/webcrypto-secure-curves/)
are
[not yet widely deployed](https://caniuse.com/mdn-api_subtlecrypto_verify_ed25519)
this package allows supplying custom `SubtleCrypto` implementation, such as
[`webcrypto-ed25519`](https://github.com/jacobbubu/webcrypto-ed25519).

## Creating SSH signatures

SSH signatures can be created using [OpenSSH](https://www.openssh.com/)'s
[`ssh-keygen`](https://man.archlinux.org/man/ssh-keygen.1):

```sh
ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file file_to_sign
```

This will create a detached signature in the `file_to_sign.sig` file.

## Supported algorithms

The following algorithms are supported at this time:

- RSA
- ed25519
- NIST P-256

If you would like to see a different signing algorithm supported please
[file an issue](https://github.com/wiktor-k/ssh-sig/issues/new) attaching both
the SSH signature and the file that was signed.

## Examples

The following example verifies an `ed25519` signature against provided data:

```typescript
import { assertEquals } from "https://deno.land/std@0.217.0/assert/mod.ts";
import { verify } from "./index.ts";

const signature = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgscJcEliU8+Su3ZZjI/dJmgzHje
UMEHlAAuMTvrYRCVwAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAECQkGDrATymoR1tunbphepkXiLGAMcF+Eca1EL3KpidzNYSTJ/smLYVw2elXq3K/l
dnvxJddvs2Z/x5En43hQIB
-----END SSH SIGNATURE-----`;

const valid = await verify(
  crypto.subtle, // bring your own SubtleCrypto
  signature, // detached signature
  "this is signed data\n", // signed data
);

assertEquals(valid, true, "signature is valid");
```

Signatures can also be parsed before verification. Since signatures contain
public keys it's also possible to export the public key in the SSH format:

```typescript
import { assertEquals } from "https://deno.land/std@0.217.0/assert/mod.ts";
import { verify } from "./index.ts";
import { parse } from "./sig_parser.ts";

const signature = parse(`-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgscJcEliU8+Su3ZZjI/dJmgzHje
UMEHlAAuMTvrYRCVwAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAECQkGDrATymoR1tunbphepkXiLGAMcF+Eca1EL3KpidzNYSTJ/smLYVw2elXq3K/l
dnvxJddvs2Z/x5En43hQIB
-----END SSH SIGNATURE-----`);

const valid = await verify(
  crypto.subtle, // bring your own SubtleCrypto
  signature, // detached signature
  "this is signed data\n", // signed data
);

assertEquals(valid, true, "signature is valid");
assertEquals(
  `${signature.publickey}`,
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHCXBJYlPPkrt2WYyP3SZoMx43lDBB5QALjE762EQlc",
  "signing key",
);
```

## License

This project is licensed under the
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be licensed as above, without any additional terms or conditions.
