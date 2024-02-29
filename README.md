# SSH Sig

[![CI](https://github.com/wiktor-k/ssh-browser-test/actions/workflows/ci.yml/badge.svg)](https://github.com/wiktor-k/ssh-browser-test/actions/workflows/ci.yml)

Provides SSH signature parser and verifier for
[SSH file signatures](https://www.agwa.name/blog/post/ssh_signatures).

All features are implemented using pure TypeScript and built-in
[SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto).

Since [`Ed25519` public keys](https://wicg.github.io/webcrypto-secure-curves/)
are
[not yet widely deployed](https://caniuse.com/mdn-api_subtlecrypto_verify_ed25519)
this package allows supplying custom `SubtleCrypto` implementation, such as
[`webcrypto-ed25519`](https://github.com/jacobbubu/webcrypto-ed25519).

## Example

The following example verifies an `ed25519` signature against provided data:

```typescript
import { verify } from "./index.ts";

const signature = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgscJcEliU8+Su3ZZjI/dJmgzHje
UMEHlAAuMTvrYRCVwAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAECQkGDrATymoR1tunbphepkXiLGAMcF+Eca1EL3KpidzNYSTJ/smLYVw2elXq3K/l
dnvxJddvs2Z/x5En43hQIB
-----END SSH SIGNATURE-----`;

const valid = await verify(
  crypto.subtle, // allow inserting SubtleCrypto
  signature, // detached signature
  "this is signed data\n", // signed data
);

console.assert(valid, "signature is valid");
```

## License

This project is licensed under the
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be licensed as above, without any additional terms or conditions.
