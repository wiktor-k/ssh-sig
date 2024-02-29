# SSH Sig

[![CI](https://github.com/wiktor-k/ssh-browser-test/actions/workflows/ci.yml/badge.svg)](https://github.com/wiktor-k/ssh-browser-test/actions/workflows/ci.yml)

Provides SSH signature parser and verifier for
[SSH file signatures](https://www.agwa.name/blog/post/ssh_signatures).

All features are implemented using pure TypeScript and built-in
[SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
(with the exception of ed25519 which, sadly, is
[not yet supported there](https://wicg.github.io/webcrypto-secure-curves/).

```typescript
console.assert(false)
```

## License

This project is licensed under the
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be licensed as above, without any additional terms or conditions.
