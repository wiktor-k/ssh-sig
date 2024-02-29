export interface Pubkey {
  pk_algo: string;
  e: Uint8Array;
  n: Uint8Array;
}

function encode(bytes: Uint8Array) {
  return btoa(String.fromCharCode.apply(null, bytes as unknown as number[]))
    .replace(
      /\+/g,
      "-",
    )
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function convert(publickey: Pubkey): {
  format: "jwk";
  keyData: JsonWebKey;
  algorithm: RsaHashedImportParams;
} {
  return {
    keyData: {
      kty: "RSA",
      e: encode(publickey.e),
      n: encode(publickey.n),
    },
    format: "jwk",
    algorithm: {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-512" },
    },
  };
}
