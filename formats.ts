export type Pubkey = {
  pk_algo: "ssh-rsa";
  e: Uint8Array;
  n: Uint8Array;
} | {
  pk_algo: "ssh-ed25519";
  key: Uint8Array;
};

function encode(bytes: Uint8Array) {
  return btoa(String.fromCharCode.apply(null, bytes as unknown as number[]))
    .replace(
      /\+/g,
      "-",
    )
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function convertPublicKey(publickey: Pubkey): {
  format: "jwk";
  keyData: JsonWebKey;
} | { format: "raw"; keyData: ArrayBuffer } {
  const pk_algo = publickey.pk_algo;
  if (pk_algo === "ssh-rsa") {
    return {
      keyData: {
        kty: "RSA",
        e: encode(publickey.e),
        n: encode(publickey.n),
      },
      format: "jwk",
    };
  } else if (pk_algo === "ssh-ed25519") {
    return {
      keyData: publickey.key.buffer,
      format: "raw",
    };
  } else {
    throw new Error(`Unsupported algo: ${pk_algo}`);
  }
}

export function convertAlgorithm(sig_algo: string) {
  if (sig_algo === "rsa-sha2-512") {
    return {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-512" },
    };
  } else if (sig_algo === "ssh-ed25519") {
    return {
      name: "Ed25519",
      hash: { name: "SHA-512" },
    };
  } else {
    throw new Error(`Unsupported algo: ${sig_algo}`);
  }
}
