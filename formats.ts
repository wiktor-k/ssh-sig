import { Reader } from "./reader.ts";

export type Pubkey = {
  pk_algo: "ssh-rsa";
  e: Uint8Array;
  n: Uint8Array;
} | {
  pk_algo: "ssh-ed25519";
  key: Uint8Array;
} | {
  pk_algo: "ecdsa-sha2-nistp256";
  curve: string;
  point: Uint8Array;
};

export function parsePubkey(pk_algo: string, publickey: Reader): Pubkey {
  let pubkey: Pubkey;
  if (pk_algo === "ssh-rsa") {
    pubkey = {
      pk_algo,
      e: new Uint8Array(publickey.readString().bytes()),
      n: new Uint8Array(publickey.readString().bytes()),
    };
  } else if (pk_algo === "ssh-ed25519") {
    pubkey = {
      pk_algo,
      key: new Uint8Array(publickey.readString().bytes()),
    };
  } else if (pk_algo === "ecdsa-sha2-nistp256") {
    const curve = publickey.readString().toString();
    pubkey = {
      pk_algo,
      curve,
      point: new Uint8Array(publickey.readString().bytes()),
    };
  } else {
    throw new Error(`Unsupported pk_algo: ${pk_algo}`);
  }
  return pubkey;
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
  } else if (pk_algo === "ecdsa-sha2-nistp256") {
    if (publickey.point[0] !== 0x04) {
      throw new Error("Only uncompressed (0x04) format is supported");
    }

    return {
      keyData: {
        kty: "EC",
        crv: "P-256",
        x: encode(publickey.point.slice(1, 33)),
        y: encode(publickey.point.slice(33)),
      },
      format: "jwk",
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
  } else if (sig_algo === "ecdsa-sha2-nistp256") {
    return {
      name: "ECDSA",
      namedCurve: "P-256",
      hash: { name: "SHA-256" },
    };
  } else {
    throw new Error(`Unsupported algo: ${sig_algo}`);
  }
}

export function convertHash(hashName: string): string {
  if (hashName === "sha256") {
    return "SHA-256";
  } else if (hashName === "sha512") {
    return "SHA-512";
  } else {
    throw new Error(`Unknown hash: ${hashName}`);
  }
}
