import { Reader } from "./reader.ts";

/**
 * Represents an SSH public key.
 */
export type Pubkey = {
  pk_algo: "ssh-rsa";
  e: Uint8Array;
  n: Uint8Array;
  toString(): string;
} | {
  pk_algo: "ssh-ed25519";
  key: Uint8Array;
  toString(): string;
} | {
  pk_algo:
    | "ecdsa-sha2-nistp256"
    | "ecdsa-sha2-nistp384"
    | "ecdsa-sha2-nistp521";
  curve: string;
  point: Uint8Array;
  toString(): string;
} | {
  pk_algo: "sk-ecdsa-sha2-nistp256@openssh.com";
  curve: string;
  point: Uint8Array;
  // typically "ssh:"
  application: string;
  toString(): string;
} | {
  pk_algo: "sk-ssh-ed25519@openssh.com";
  key: Uint8Array;
  // typically "ssh:"
  application: string;
  toString(): string;
};

export function parsePubkey(
  pk_algo: string,
  publickey: Reader,
  raw_publickey: ArrayBuffer,
): Pubkey {
  let pubkey: Pubkey;
  if (pk_algo === "ssh-rsa") {
    pubkey = {
      pk_algo,
      e: new Uint8Array(publickey.readString().bytes()),
      n: new Uint8Array(publickey.readString().bytes()),
      toString() {
        return `${pk_algo} ${base64Encode(new Uint8Array(raw_publickey))}`;
      },
    };
  } else if (pk_algo === "ssh-ed25519") {
    pubkey = {
      pk_algo,
      key: new Uint8Array(publickey.readString().bytes()),
      toString() {
        return `${pk_algo} ${base64Encode(new Uint8Array(raw_publickey))}`;
      },
    };
  } else if (pk_algo === "sk-ssh-ed25519@openssh.com") {
    const key = new Uint8Array(publickey.readString().bytes());
    const application = publickey.readString().toString();
    pubkey = {
      pk_algo,
      key,
      application,
      toString() {
        return `${pk_algo} ${base64Encode(new Uint8Array(raw_publickey))}`;
      },
    };
  } else if (
    pk_algo === "ecdsa-sha2-nistp256" || pk_algo === "ecdsa-sha2-nistp384" ||
    pk_algo === "ecdsa-sha2-nistp521"
  ) {
    const curve = publickey.readString().toString();
    const point = new Uint8Array(publickey.readString().bytes());
    pubkey = {
      pk_algo,
      curve,
      point,
      toString() {
        return `${pk_algo} ${base64Encode(new Uint8Array(raw_publickey))}`;
      },
    };
  } else if (pk_algo === "sk-ecdsa-sha2-nistp256@openssh.com") {
    const curve = publickey.readString().toString();
    const point = new Uint8Array(publickey.readString().bytes());
    const application = publickey.readString().toString();
    pubkey = {
      pk_algo,
      curve,
      point,
      application,
      toString() {
        return `${pk_algo} ${base64Encode(new Uint8Array(raw_publickey))}`;
      },
    };
  } else {
    throw new Error(`Unsupported pk_algo: ${pk_algo}`);
  }
  return pubkey;
}

function base64Encode(bytes: Uint8Array) {
  return btoa(String.fromCharCode.apply(null, bytes as unknown as number[]));
}

function base64UrlEncode(bytes: Uint8Array) {
  return base64Encode(bytes)
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
        e: base64UrlEncode(publickey.e),
        n: base64UrlEncode(publickey.n),
      },
      format: "jwk",
    };
  } else if (
    pk_algo === "ssh-ed25519" || pk_algo === "sk-ssh-ed25519@openssh.com"
  ) {
    return {
      keyData: publickey.key.buffer,
      format: "raw",
    };
  } else if (
    pk_algo === "ecdsa-sha2-nistp256" || pk_algo === "ecdsa-sha2-nistp384" ||
    pk_algo === "ecdsa-sha2-nistp521" ||
    pk_algo === "sk-ecdsa-sha2-nistp256@openssh.com"
  ) {
    if (publickey.point[0] !== 0x04) {
      throw new Error("Only uncompressed (0x04) format is supported");
    }

    const point = publickey.point.slice(1);

    let crv;
    if (
      pk_algo === "ecdsa-sha2-nistp256" ||
      pk_algo === "sk-ecdsa-sha2-nistp256@openssh.com"
    ) {
      crv = "P-256";
    } else if (pk_algo === "ecdsa-sha2-nistp384") {
      crv = "P-384";
    }
    {
      crv = "P-521";
    }
    return {
      keyData: {
        kty: "EC",
        crv,
        x: base64UrlEncode(point.slice(0, point.length / 2)),
        y: base64UrlEncode(point.slice(point.length / 2)),
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
  } else if (
    sig_algo === "ssh-ed25519" || sig_algo === "sk-ssh-ed25519@openssh.com"
  ) {
    return {
      name: "Ed25519",
      hash: { name: "SHA-512" },
    };
  } else if (
    sig_algo === "ecdsa-sha2-nistp256" ||
    sig_algo === "sk-ecdsa-sha2-nistp256@openssh.com"
  ) {
    return {
      name: "ECDSA",
      namedCurve: "P-256",
      hash: { name: "SHA-256" },
    };
  } else if (sig_algo === "ecdsa-sha2-nistp384") {
    return {
      name: "ECDSA",
      namedCurve: "P-384",
      hash: { name: "SHA-384" },
    };
  } else if (sig_algo === "ecdsa-sha2-nistp521") {
    return {
      name: "ECDSA",
      namedCurve: "P-521",
      hash: { name: "SHA-512" },
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
