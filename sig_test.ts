import { assertEquals } from "https://deno.land/std@0.217.0/assert/mod.ts";

//var fs = require("fs");
//var b = fs.readFileSync("b.bin");
interface Sig {
  publickey: {
    pk_algo: string;
    e: Uint8Array;
    n: Uint8Array;
  };
  namespace: string;
  reserved: ArrayBuffer;
  hash_algorithm: string;
  signature: {
    sig_algo: string;
    raw_signature: ArrayBuffer;
  };
}

class Reader {
  pos = 0;
  constructor(private view: DataView) {
    this.view = view;
  }
  readUint8() {
    return this.view.getUint8(this.pos++);
  }
  readUint32() {
    let v = this.view.getUint32(this.pos);
    this.pos += 4;
    return v;
  }
  readBytes(num: number) {
    let dv = new DataView(
      this.view.buffer,
      this.pos + this.view.byteOffset,
      num,
    );
    this.pos += num;
    return new Reader(dv);
  }
  readString() {
    let len = this.readUint32();
    return this.readBytes(len);
  }
  toString() {
    let s = "";
    for (let i = 0; i < this.view.byteLength; i++) {
      s += String.fromCharCode(this.view.getUint8(i));
    }
    return s;
  }
  bytes() {
    return this.view.buffer.slice(
      this.view.byteOffset + this.pos,
      this.view.byteOffset + this.view.byteLength,
    );
  }
}

function encode(bytes: Uint8Array) {
  //if (bytes[0] == 0) bytes = new Uint8Array(bytes.slice(1));
  //console.log('encoding => ' + bytes.length);
  return btoa(String.fromCharCode.apply(null, bytes as unknown as any)).replace(
    /\+/g,
    "-",
  )
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function v(signature: Sig) {
  //https://nodejs.org/api/webcrypto.html#subtleimportkeyformat-keydata-algorithm-extractable-keyusages
  // for 'RSASSA-PKCS1-v1_5' only spki, pkcs8 and jwk are supported
  // https://stackoverflow.com/questions/46232571/webcrypto-importing-rsa-public-key-with-modulus-and-exponent-using-crypto-subtl
  let jwk = {
    kty: "RSA",
    e: encode(signature.publickey.e),
    n: encode(signature.publickey.n),
  };
  console.log(JSON.stringify([
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-512" },
    },
    false,
    [
      "verify",
    ],
  ]));
  let key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-512" },
    },
    false,
    [
      "verify",
    ],
  );
  console.log("jwk", key);
  // https://github.com/openssh/openssh-portable/blob/d575cf44895104e0fcb0629920fb645207218129/PROTOCOL.sshsig
  // MAGIC_PREAMBLE
  let data = Array.prototype.map.call("SSHSIG", (x) => x.charCodeAt(0));
  // namespace
  data.push(...[0, 0, 0, 4]);
  data.push(...Array.prototype.map.call("file", (x) => x.charCodeAt(0)));
  // reserved
  data.push(...[0, 0, 0, 0]);
  // hash_algorithm
  data.push(...[0, 0, 0, 6]);
  data.push(...Array.prototype.map.call("sha512", (x) => x.charCodeAt(0)));

  let digest = new Uint8Array(
    await crypto.subtle.digest(
      {
        name: "SHA-512",
      },
      new Uint8Array(
        Array.prototype.map.call(
          "this is signed data\n",
          (x) => x.charCodeAt(0),
        ) as unknown as any,
      ),
    ),
  );
  data.push(...[0, 0, 0, digest.length]);
  data.push(...digest);
  let result = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signature.signature.raw_signature,
    new Uint8Array(data as unknown as any),
  );
  return result;
}

//let raw_signature =

Deno.test(
  { permissions: { read: true }, name: "sig test" },
  async () => {
    var b = await Deno.readFile("b.bin");
    var sig = new DataView(b.buffer, b.byteOffset, b.length);

    let r = new Reader(sig);
    console.assert(r.readBytes(6).toString() == "SSHSIG");
    console.assert(r.readUint32() == 1);
    let publickey = r.readString();

    let pk_algo = publickey.readString().toString();
    console.assert(pk_algo == "ssh-rsa");
    let e = new Uint8Array(publickey.readString().bytes());
    assertEquals(e, new Uint8Array([1, 0, 1]));
    let n = new Uint8Array(publickey.readString().bytes());

    let namespace = r.readString().toString();
    let reserved = r.readString().bytes();
    let hash_algorithm = r.readString().toString();
    let raw_signature = r.readString();
    let sig_algo = raw_signature.readString().toString();
    console.assert(sig_algo == "rsa-sha2-512");
    let sig2 = {
      publickey: {
        pk_algo,
        e,
        n,
      },
      namespace,
      reserved,
      hash_algorithm,
      signature: {
        sig_algo,
        raw_signature: raw_signature.readString().bytes(),
      },
    };
    assertEquals(await v(sig2), true);
  },
);
