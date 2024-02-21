var fs = require("fs");
var b = fs.readFileSync("b.bin");
var sig = new DataView(b.buffer, b.byteOffset, b.length);

class Reader {
  pos = 0;
  constructor(view) {
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
  readBytes(num) {
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

const areEqual = (first, second) =>
  first.length === second.length &&
  first.every((value, index) => value === second[index]);

let r = new Reader(sig);
console.assert(r.readBytes(6) == "SSHSIG");
console.assert(r.readUint32() == 1);
let publickey = r.readString();

let pk_algo = publickey.readString().toString();
console.assert(pk_algo == "ssh-rsa");
let e = new Uint8Array(publickey.readString().bytes());
console.assert(areEqual(e, [1, 0, 1]));
let n = new Uint8Array(publickey.readString().bytes());

function encode(bytes) {
  console.log("encode", bytes);
  //if (bytes[0] == 0) { bytes.shift(1); }
  return btoa(String.fromCharCode.apply(null, bytes));
}

async function v(signature) {
  //https://nodejs.org/api/webcrypto.html#subtleimportkeyformat-keydata-algorithm-extractable-keyusages
  // for 'RSASSA-PKCS1-v1_5' only spki, pkcs8 and jwk are supported
  // https://stackoverflow.com/questions/46232571/webcrypto-importing-rsa-public-key-with-modulus-and-exponent-using-crypto-subtl
  let key = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "RSA",
      e: encode(signature.publickey.e),
      n: encode(signature.publickey.n),
    },
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-512" },
    },
    false,
    [
      "verify",
    ],
  );
  console.log(key);
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
        ),
      ),
    ),
  );
  //console.log(digest);
  // H(message)
  data.push(...[0, 0, 0, digest.length]);
  data.push(...digest);
  data = new Uint8Array(data);
  console.log(data);
  let result = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signature.signature.raw_signature,
    data,
  );
  console.log("result => " + result);
}

//let raw_signature =

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

console.log(sig2);

v(sig2).then(console.log.bind(console), console.error.bind(console));
