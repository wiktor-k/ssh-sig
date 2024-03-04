import { Sig } from "./sig.ts";
import { Reader } from "./reader.ts";
import { parsePubkey } from "./formats.ts";

export function parse(view: DataView): Sig {
  const reader = new Reader(view);

  const magic = reader.readBytes(6).toString();
  if (magic !== "SSHSIG") {
    throw new Error(`Expected SSHSIG magic value but got: ${magic}`);
  }
  const version = reader.readUint32();
  if (version !== 1) {
    throw new Error(`Expected version 1 but got: ${version}`);
  }
  const publickey = reader.readString();

  const pk_algo = publickey.readString().toString();
  const pubkey = parsePubkey(pk_algo, publickey);
  const namespace = reader.readString().toString();
  const reserved = reader.readString().bytes();
  const hash_algorithm = reader.readString().toString();
  const raw_signature = reader.readString();
  const sig_algo = raw_signature.readString().toString();
  const sig_bytes = raw_signature.readString();
  let bytes;
  if (sig_algo === "ecdsa-sha2-nistp256") {
    let r = new Uint8Array(sig_bytes.readString().bytes());
    if (r[0] === 0x00 && r.length == 33) {
      r = r.slice(1);
    }
    let s = new Uint8Array(sig_bytes.readString().bytes());
    if (s[0] === 0x00 && s.length == 33) {
      s = s.slice(1);
    }
    bytes = new Uint8Array([...r, ...s]);
  } else {
    bytes = sig_bytes.bytes();
  }
  return {
    publickey: pubkey,
    namespace,
    reserved,
    hash_algorithm,
    signature: {
      sig_algo,
      raw_signature: bytes,
    },
  };
}
