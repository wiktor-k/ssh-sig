import { Sig } from "./sig.ts";
import { Reader } from "./reader.ts";
import { parsePubkey } from "./formats.ts";
import { dearmor } from "./armor.ts";

export function parse(signature: DataView | string): Sig {
  let view;
  if (typeof signature === "string") {
    const bytes = dearmor(signature);
    view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
  } else {
    view = signature;
  }
  const reader = new Reader(view);

  const magic = reader.readBytes(6).toString();
  if (magic !== "SSHSIG") {
    throw new Error(`Expected SSHSIG magic value but got: ${magic}`);
  }
  const version = reader.readUint32();
  if (version !== 1) {
    throw new Error(`Expected version 1 but got: ${version}`);
  }
  const raw_publickey = reader.peekString().bytes();
  const publickey = reader.readString();
  const pk_algo = publickey.readString().toString();
  const pubkey = parsePubkey(pk_algo, publickey, raw_publickey);
  const namespace = reader.readString().toString();
  const reserved = reader.readString().bytes();
  const hash_algorithm = reader.readString().toString();
  const raw_signature = reader.readString();
  const sig_algo = raw_signature.readString().toString();
  const sig_bytes = raw_signature.readString();
  let bytes;
  if (
    sig_algo === "ecdsa-sha2-nistp256" || sig_algo === "ecdsa-sha2-nistp384" ||
    sig_algo === "ecdsa-sha2-nistp512" ||
    sig_algo === "sk-ecdsa-sha2-nistp256@openssh.com"
  ) {
    let r = new Uint8Array(sig_bytes.readString().bytes());
    if (r[0] === 0x00 && r.length % 2 == 1) {
      r = r.slice(1);
    }
    let s = new Uint8Array(sig_bytes.readString().bytes());
    if (s[0] === 0x00 && s.length % 2 == 1) {
      s = s.slice(1);
    }
    bytes = new Uint8Array([...r, ...s]);
  } else {
    bytes = sig_bytes.bytes();
  }
  let flags, counter;
  if (sig_algo === "sk-ecdsa-sha2-nistp256@openssh.com") {
    flags = new Uint8Array(raw_signature.readBytes(1).bytes())[0];
    counter = raw_signature.readUint32();
  }
  return {
    publickey: pubkey,
    namespace,
    reserved,
    hash_algorithm,
    signature: {
      sig_algo,
      raw_signature: bytes,
      flags,
      counter,
    },
  };
}
