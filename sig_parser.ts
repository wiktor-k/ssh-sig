import { Sig } from "./sig.ts";
import { Reader } from "./reader.ts";

export function parse(view: DataView): Sig {
  const r = new Reader(view);
  console.assert(r.readBytes(6).toString() == "SSHSIG");
  console.assert(r.readUint32() == 1);
  const publickey = r.readString();

  const pk_algo = publickey.readString().toString();
  console.assert(pk_algo == "ssh-rsa");
  const e = new Uint8Array(publickey.readString().bytes());
  const n = new Uint8Array(publickey.readString().bytes());

  const namespace = r.readString().toString();
  const reserved = r.readString().bytes();
  const hash_algorithm = r.readString().toString();
  const raw_signature = r.readString();
  const sig_algo = raw_signature.readString().toString();
  console.assert(sig_algo == "rsa-sha2-512");
  return {
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
}
