import { Sig } from "./sig.ts";
import { Reader } from "./reader.ts";

export function parse(view: DataView): Sig {
  let r = new Reader(view);
  console.assert(r.readBytes(6).toString() == "SSHSIG");
  console.assert(r.readUint32() == 1);
  let publickey = r.readString();

  let pk_algo = publickey.readString().toString();
  console.assert(pk_algo == "ssh-rsa");
  let e = new Uint8Array(publickey.readString().bytes());
  let n = new Uint8Array(publickey.readString().bytes());

  let namespace = r.readString().toString();
  let reserved = r.readString().bytes();
  let hash_algorithm = r.readString().toString();
  let raw_signature = r.readString();
  let sig_algo = raw_signature.readString().toString();
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
