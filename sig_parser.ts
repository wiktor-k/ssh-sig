import { Sig } from "./sig.ts";
import { Reader } from "./reader.ts";
import { Pubkey } from "./formats.ts";

export function parse(view: DataView): Sig {
  const r = new Reader(view);

  const magic = r.readBytes(6).toString();
  if (magic !== "SSHSIG") {
    throw new Error(`Expected SSHSIG magic value but got: ${magic}`);
  }
  const version = r.readUint32();
  if (version !== 1) {
    throw new Error(`Expected version 1 but got: ${version}`);
  }
  const publickey = r.readString();

  const pk_algo = publickey.readString().toString();
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
  } else {
    throw new Error(`Unsupported pk_algo: ${pk_algo}`);
  }

  const namespace = r.readString().toString();
  const reserved = r.readString().bytes();
  const hash_algorithm = r.readString().toString();
  const raw_signature = r.readString();
  const sig_algo = raw_signature.readString().toString();
  return {
    publickey: pubkey,
    namespace,
    reserved,
    hash_algorithm,
    signature: {
      sig_algo,
      raw_signature: raw_signature.readString().bytes(),
    },
  };
}
