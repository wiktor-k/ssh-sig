import { Pubkey } from "./formats.ts";

export interface Sig {
  publickey: Pubkey;
  namespace: string;
  reserved: ArrayBuffer;
  hash_algorithm: string;
  signature: {
    sig_algo: string;
    raw_signature: ArrayBuffer;
    flags?: number;
    counter?: number;
  };
}
