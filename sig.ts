import { Pubkey } from "./formats.ts";

/**
 * Represents a parsed SSH signature.
 */
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
