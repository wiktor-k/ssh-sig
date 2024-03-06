import { Sig } from "./sig.ts";
import { verify as rawVerify } from "./verifier.ts";
import { parse } from "./sig_parser.ts";

/**
 * Verifies SSH signature against provided data.
 *
 * @param {Sig | string} signature SSH signature.
 * @param {Uint8Array | string} signed_data Data that has been signed.
 * @param {object} options Pass-in subtle crypto if required.
 * @returns {Promise<boolean>} Resolves to true if the signature is valid, to false otherwise.
 */
export async function verify(
  signature: Sig | string,
  signed_data: Uint8Array | string,
  options?: {
    subtle?: SubtleCrypto;
  },
): Promise<boolean> {
  if (typeof options === "undefined") {
    options = {};
  }
  const subtle = options.subtle || crypto.subtle;
  if (typeof signature === "string") {
    signature = parse(signature);
  }
  if (typeof signed_data === "string") {
    signed_data = new TextEncoder().encode(signed_data);
  }
  return await rawVerify(subtle, signature, signed_data);
}
