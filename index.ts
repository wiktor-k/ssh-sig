import { Sig } from "./sig.ts";
import { verify as rawVerify } from "./verifier.ts";
import { parse } from "./sig_parser.ts";
import { dearmor } from "./armor.ts";

/**
 * Verifies SSH signature against provided data.
 *
 * @param {SubtleCrypto} subtle Implementation of the SubtleCrypto interface.
 * @param {Sig | string} signature SSH signature.
 * @param {Uint8Array | string} signed_data Data that has been signed.
 * @returns {Promise<boolean>} Resolves to true if the signature is valid, to false otherwise.
 */
export async function verify(
  subtle: SubtleCrypto,
  signature: Sig | string,
  signed_data: Uint8Array | string,
): Promise<boolean> {
  if (typeof signature === "string") {
    const bytes = dearmor(signature);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.length);
    signature = parse(view);
  }
  if (typeof signed_data === "string") {
    signed_data = new TextEncoder().encode(signed_data);
  }
  return await rawVerify(subtle, signature, signed_data);
}
