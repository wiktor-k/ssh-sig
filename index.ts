import { Sig } from "./sig.ts";
import { verify as rawVerify } from "./verifier.ts";
import { parse } from "./sig_parser.ts";
import { dearmor } from "./armor.ts";

export async function verify(
  subtle: SubtleCrypto,
  signature: Sig | string,
  signed_data: Uint8Array | string,
) {
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
