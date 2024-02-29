import { Sig } from "./sig.ts";
import { convertAlgorithm, convertPublicKey } from "./formats.ts";

export async function verify(subtle: SubtleCrypto, signature: Sig, signed_data: Uint8Array) {
  //https://nodejs.org/api/webcrypto.html#subtleimportkeyformat-keydata-algorithm-extractable-keyusages
  // for 'RSASSA-PKCS1-v1_5' only spki, pkcs8 and jwk are supported
  // https://stackoverflow.com/questions/46232571/webcrypto-importing-rsa-public-key-with-modulus-and-exponent-using-crypto-subtl
  const { keyData, format } = convertPublicKey(signature.publickey);
  const algorithm = convertAlgorithm(signature.signature.sig_algo);
  const key = await subtle.importKey(
    format as unknown as "raw",
    keyData as unknown as BufferSource,
    algorithm,
    false,
    [
      "verify",
    ],
  );
  // https://github.com/openssh/openssh-portable/blob/d575cf44895104e0fcb0629920fb645207218129/PROTOCOL.sshsig
  // MAGIC_PREAMBLE
  const data = Array.prototype.map.call("SSHSIG", (x) => x.charCodeAt(0));
  // namespace
  data.push(...[0, 0, 0, 4]);
  data.push(...Array.prototype.map.call("file", (x) => x.charCodeAt(0)));
  // reserved
  data.push(...[0, 0, 0, 0]);
  // hash_algorithm
  data.push(...[0, 0, 0, 6]);
  data.push(...Array.prototype.map.call("sha512", (x) => x.charCodeAt(0)));

  const digest = new Uint8Array(
    await subtle.digest(
      algorithm.hash,
      signed_data,
    ),
  );
  data.push(...[0, 0, 0, digest.length]);
  data.push(...digest);
  return await subtle.verify(
    algorithm.name,
    key,
    signature.signature.raw_signature,
    new Uint8Array(data as unknown as number[]),
  );
}
