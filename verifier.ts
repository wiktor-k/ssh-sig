import { Sig } from "./sig.ts";
import { convertAlgorithm, convertHash, convertPublicKey } from "./formats.ts";
import { Writer } from "./writer.ts";

export async function verify(
  subtle: SubtleCrypto,
  signature: Sig,
  signed_data: Uint8Array,
) {
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

  const writer = new Writer(100);
  // https://github.com/openssh/openssh-portable/blob/d575cf44895104e0fcb0629920fb645207218129/PROTOCOL.sshsig
  // MAGIC_PREAMBLE
  writer.writeBytes("SSHSIG");
  // namespace
  writer.writeString("file");
  // reserved
  writer.writeUint32(0);
  // hash_algorithm
  const hash = signature.hash_algorithm;
  writer.writeString(hash);
  const digest = new Uint8Array(
    await subtle.digest(
      convertHash(hash),
      signed_data,
    ),
  );
  writer.writeString(digest);

  const data = writer.bytes();

  if (
    signature.publickey.pk_algo === "sk-ecdsa-sha2-nistp256@openssh.com" ||
    signature.publickey.pk_algo === "sk-ssh-ed25519@openssh.com"
  ) {
    // https://fuchsia.googlesource.com/third_party/openssh-portable/+/refs/heads/main/PROTOCOL.u2f#176
    const u2f_data = new Writer(100);
    u2f_data.writeBytes(
      await subtle.digest(
        "SHA-256",
        Uint8Array.from(
          Array.prototype.map.call(
            signature.publickey.application,
            (x) => x.charCodeAt(0),
          ) as unknown as number[],
        ),
      ),
    );
    u2f_data.writeByte(signature.signature.flags || 0);
    u2f_data.writeUint32(signature.signature.counter || 0);
    u2f_data.writeBytes(
      await subtle.digest(
        "SHA-256",
        data,
      ),
    );
    return await subtle.verify(
      algorithm,
      key,
      signature.signature.raw_signature,
      u2f_data.bytes(),
    );
  }

  return await subtle.verify(
    algorithm,
    key,
    signature.signature.raw_signature,
    data,
  );
}
