import { assertEquals } from "https://deno.land/std@0.217.0/assert/mod.ts";
import { Sig } from "./sig.ts";
import { convert } from "./key.ts";
import { parse } from "./sig_parser.ts";
import { dearmor } from "./armor.ts";

async function v(signature: Sig, ddata: Uint8Array) {
  //https://nodejs.org/api/webcrypto.html#subtleimportkeyformat-keydata-algorithm-extractable-keyusages
  // for 'RSASSA-PKCS1-v1_5' only spki, pkcs8 and jwk are supported
  // https://stackoverflow.com/questions/46232571/webcrypto-importing-rsa-public-key-with-modulus-and-exponent-using-crypto-subtl
  const { keyData, format, algorithm } = convert(signature.publickey);
  const key = await crypto.subtle.importKey(format, keyData, algorithm, false, [
    "verify",
  ]);
  // https://github.com/openssh/openssh-portable/blob/d575cf44895104e0fcb0629920fb645207218129/PROTOCOL.sshsig
  // MAGIC_PREAMBLE
  let data = Array.prototype.map.call("SSHSIG", (x) => x.charCodeAt(0));
  // namespace
  data.push(...[0, 0, 0, 4]);
  data.push(...Array.prototype.map.call("file", (x) => x.charCodeAt(0)));
  // reserved
  data.push(...[0, 0, 0, 0]);
  // hash_algorithm
  data.push(...[0, 0, 0, 6]);
  data.push(...Array.prototype.map.call("sha512", (x) => x.charCodeAt(0)));

  let digest = new Uint8Array(
    await crypto.subtle.digest(
      algorithm.hash,
      ddata,
    ),
  );
  data.push(...[0, 0, 0, digest.length]);
  data.push(...digest);
  return await crypto.subtle.verify(
    algorithm.name,
    key,
    signature.signature.raw_signature,
    new Uint8Array(data as unknown as any),
  );
}

//let raw_signature =

Deno.test(
  { permissions: { read: true }, name: "sig test" },
  async () => {
    var b = dearmor(await Deno.readTextFile("signed-data.txt.sig"));
    var sig = new DataView(b.buffer, b.byteOffset, b.length);
    const sig2 = parse(sig);
    assertEquals(await v(sig2, await Deno.readFile("signed-data.txt")), true);
  },
);
