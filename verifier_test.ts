import { assertEquals } from "https://deno.land/std@0.217.0/assert/mod.ts";
import { parse } from "./sig_parser.ts";
import { dearmor } from "./armor.ts";
import { verify } from "./verifier.ts";

for await (const entry of Deno.readDir("fixtures")) {
  if (entry.name.endsWith(".sig")) {
    Deno.test(
      { permissions: { read: true }, name: entry.name },
      async () => {
        const b = dearmor(await Deno.readTextFile(`fixtures/${entry.name}`));
        const sig = new DataView(b.buffer, b.byteOffset, b.length);
        const sig2 = parse(sig);
        assertEquals(
          await verify(crypto.subtle,
            sig2,
            await Deno.readFile(`fixtures/${entry.name.replace(/\.sig$/, "")}`),
          ),
          true,
        );
      },
    );
  }
}
