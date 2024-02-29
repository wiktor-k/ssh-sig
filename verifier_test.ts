import { assertEquals } from "https://deno.land/std@0.217.0/assert/mod.ts";
import { verify } from "./index.ts";

for await (const entry of Deno.readDir("fixtures")) {
  if (entry.name.endsWith(".sig")) {
    Deno.test(
      { permissions: { read: true }, name: entry.name },
      async () => {
        const signature = await Deno.readTextFile(`fixtures/${entry.name}`);
        assertEquals(
          await verify(
            crypto.subtle,
            signature,
            await Deno.readTextFile(
              `fixtures/${entry.name.replace(/\.sig$/, "")}`,
            ),
          ),
          true,
        );
      },
    );
  }
}
