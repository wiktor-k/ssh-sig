import { assertEquals } from "https://deno.land/std@0.217.0/assert/mod.ts";
import { verify } from "./index.ts";
import { parse } from "./sig_parser.ts";

for await (const entry of Deno.readDir("fixtures")) {
  if (entry.name.endsWith(".sig")) {
    Deno.test(
      { permissions: { read: true, write: true, run: true }, name: entry.name },
      async () => {
        const signature = parse(
          await Deno.readTextFile(`fixtures/${entry.name}`),
        );
        assertEquals(
          await verify(
            signature,
            await Deno.readTextFile(
              `fixtures/${entry.name.replace(/\.sig$/, "")}`,
            ),
          ),
          true,
          "signature verification should succeed",
        );
        const allowedSigners = await Deno.makeTempFile();

        await Deno.writeTextFile(
          allowedSigners,
          `test@example.com ${signature.publickey}`,
        );
        const command = new Deno.Command("ssh-keygen", {
          args: [
            "-Y",
            "verify",
            "-f",
            allowedSigners,
            "-I",
            "test@example.com",
            "-n",
            "file",
            "-s",
            `fixtures/${entry.name}`,
          ],
          stdin: "piped",
        });
        const child = command.spawn();
        Deno.openSync(`fixtures/${entry.name.replace(/\.sig$/, "")}`).readable
          .pipeTo(child.stdin);
        const status = await child.status;
        assertEquals(status.success, true);
      },
    );
  }
}
