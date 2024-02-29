Deno.test(
  { permissions: { read: true, write: true }, name: "readme.md" },
  async () => {
    const readme = await Deno.readTextFile("README.md");
    for (const block of readme.match(/```typescript[\s\S]*?```/gm) || "") {
      const source = block.replace(/^```typescript/gm, "").replace(
        /```$/gm,
        "",
      );

      const tmpFilePath = await Deno.makeTempFile({ suffix: ".ts", dir: "." });

      await Deno.writeTextFile(tmpFilePath, source);

      await import(tmpFilePath);
      await Deno.remove(tmpFilePath);
      //
    }
  },
);
