#!/usr/bin/env node
import { main } from "../src/cli.mjs";

// A one-shot command is done when main returns (serve never does): exit then, once the output is flushed,
// rather than wait for background discovery refreshes that the next run will redo anyway.
const exit = (code) => process.stdout.write("", () => process.stderr.write("", () => process.exit(code)));

main().then((code) => exit(typeof code === "number" ? code : 0)).catch((error) => {
  process.stderr.write(`mycomesh-consumer: ${error.message}\n`);
  exit(1);
});
