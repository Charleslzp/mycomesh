#!/usr/bin/env node
import { main } from "../src/cli.mjs";

main().then((code) => { if (typeof code === "number") process.exitCode = code; }).catch((error) => {
  process.stderr.write(`mycomesh-consumer: ${error.message}\n`);
  process.exitCode = 1;
});
