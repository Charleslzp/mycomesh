#!/usr/bin/env node

const [command] = process.argv.slice(2);
const { main } = command === "provider"
  ? await import("../src/provider.mjs")
  : await import("../src/cli.mjs");

const args = command === "provider" ? process.argv.slice(3) : process.argv.slice(2);
process.exitCode = await main(args);
