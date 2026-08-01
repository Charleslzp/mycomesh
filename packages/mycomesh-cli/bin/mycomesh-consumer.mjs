#!/usr/bin/env node

import { isApiInvocation } from "../src/consumer.mjs";

const argv = process.argv.slice(2);
const { main } = isApiInvocation(argv)
  ? await import("../src/cli.mjs")
  : await import("../src/consumer.mjs");

process.exitCode = await main(argv);
