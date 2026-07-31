#!/usr/bin/env node

import { main } from "../src/provider.mjs";

process.exitCode = await main(process.argv.slice(2));
