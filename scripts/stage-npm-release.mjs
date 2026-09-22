#!/usr/bin/env node

// Build npm release candidates from an exact Git commit. Provider source and
// image pins are injected only into the temporary archive snapshot, never the
// working tree. This script intentionally does not publish either package.

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const DEFAULT_ROOT = resolve(dirname(SCRIPT_PATH), "..");
const SOURCE_COMMIT_RE = /^[0-9a-f]{40}$/;
const PROVIDER_IMAGE_RE =
  /^ghcr\.io\/charleslzp\/mycomesh-provider-codex@sha256:[0-9a-f]{64}$/;
const METADATA_SCHEMA = "mycomesh.npm-release-candidate.v1";
const METADATA_FILE = "npm-release-candidate.json";

function isolatedGitEnvironment() {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
  );
  // A replace ref can leave rev-parse reporting commit A while archive reads
  // commit B's tree. Release inputs must always use the literal object named by
  // source_commit.
  env.GIT_NO_REPLACE_OBJECTS = "1";
  return env;
}

function usage() {
  return `Usage: node scripts/stage-npm-release.mjs \\
  --source-commit COMMIT \\
  --provider-image ghcr.io/charleslzp/mycomesh-provider-codex@sha256:DIGEST \\
  --output-dir PATH

Creates Provider and Consumer npm tarballs plus ${METADATA_FILE}. The output
directory must not exist and must be outside the source repository. Nothing is
published and the working tree is never modified.`;
}

function parseArguments(argv) {
  const parsed = { root: DEFAULT_ROOT };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "-h" || token === "--help") return { help: true };
    const separator = token.indexOf("=");
    const name = separator === -1 ? token : token.slice(0, separator);
    const value = separator === -1 ? argv[++index] : token.slice(separator + 1);
    if (!name.startsWith("--") || !value) throw new Error(`${name} requires a value`);
    if (name === "--source-commit") parsed.sourceCommit = value;
    else if (name === "--provider-image") parsed.providerImage = value;
    else if (name === "--output-dir") parsed.outputDir = value;
    else if (name === "--root") parsed.root = value;
    else throw new Error(`unknown option: ${name}`);
  }
  return parsed;
}

function isInside(parent, child) {
  const value = relative(parent, child);
  return value === "" || (!value.startsWith("..") && !isAbsolute(value));
}

async function mustNotExist(path) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error(`output directory already exists: ${path}`);
}

async function canonicalFuturePath(path) {
  let cursor = resolve(path);
  const missing = [];
  while (true) {
    try {
      const existing = await realpath(cursor);
      return resolve(existing, ...missing);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    const parent = dirname(cursor);
    if (parent === cursor) throw new Error(`cannot resolve output path: ${path}`);
    missing.unshift(basename(cursor));
    cursor = parent;
  }
}

async function assertNoSymlinks(path) {
  const info = await lstat(path);
  if (info.isSymbolicLink()) throw new Error(`package input must not contain symlinks: ${path}`);
  if (!info.isDirectory()) return;
  for (const entry of await readdir(path)) await assertNoSymlinks(join(path, entry));
}

function packageEntry(entry) {
  if (
    typeof entry !== "string"
    || entry.length === 0
    || isAbsolute(entry)
    || entry.split(/[\\/]/).includes("..")
    || /[*?[\]]/.test(entry)
  ) {
    throw new Error(`unsupported package files entry: ${String(entry)}`);
  }
  return entry;
}

async function copyIfPresent(source, destination) {
  try {
    await stat(source);
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
  await assertNoSymlinks(source);
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination, { recursive: true, errorOnExist: true, force: false });
  return true;
}

async function stagePackage(source, destination) {
  const manifest = JSON.parse(await readFile(join(source, "package.json"), "utf8"));
  if (!Array.isArray(manifest.files) || !manifest.files.length) {
    throw new Error(`${manifest.name || source} must declare a non-empty files list`);
  }
  await mkdir(destination, { recursive: true });
  await copyIfPresent(join(source, "package.json"), join(destination, "package.json"));
  const packageFiles = manifest.files.map(packageEntry);
  const declared = new Set(packageFiles.map((entry) => entry.toLowerCase()));
  for (const entry of packageFiles) {
    const copied = await copyIfPresent(join(source, entry), join(destination, entry));
    if (!copied) throw new Error(`${manifest.name} package input is missing: ${entry}`);
  }
  for (const entry of await readdir(source)) {
    if (
      /^(readme|license|licence|notice|changelog)(\..*)?$/i.test(entry)
      && !declared.has(entry.toLowerCase())
    ) {
      await copyIfPresent(join(source, entry), join(destination, entry));
    }
  }
  return manifest;
}

function replaceExactlyOnce(source, expression, replacement, label) {
  const matches = source.match(new RegExp(expression.source, expression.flags.includes("g") ? expression.flags : `${expression.flags}g`));
  if (!matches || matches.length !== 1) throw new Error(`expected one ${label} placeholder`);
  return source.replace(expression, replacement);
}

async function bindProviderRelease(releasePath, sourceCommit, providerImage) {
  let source = await readFile(releasePath, "utf8");
  source = replaceExactlyOnce(
    source,
    /export const PROVIDER_RELEASE_SOURCE_COMMIT = null;/,
    `export const PROVIDER_RELEASE_SOURCE_COMMIT = ${JSON.stringify(sourceCommit)};`,
    "Provider source commit",
  );
  source = replaceExactlyOnce(
    source,
    /export const PROVIDER_RELEASE_IMAGE = null;/,
    `export const PROVIDER_RELEASE_IMAGE = ${JSON.stringify(providerImage)};`,
    "Provider image",
  );
  await writeFile(releasePath, source, { encoding: "utf8", mode: 0o644 });
}

async function sha256(path) {
  const digest = createHash("sha256");
  digest.update(await readFile(path));
  return digest.digest("hex");
}

async function packPackage({ source, output, npmCommand, requiredFiles }) {
  const { stdout } = await execute(
    npmCommand,
    ["pack", "--ignore-scripts", "--json", "--pack-destination", output],
    { cwd: source, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 },
  );
  const rawReport = JSON.parse(stdout);
  const report = Array.isArray(rawReport) ? rawReport : Object.values(rawReport);
  if (report.length !== 1 || typeof report[0]?.filename !== "string") {
    throw new Error(`unexpected npm pack report for ${source}`);
  }
  const packed = report[0];
  const files = new Set((packed.files || []).map((entry) => entry.path));
  const missing = requiredFiles.filter((entry) => !files.has(entry));
  if (missing.length) throw new Error(`${packed.name} tarball is missing: ${missing.join(", ")}`);
  const tarball = join(output, packed.filename);
  return {
    name: packed.name,
    version: packed.version,
    filename: packed.filename,
    size: (await stat(tarball)).size,
    sha256: await sha256(tarball),
    npm_shasum: packed.shasum,
    npm_integrity: packed.integrity,
  };
}

export async function buildNpmReleaseCandidate({
  root = DEFAULT_ROOT,
  sourceCommit,
  providerImage,
  outputDir,
  npmCommand = process.env.MYCOMESH_NPM_CLI || "npm",
  gitCommand = process.env.MYCOMESH_GIT_CLI || "git",
  tarCommand = process.env.MYCOMESH_TAR_CLI || "tar",
} = {}) {
  const requestedRoot = await realpath(resolve(root));
  if (!SOURCE_COMMIT_RE.test(sourceCommit || "")) {
    throw new Error("--source-commit must be a lowercase 40-character Git commit");
  }
  if (!PROVIDER_IMAGE_RE.test(providerImage || "")) {
    throw new Error("--provider-image must be the official Provider image pinned by sha256 digest");
  }
  if (!outputDir) throw new Error("--output-dir is required");
  const { stdout: topLevelOutput } = await execute(
    gitCommand,
    ["-C", requestedRoot, "rev-parse", "--show-toplevel"],
    { encoding: "utf8", env: isolatedGitEnvironment() },
  );
  const sourceRoot = await realpath(topLevelOutput.trim());
  if (requestedRoot !== sourceRoot) {
    throw new Error("--root must identify the Git repository root");
  }
  const candidateOutput = await canonicalFuturePath(outputDir);
  if (isInside(sourceRoot, candidateOutput)) {
    throw new Error("--output-dir must be outside the source repository");
  }
  await mustNotExist(candidateOutput);
  const outputParent = dirname(candidateOutput);
  await mkdir(outputParent, { recursive: true });

  const { stdout: headOutput } = await execute(
    gitCommand,
    ["-C", sourceRoot, "rev-parse", "HEAD"],
    { encoding: "utf8", env: isolatedGitEnvironment() },
  );
  const head = headOutput.trim();
  if (head !== sourceCommit) {
    throw new Error(`--source-commit ${sourceCommit} does not match repository HEAD ${head}`);
  }

  const snapshotRoot = await mkdtemp(join(tmpdir(), "mycomesh-npm-source-"));
  const archivePath = join(snapshotRoot, "source.tar");
  const archiveRoot = join(snapshotRoot, "source");
  await mkdir(archiveRoot);
  const temporaryOutput = await mkdtemp(join(outputParent, ".mycomesh-npm-release-"));
  try {
    await execute(
      gitCommand,
      ["-C", sourceRoot, "archive", "--format=tar", `--output=${archivePath}`, sourceCommit],
      { encoding: "utf8", env: isolatedGitEnvironment(), maxBuffer: 1024 * 1024 },
    );
    await execute(tarCommand, ["-xf", archivePath, "-C", archiveRoot], {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
    });

    const providerStage = join(snapshotRoot, "provider");
    const consumerStage = join(snapshotRoot, "consumer");
    await stagePackage(archiveRoot, providerStage);
    await stagePackage(join(archiveRoot, "packages", "mycomesh-cli"), consumerStage);
    await bindProviderRelease(
      join(providerStage, "packages", "mycomesh-cli", "src", "release.mjs"),
      sourceCommit,
      providerImage,
    );

    const provider = await packPackage({
      source: providerStage,
      output: temporaryOutput,
      npmCommand,
      requiredFiles: [
        "packages/mycomesh-cli/src/release.mjs",
        "packages/mycomesh-cli/networks/v10-controlled-test.json",
        "packages/mycomesh-cli/networks/v10-controlled-test.ca.crt",
      ],
    });
    const consumer = await packPackage({
      source: consumerStage,
      output: temporaryOutput,
      npmCommand,
      requiredFiles: [
        "src/release.mjs",
        "networks/v10-controlled-test.json",
        "networks/v10-controlled-test.ca.crt",
      ],
    });
    const metadata = {
      schema: METADATA_SCHEMA,
      source_commit: sourceCommit,
      provider_image: providerImage,
      packages: { provider, consumer },
    };
    await writeFile(
      join(temporaryOutput, METADATA_FILE),
      `${JSON.stringify(metadata, null, 2)}\n`,
      { encoding: "utf8", mode: 0o644 },
    );
    await rename(temporaryOutput, candidateOutput);
    return { ...metadata, output_dir: candidateOutput };
  } catch (error) {
    await rm(temporaryOutput, { recursive: true, force: true });
    throw error;
  } finally {
    await rm(snapshotRoot, { recursive: true, force: true });
  }
}

async function main(argv) {
  try {
    const parsed = parseArguments(argv);
    if (parsed.help) {
      process.stdout.write(`${usage()}\n`);
      return 0;
    }
    const result = await buildNpmReleaseCandidate(parsed);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`stage npm release: ${error instanceof Error ? error.message : String(error)}\n`);
    process.stderr.write(`${usage()}\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === SCRIPT_PATH) {
  process.exitCode = await main(process.argv.slice(2));
}

export { METADATA_FILE, METADATA_SCHEMA, parseArguments };
