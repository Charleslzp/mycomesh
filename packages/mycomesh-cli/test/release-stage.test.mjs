import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

import {
  buildNpmReleaseCandidate,
  METADATA_FILE,
  METADATA_SCHEMA,
} from "../../../scripts/stage-npm-release.mjs";

const execute = promisify(execFile);
const REPOSITORY = resolve(dirname(new URL(import.meta.url).pathname), "../../..");

async function digest(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function makeRepository(root) {
  await mkdir(join(root, "bin"), { recursive: true });
  await mkdir(join(root, "packages/mycomesh-cli/src"), { recursive: true });
  await mkdir(join(root, "packages/mycomesh-cli/networks"), { recursive: true });
  await writeFile(join(root, "package.json"), JSON.stringify({
    name: "mycomesh-provider",
    version: "0.1.38",
    type: "module",
    bin: { "mycomesh-provider": "bin/mycomesh-provider" },
    files: [
      "bin",
      "packages/mycomesh-cli/src",
      "packages/mycomesh-cli/package.json",
      "packages/mycomesh-cli/networks/v10-controlled-test.json",
      "packages/mycomesh-cli/networks/v10-controlled-test.ca.crt",
    ],
  }));
  await writeFile(
    join(root, "bin/mycomesh-provider"),
    "#!/usr/bin/env node\nawait import('../packages/mycomesh-cli/src/provider.mjs');\n",
    { mode: 0o755 },
  );
  await writeFile(join(root, "packages/mycomesh-cli/package.json"), JSON.stringify({
    name: "mycomesh-consumer",
    version: "0.1.52",
    type: "module",
    files: [
      "src/release.mjs",
      "README.md",
      "networks/v10-controlled-test.json",
      "networks/v10-controlled-test.ca.crt",
    ],
  }));
  await writeFile(join(root, "packages/mycomesh-cli/README.md"), "# Fixture Consumer\n");
  for (const name of ["provider.mjs", "release.mjs"]) {
    await cp(
      join(REPOSITORY, "packages/mycomesh-cli/src", name),
      join(root, "packages/mycomesh-cli/src", name),
    );
  }
  await writeFile(
    join(root, "packages/mycomesh-cli/networks/v10-controlled-test.json"),
    '{"protocol_version":10}\n',
  );
  await writeFile(
    join(root, "packages/mycomesh-cli/networks/v10-controlled-test.ca.crt"),
    "fixture CA\n",
  );
  await writeFile(
    join(root, "packages/mycomesh-cli/networks/v10-controlled-test.json.pre-release"),
    '{"protocol_version":9}\n',
  );
  await execute("git", ["init", "-q"], { cwd: root });
  await execute("git", ["config", "user.email", "release-test@example.invalid"], { cwd: root });
  await execute("git", ["config", "user.name", "Release Test"], { cwd: root });
  await execute("git", ["add", "."], { cwd: root });
  await execute("git", ["commit", "-qm", "fixture"], { cwd: root });
  return (await execute("git", ["rev-parse", "HEAD"], { cwd: root })).stdout.trim();
}

test("npm release staging binds only the Provider tarball to one commit and image", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "mycomesh-release-stage-test-"));
  const source = join(temporary, "source");
  const output = join(temporary, "candidate");
  const extracted = join(temporary, "extracted");
  const providerImage = `ghcr.io/charleslzp/mycomesh-provider-codex@sha256:${"a".repeat(64)}`;
  try {
    await mkdir(source);
    const sourceCommit = await makeRepository(source);
    const releasePath = join(source, "packages/mycomesh-cli/src/release.mjs");
    await writeFile(
      releasePath,
      (await readFile(releasePath, "utf8")).replace(
        "export const PROVIDER_RELEASE_SOURCE_COMMIT = null;",
        'export const PROVIDER_RELEASE_SOURCE_COMMIT = "replacement-tree";',
      ),
    );
    await execute("git", ["add", releasePath], { cwd: source });
    await execute("git", ["commit", "-qm", "replacement tree must be ignored"], { cwd: source });
    const replacementCommit = (await execute("git", ["rev-parse", "HEAD"], { cwd: source })).stdout.trim();
    await execute("git", ["checkout", "-q", "--detach", sourceCommit], { cwd: source });
    await execute("git", ["replace", sourceCommit, replacementCommit], { cwd: source });
    await appendFile(
      releasePath,
      "\n// Uncommitted working-tree content must not enter the release candidate.\n",
    );
    const before = (await execute("git", ["status", "--porcelain"], { cwd: source })).stdout;
    const forbiddenOutput = join(source, "release-output", "candidate");
    await assert.rejects(
      buildNpmReleaseCandidate({
        root: source,
        sourceCommit,
        providerImage,
        outputDir: forbiddenOutput,
      }),
      /outside the source repository/,
    );
    await assert.rejects(readFile(join(source, "release-output")), /ENOENT/);
    const result = await buildNpmReleaseCandidate({
      root: source,
      sourceCommit,
      providerImage,
      outputDir: output,
    });
    const after = (await execute("git", ["status", "--porcelain"], { cwd: source })).stdout;
    assert.match(before, /packages\/mycomesh-cli\/src\/release\.mjs/);
    assert.equal(after, before);
    assert.equal(result.schema, METADATA_SCHEMA);
    assert.equal(result.source_commit, sourceCommit);
    assert.equal(result.provider_image, providerImage);

    const metadata = JSON.parse(await readFile(join(output, METADATA_FILE), "utf8"));
    assert.equal(metadata.packages.provider.name, "mycomesh-provider");
    assert.equal(metadata.packages.provider.version, "0.1.38");
    assert.equal(metadata.packages.consumer.name, "mycomesh-consumer");
    assert.equal(metadata.packages.consumer.version, "0.1.52");
    for (const entry of Object.values(metadata.packages)) {
      assert.equal(entry.sha256, await digest(join(output, entry.filename)));
    }

    const providerList = (await execute("tar", [
      "-tzf",
      join(output, metadata.packages.provider.filename),
    ])).stdout;
    assert.doesNotMatch(providerList, /pre-release/);
    await mkdir(extracted);
    await execute("tar", [
      "-xzf",
      join(output, metadata.packages.provider.filename),
      "-C",
      extracted,
    ]);
    const provider = await import(
      `${pathToFileURL(join(extracted, "package/packages/mycomesh-cli/src/provider.mjs")).href}?fixture=${sourceCommit}`
    );
    const parsed = provider.parseArguments([], { HOME: "/Users/provider" });
    assert.equal(parsed.ref, sourceCommit);
    assert.equal(parsed.sourceDir, "/Users/provider/.mycomesh/provider/releases/0.1.38");
    assert.ok(provider.toBootstrapArgs(parsed).includes(providerImage));
    let doctorOutput = "";
    const doctorCode = await provider.main(["--doctor-json"], {
      env: { HOME: join(temporary, "provider-home") },
      stdout: { write: (value) => { doctorOutput += String(value); } },
      stderr: { write: () => {} },
      doctorRun: async () => ({ stdout: "GNU Make 4.4" }),
    });
    assert.equal(doctorCode, 0);
    const doctor = JSON.parse(doctorOutput);
    assert.deepEqual(doctor.release, {
      version: "0.1.38",
      binding: "bound",
      source_commit: sourceCommit,
      provider_image: providerImage,
      default_ref: sourceCommit,
    });

    const consumerList = (await execute("tar", [
      "-tzf",
      join(output, metadata.packages.consumer.filename),
    ])).stdout;
    assert.match(consumerList, /package\/networks\/v10-controlled-test\.json/);
    assert.match(consumerList, /package\/networks\/v10-controlled-test\.ca\.crt/);
    assert.doesNotMatch(consumerList, /pre-release/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
