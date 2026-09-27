import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  METADATA_FILE,
  METADATA_SCHEMA,
  parseArguments,
  preflightRegistry,
  publishNpmRelease,
  publishPackages,
  loadJournal,
  validateCandidate,
  verifyCandidateAttestations,
} from "../../../scripts/publish-npm-release.mjs";

const execute = promisify(execFile);
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));

function digest(raw, algorithm, encoding = "hex") {
  return createHash(algorithm).update(raw).digest(encoding);
}

async function makePackage(candidate, role, name, version) {
  const source = await mkdtemp(join(candidate, `.source-${role}-`));
  await mkdir(join(source, "package"), { recursive: true });
  await writeFile(
    join(source, "package/package.json"),
    JSON.stringify({ name, version, files: ["package.json"] }),
  );
  const filename = `${name}-${version}.tgz`;
  const path = join(candidate, filename);
  await execute("tar", ["-czf", path, "-C", source, "package"]);
  const raw = await readFile(path);
  await rm(source, { recursive: true, force: true });
  return {
    name,
    version,
    filename,
    size: raw.length,
    sha256: digest(raw, "sha256"),
    npm_shasum: digest(raw, "sha1"),
    npm_integrity: `sha512-${digest(raw, "sha512", "base64")}`,
  };
}

async function makeFakeGh({ match = true } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-fake-gh-"));
  const command = join(directory, "gh");
  const digestExpression = match
    ? 'createHash("sha256").update(raw).digest("hex")'
    : '"0".repeat(64)';
  await writeFile(command, `#!/usr/bin/env node
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const path = process.argv[4];
const raw = readFileSync(path);
const sha256 = ${digestExpression};
process.stdout.write(JSON.stringify([{ verificationResult: { statement: { subject: [{ name: path, digest: { sha256 } }] } } }]));
`, { encoding: "utf8", mode: 0o755 });
  await chmod(command, 0o755);
  return { directory, command };
}

async function makeFakeNpm({ existing = [], failure = false, mutatePath = null, markerPath = null, logPath = null } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-fake-npm-"));
  const command = join(directory, "npm");
  await writeFile(command, `#!/usr/bin/env node
const { appendFileSync, writeFileSync } = require("node:fs");
const args = process.argv.slice(2);
const existing = ${JSON.stringify(existing)};
const mutatePath = ${JSON.stringify(mutatePath)};
const markerPath = ${JSON.stringify(markerPath)};
const logPath = ${JSON.stringify(logPath)};
if (markerPath) writeFileSync(markerPath, args.join(" "));
if (args[0] === "view") {
  const spec = args[1];
  let record = null;
  if (Array.isArray(existing) && existing.includes(spec)) {
    record = spec.slice(spec.lastIndexOf("@") + 1);
  } else if (existing && !Array.isArray(existing) && typeof existing === "object") {
    record = existing[spec] || null;
  }
  if (record !== null) {
    process.stdout.write(JSON.stringify(record));
    process.exit(0);
  }
  if (${JSON.stringify(failure)}) {
    process.stderr.write("npm ERR! code E401\\n");
    process.exit(1);
  }
  process.stderr.write("npm ERR! code E404\\n");
  process.exit(1);
}
if (args[0] === "publish") {
  if (logPath) appendFileSync(logPath, args[1] + "\\n");
  if (mutatePath) writeFileSync(mutatePath, "tampered");
}
`, { encoding: "utf8", mode: 0o755 });
  await chmod(command, 0o755);
  return { directory, command };
}

async function makeFakePython() {
  const directory = await mkdtemp(join(tmpdir(), "mycomesh-fake-python-"));
  const command = join(directory, "python");
  await writeFile(command, `#!/usr/bin/env node
process.stdout.write(JSON.stringify({ ok: true }));
`, { encoding: "utf8", mode: 0o755 });
  await chmod(command, 0o755);
  return { directory, command };
}

async function makeCandidate() {
  const temporary = await mkdtemp(join(tmpdir(), "mycomesh-npm-publish-test-"));
  const provider = await makePackage(temporary, "provider", "mycomesh-provider", "0.1.38");
  const consumer = await makePackage(temporary, "consumer", "mycomesh-consumer", "0.1.52");
  await writeFile(
    join(temporary, METADATA_FILE),
    JSON.stringify({
      schema: METADATA_SCHEMA,
      source_commit: "a".repeat(40),
      provider_image: `ghcr.io/charleslzp/mycomesh-provider-codex@sha256:${"b".repeat(64)}`,
      packages: { provider, consumer },
    }),
  );
  return { temporary, provider, consumer };
}

test("publish candidate validation binds tarball identity and all npm digests", async () => {
  const fixture = await makeCandidate();
  try {
    const result = await validateCandidate({ candidateDir: fixture.temporary });
    assert.equal(result.metadata.source_commit, "a".repeat(40));
    assert.equal(result.packages.provider.name, "mycomesh-provider");
    assert.equal(result.packages.consumer.version, "0.1.52");
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
  }
});

test("publish candidate validation rejects a changed tarball before any npm call", async () => {
  const fixture = await makeCandidate();
  try {
    await writeFile(join(fixture.temporary, fixture.provider.filename), "tampered");
    await assert.rejects(
      validateCandidate({ candidateDir: fixture.temporary }),
      /size does not match candidate metadata|digest does not match candidate metadata/,
    );
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
  }
});

test("publish attestation verification binds every candidate file to its digest", async () => {
  const fixture = await makeCandidate();
  const fakeGh = await makeFakeGh();
  try {
    const result = await verifyCandidateAttestations({
      candidate: fixture.temporary,
      sourceCommit: "a".repeat(40),
      ghCommand: fakeGh.command,
    });
    assert.equal(result.files.length, 3);
    assert.equal(result.repository, "Charleslzp/mycomesh");
    assert.equal(result.signer_workflow, "Charleslzp/mycomesh/.github/workflows/release-candidate.yml");
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(fakeGh.directory, { recursive: true, force: true });
  }
});

test("publish attestation verification fails on a mismatched subject digest", async () => {
  const fixture = await makeCandidate();
  const fakeGh = await makeFakeGh({ match: false });
  try {
    await assert.rejects(
      verifyCandidateAttestations({
        candidate: fixture.temporary,
        sourceCommit: "a".repeat(40),
        ghCommand: fakeGh.command,
      }),
      /subject does not match/,
    );
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(fakeGh.directory, { recursive: true, force: true });
  }
});

test("publish preflight requires every candidate version to be absent", async () => {
  const fixture = await makeCandidate();
  const fakeNpm = await makeFakeNpm();
  try {
    const result = await preflightRegistry({
      npmCommand: fakeNpm.command,
      registry: "https://registry.npmjs.org",
      packages: { provider: fixture.provider, consumer: fixture.consumer },
    });
    assert.deepEqual(result, { provider: "absent", consumer: "absent" });
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(fakeNpm.directory, { recursive: true, force: true });
  }
});

test("publish preflight rejects an existing version and non-404 registry errors", async () => {
  const fixture = await makeCandidate();
  const existingNpm = await makeFakeNpm({ existing: ["mycomesh-provider@0.1.38"] });
  const failureNpm = await makeFakeNpm({ failure: true });
  try {
    await assert.rejects(
      preflightRegistry({
        npmCommand: existingNpm.command,
        registry: "https://registry.npmjs.org",
        packages: { provider: fixture.provider, consumer: fixture.consumer },
      }),
      /already exists .*mycomesh-provider@0\.1\.38/,
    );
    await assert.rejects(
      preflightRegistry({
        npmCommand: failureNpm.command,
        registry: "https://registry.npmjs.org",
        packages: { provider: fixture.provider, consumer: fixture.consumer },
      }),
      /preflight failed/,
    );
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(existingNpm.directory, { recursive: true, force: true });
    await rm(failureNpm.directory, { recursive: true, force: true });
  }
});

test("dry-run does not call npm view or publish", async () => {
  const fixture = await makeCandidate();
  const marker = join(fixture.temporary, "npm-called");
  const fakeNpm = await makeFakeNpm({ markerPath: marker });
  const fakePython = await makeFakePython();
  try {
    const result = await publishNpmRelease({
      candidateDir: fixture.temporary,
      root: repositoryRoot,
      npmCommand: fakeNpm.command,
      pythonCommand: fakePython.command,
      publish: false,
    });
    assert.equal(result.published, false);
    await assert.rejects(readFile(marker), { code: "ENOENT" });
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(fakeNpm.directory, { recursive: true, force: true });
    await rm(fakePython.directory, { recursive: true, force: true });
  }
});

test("publish revalidates the untouched package after the first publish", async () => {
  const fixture = await makeCandidate();
  const baseline = await validateCandidate({ candidateDir: fixture.temporary });
  const fakeNpm = await makeFakeNpm({
    mutatePath: join(fixture.temporary, fixture.consumer.filename),
  });
  try {
    await assert.rejects(
      publishPackages({
        npmCommand: fakeNpm.command,
        registry: "https://registry.npmjs.org",
        tag: "latest",
        candidate: baseline,
      }),
      /consumer tarball size does not match candidate metadata/,
    );
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(fakeNpm.directory, { recursive: true, force: true });
  }
});

test("publish journal records package progress and resumes only from exact registry digests", async () => {
  const fixture = await makeCandidate();
  const baseline = await validateCandidate({ candidateDir: fixture.temporary });
  const journalPath = join(fixture.temporary, "..", "npm-publish-journal.json");
  const firstLog = join(fixture.temporary, "first-publish.log");
  const firstNpm = await makeFakeNpm({ logPath: firstLog });
  try {
    const loaded = await loadJournal(
      journalPath,
      baseline,
      "https://registry.npmjs.org",
      "latest",
    );
    assert.equal(loaded.existed, false);
    await publishPackages({
      npmCommand: firstNpm.command,
      registry: "https://registry.npmjs.org",
      tag: "latest",
      candidate: baseline,
      journal: loaded.journal,
      journalPath,
    });
    assert.deepEqual(
      Object.fromEntries(Object.entries(loaded.journal.packages).map(([role, item]) => [role, item.status])),
      { provider: "published", consumer: "published" },
    );
    assert.equal((await readFile(firstLog, "utf8")).trim().split("\n").length, 2);

    const exactRegistry = {
      [`${fixture.provider.name}@${fixture.provider.version}`]: {
        version: fixture.provider.version,
        dist: { shasum: fixture.provider.npm_shasum, integrity: fixture.provider.npm_integrity },
      },
      [`${fixture.consumer.name}@${fixture.consumer.version}`]: {
        version: fixture.consumer.version,
        dist: { shasum: fixture.consumer.npm_shasum, integrity: fixture.consumer.npm_integrity },
      },
    };
    const resumeNpm = await makeFakeNpm({ existing: exactRegistry, logPath: join(fixture.temporary, "resume.log") });
    try {
      const resumed = await loadJournal(
        journalPath,
        baseline,
        "https://registry.npmjs.org",
        "latest",
      );
      assert.equal(resumed.existed, true);
      await publishPackages({
        npmCommand: resumeNpm.command,
        registry: "https://registry.npmjs.org",
        tag: "latest",
        candidate: baseline,
        journal: resumed.journal,
        journalPath,
      });
      await assert.rejects(readFile(join(fixture.temporary, "resume.log")), { code: "ENOENT" });
    } finally {
      await rm(resumeNpm.directory, { recursive: true, force: true });
    }
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(firstNpm.directory, { recursive: true, force: true });
    await rm(journalPath, { force: true });
  }
});

test("publishPackages rejects a journal inside the candidate directory", async () => {
  const fixture = await makeCandidate();
  const baseline = await validateCandidate({ candidateDir: fixture.temporary });
  const fakeNpm = await makeFakeNpm();
  try {
    const loaded = await loadJournal(
      join(fixture.temporary, "publish-journal.json"),
      baseline,
      "https://registry.npmjs.org",
      "latest",
    );
    await assert.rejects(
      publishPackages({
        npmCommand: fakeNpm.command,
        registry: "https://registry.npmjs.org",
        tag: "latest",
        candidate: baseline,
        journal: loaded.journal,
        journalPath: join(fixture.temporary, "publish-journal.json"),
      }),
      /journal must be outside the candidate directory/,
    );
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(fakeNpm.directory, { recursive: true, force: true });
  }
});

test("publishPackages refuses a pre-existing publish lock", async () => {
  const fixture = await makeCandidate();
  const baseline = await validateCandidate({ candidateDir: fixture.temporary });
  const fakeNpm = await makeFakeNpm();
  const journalPath = join(fixture.temporary, "..", "locked-publish-journal.json");
  const lockPath = `${journalPath}.lock`;
  await mkdir(lockPath, { mode: 0o700 });
  try {
    await assert.rejects(
      publishPackages({
        npmCommand: fakeNpm.command,
        registry: "https://registry.npmjs.org",
        tag: "latest",
        candidate: baseline,
        journal: {
          schema: "mycomesh.npm-publish-journal.v1",
          candidate_dir: baseline.candidate,
          source_commit: baseline.metadata.source_commit,
          registry: "https://registry.npmjs.org",
          tag: "latest",
          packages: Object.fromEntries(["provider", "consumer"].map((role) => [role, {
            ...baseline.packages[role], status: "pending", published_at: null,
          }])),
        },
        journalPath,
      }),
      /publish lock already exists/,
    );
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
    await rm(fakeNpm.directory, { recursive: true, force: true });
    await rm(journalPath, { force: true });
    await rm(lockPath, { recursive: true, force: true });
  }
});

test("publish CLI requires an explicit mutating switch", () => {
  const parsed = parseArguments(["--candidate-dir", "/tmp/candidate"]);
  assert.equal(parsed.publish, false);
  assert.equal(parseArguments(["--candidate-dir=/tmp/candidate", "--publish"]).publish, true);
});

test("publish rejects registry credentials and URL decorations", async () => {
  const fixture = await makeCandidate();
  try {
    for (const registry of [
      "https://user:password@registry.npmjs.org",
      "https://registry.npmjs.org/?token=leak",
      "https://registry.npmjs.org/#publish",
    ]) {
      await assert.rejects(
        publishNpmRelease({ candidateDir: fixture.temporary, registry }),
        /must not contain credentials, query parameters, or fragments/,
      );
    }
  } finally {
    await rm(fixture.temporary, { recursive: true, force: true });
  }
});
