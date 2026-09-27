#!/usr/bin/env node

// Publish only an immutable, release-gate-verified candidate.  This command
// is deliberately dry-run by default; --publish is the only mutating switch.

import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  lstat,
  mkdtemp,
  mkdir,
  readdir,
  readFile,
  rename,
  realpath,
  rm,
  rmdir,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const SCRIPT_PATH = fileURLToPath(import.meta.url);
const DEFAULT_ROOT = resolve(dirname(SCRIPT_PATH), "..");
const SOURCE_COMMIT_RE = /^[0-9a-f]{40}$/;
const PROVIDER_IMAGE_RE =
  /^ghcr\.io\/charleslzp\/mycomesh-provider-codex@sha256:[0-9a-f]{64}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const SHA1_RE = /^[0-9a-f]{40}$/;
const NPM_FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*\.tgz$/;
const NPM_INTEGRITY_RE = /^sha512-[A-Za-z0-9+/]+={0,2}$/;
const METADATA_SCHEMA = "mycomesh.npm-release-candidate.v1";
const METADATA_FILE = "npm-release-candidate.json";
const PUBLISH_JOURNAL_SCHEMA = "mycomesh.npm-publish-journal.v1";
const ATTESTATION_REPOSITORY = "Charleslzp/mycomesh";
const ATTESTATION_SIGNER_WORKFLOW =
  "Charleslzp/mycomesh/.github/workflows/release-candidate.yml";
const ATTESTATION_SOURCE_REF = "refs/heads/main";
const PACKAGE_ROLES = ["provider", "consumer"];
const PACKAGE_NAMES = {
  provider: "mycomesh-provider",
  consumer: "mycomesh-consumer",
};

function usage() {
  return `Usage: node scripts/publish-npm-release.mjs \\
  --candidate-dir PATH [--root PATH] [--registry URL] [--tag TAG]
  [--journal PATH] [--publish]

Validates a release-candidate directory produced by stage-npm-release.mjs and
the strict release gate. --publish additionally requires GitHub Actions
attestations for every candidate file, a registry preflight, and a fresh
package revalidation before each publish, all bound to the official workflow
and source commit. --publish records a resumable per-package journal outside
the candidate directory. Without --publish no npm or GitHub command is run.`;
}

function parseArguments(argv) {
  const parsed = {
    root: DEFAULT_ROOT,
    registry: "https://registry.npmjs.org",
    tag: "latest",
    publish: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "-h" || token === "--help") return { help: true };
    if (token === "--publish") {
      parsed.publish = true;
      continue;
    }
    const separator = token.indexOf("=");
    const name = separator === -1 ? token : token.slice(0, separator);
    const value = separator === -1 ? argv[++index] : token.slice(separator + 1);
    if (!name.startsWith("--") || !value) throw new Error(`${name} requires a value`);
    if (name === "--candidate-dir") parsed.candidateDir = value;
    else if (name === "--root") parsed.root = value;
    else if (name === "--registry") parsed.registry = value;
    else if (name === "--tag") parsed.tag = value;
    else if (name === "--journal") parsed.journalPath = value;
    else if (name === "--npm-command") parsed.npmCommand = value;
    else if (name === "--python-command") parsed.pythonCommand = value;
    else if (name === "--tar-command") parsed.tarCommand = value;
    else throw new Error(`unknown option: ${name}`);
  }
  return parsed;
}

function assertExactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (keys.length !== wanted.length || keys.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has unknown or missing fields`);
  }
}

function assertBoundedText(value, label, maximum = 512) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum ||
      value !== value.trim() || value.includes("\0")) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

async function regularFile(path, label) {
  const info = await lstat(path);
  if (info.isSymbolicLink() || !info.isFile()) throw new Error(`${label} must be a regular file`);
  return info;
}

async function candidateRoot(path) {
  const target = resolve(path || "");
  const info = await lstat(target);
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error("candidate directory must be a regular directory");
  }
  return realpath(target);
}

function safeCandidateFile(candidate, filename) {
  if (!NPM_FILENAME_RE.test(filename) || filename.includes("..")) {
    throw new Error(`candidate tarball filename is invalid: ${filename}`);
  }
  const path = resolve(candidate, filename);
  if (relative(candidate, path) !== filename) throw new Error("candidate tarball escapes its directory");
  return path;
}

function digest(raw, algorithm, encoding = "hex") {
  return createHash(algorithm).update(raw).digest(encoding);
}

async function readPackageJson(tarball, tarCommand) {
  let stdout;
  try {
    ({ stdout } = await execute(
      tarCommand,
      ["-x", "-O", "-z", "-f", tarball, "package/package.json"],
      { encoding: "utf8", maxBuffer: 256 * 1024 },
    ));
  } catch (error) {
    throw new Error(`cannot read package metadata from ${tarball}: ${error?.message || error}`);
  }
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error(`package metadata is not JSON: ${tarball}: ${error.message}`);
  }
}

async function candidateAttestationTargets(candidate) {
  const names = (await readdir(candidate)).sort();
  const targets = [];
  for (const name of names) {
    const path = join(candidate, name);
    const info = await lstat(path);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error(`attested candidate must contain only regular files: ${name}`);
    }
    targets.push(path);
  }
  if (targets.length === 0) throw new Error("attested candidate is empty");
  return targets;
}

function attestationSubjectMatches(report, expectedDigest) {
  if (!Array.isArray(report) || report.length === 0) return false;
  return report.some((entry) => {
    const subjects = entry?.verificationResult?.statement?.subject;
    if (!Array.isArray(subjects)) return false;
    return subjects.some((subject) => subject?.digest?.sha256 === expectedDigest);
  });
}

function validateAttestationOption(value, label, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

export async function verifyCandidateAttestations({
  candidate,
  sourceCommit,
  ghCommand = process.env.MYCOMESH_GH_CLI || "gh",
  repository = ATTESTATION_REPOSITORY,
  signerWorkflow = ATTESTATION_SIGNER_WORKFLOW,
  sourceRef = ATTESTATION_SOURCE_REF,
} = {}) {
  const candidatePath = await candidateRoot(candidate);
  if (!SOURCE_COMMIT_RE.test(sourceCommit || "")) {
    throw new Error("attestation source commit is invalid");
  }
  validateAttestationOption(
    repository,
    "attestation repository",
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
  );
  validateAttestationOption(
    signerWorkflow,
    "attestation signer workflow",
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/\.github\/workflows\/[A-Za-z0-9_.-]+$/,
  );
  validateAttestationOption(
    sourceRef,
    "attestation source ref",
    /^refs\/heads\/[A-Za-z0-9._/-]+$/,
  );
  const targets = await candidateAttestationTargets(candidatePath);
  const verified = [];
  for (const path of targets) {
    const expectedDigest = digest(await readFile(path), "sha256");
    let stdout;
    try {
      ({ stdout } = await execute(
        ghCommand,
        [
          "attestation", "verify", path,
          "--repo", repository,
          "--signer-workflow", signerWorkflow,
          "--source-digest", sourceCommit,
          "--source-ref", sourceRef,
          "--deny-self-hosted-runners",
          "--digest-alg", "sha256",
          "--format", "json",
        ],
        { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 },
      ));
    } catch (error) {
      throw new Error(
        `GitHub attestation verification failed for ${path}: ${error?.message || error}`,
      );
    }
    let report;
    try {
      report = JSON.parse(stdout);
    } catch (error) {
      throw new Error(`GitHub attestation output is not JSON for ${path}: ${error.message}`);
    }
    if (!attestationSubjectMatches(report, expectedDigest)) {
      throw new Error(`GitHub attestation subject does not match ${path}`);
    }
    verified.push({ path, sha256: expectedDigest });
  }
  return {
    repository,
    signer_workflow: signerWorkflow,
    source_commit: sourceCommit,
    source_ref: sourceRef,
    files: verified,
  };
}

async function validateCandidate({ candidateDir, tarCommand = process.env.MYCOMESH_TAR_CLI || "tar" } = {}) {
  const candidate = await candidateRoot(candidateDir);
  const metadataPath = join(candidate, METADATA_FILE);
  await regularFile(metadataPath, METADATA_FILE);
  let metadata;
  try {
    metadata = JSON.parse(await readFile(metadataPath, "utf8"));
  } catch (error) {
    throw new Error(`candidate metadata is not strict JSON: ${error.message}`);
  }
  assertExactKeys(metadata, ["schema", "source_commit", "provider_image", "packages"], "candidate metadata");
  if (metadata.schema !== METADATA_SCHEMA || !SOURCE_COMMIT_RE.test(metadata.source_commit)) {
    throw new Error("candidate metadata schema or source_commit is invalid");
  }
  if (!PROVIDER_IMAGE_RE.test(metadata.provider_image)) {
    throw new Error("candidate Provider image must be pinned to the official OCI digest");
  }
  assertExactKeys(metadata.packages, PACKAGE_ROLES, "candidate packages");
  const packages = {};
  for (const role of PACKAGE_ROLES) {
    const declared = metadata.packages[role];
    assertExactKeys(
      declared,
      ["name", "version", "filename", "size", "sha256", "npm_shasum", "npm_integrity"],
      `candidate ${role} package`,
    );
    if (declared.name !== PACKAGE_NAMES[role] || !assertBoundedText(declared.version, `${role} version`, 128)) {
      throw new Error(`candidate ${role} package identity is invalid`);
    }
    if (!NPM_FILENAME_RE.test(declared.filename) || declared.filename.includes("..")) {
      throw new Error(`candidate ${role} filename is invalid`);
    }
    if (!Number.isInteger(declared.size) || declared.size <= 0 || declared.size > 64 * 1024 * 1024) {
      throw new Error(`candidate ${role} tarball size is invalid`);
    }
    if (!SHA256_RE.test(declared.sha256) || !SHA1_RE.test(declared.npm_shasum) ||
        !NPM_INTEGRITY_RE.test(declared.npm_integrity)) {
      throw new Error(`candidate ${role} tarball digests are invalid`);
    }
    const path = safeCandidateFile(candidate, declared.filename);
    const info = await regularFile(path, `${role} tarball`);
    const raw = await readFile(path);
    if (info.size !== declared.size || raw.length !== declared.size) {
      throw new Error(`${role} tarball size does not match candidate metadata`);
    }
    if (digest(raw, "sha256") !== declared.sha256 || digest(raw, "sha1") !== declared.npm_shasum ||
        `sha512-${digest(raw, "sha512", "base64")}` !== declared.npm_integrity) {
      throw new Error(`${role} tarball digest does not match candidate metadata`);
    }
    const packed = await readPackageJson(path, tarCommand);
    if (!packed || packed.name !== declared.name || packed.version !== declared.version) {
      throw new Error(`${role} tarball package.json identity does not match candidate metadata`);
    }
    packages[role] = { ...declared, path };
  }
  if (packages.provider.filename === packages.consumer.filename) {
    throw new Error("Provider and Consumer tarballs must be different files");
  }
  return { candidate, metadata, packages };
}

async function runReleaseGate({
  root,
  candidate,
  metadata,
  packages,
  pythonCommand = process.env.MYCOMESH_PYTHON_CLI || "python3",
  juryRegistryArtifact,
} = {}) {
  const rootPath = await realpath(resolve(root));
  const args = [
    join(rootPath, "scripts/release_gate.py"),
    "--strict-artifacts",
    "--json",
    "--root", rootPath,
    "--artifact-evidence", join(candidate, "release-artifacts.json"),
    "--npm-metadata", join(candidate, METADATA_FILE),
    "--provider-tgz", packages.provider.path,
    "--consumer-tgz", packages.consumer.path,
    "--oci-metadata", join(candidate, "provider-oci-metadata.json"),
    "--deployed-code-evidence", join(candidate, "deployed-code.json"),
    "--abi-artifact", join(rootPath, "out/MycoSettlementV10.sol/MycoSettlementV10.json"),
    "--expected-source-commit", metadata.source_commit,
  ];
  const registryArtifact = juryRegistryArtifact
    ? resolve(juryRegistryArtifact)
    : join(rootPath, "out/ProviderJuryRegistryV1.sol/ProviderJuryRegistryV1.json");
  try {
    await regularFile(registryArtifact, "ProviderJuryRegistryV1 compiler artifact");
    args.push("--jury-registry-abi-artifact", registryArtifact);
  } catch (error) {
    throw new Error(`strict release gate requires the ProviderJuryRegistryV1 artifact: ${error.message}`);
  }
  let stdout = "";
  try {
    ({ stdout } = await execute(pythonCommand, args, {
      cwd: rootPath,
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    }));
  } catch (error) {
    const output = [error?.stdout, error?.stderr].filter(Boolean).join("\n").trim();
    throw new Error(`strict release gate failed${output ? `: ${output}` : ""}`);
  }
  let report;
  try {
    report = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`strict release gate returned invalid JSON: ${error.message}`);
  }
  if (report?.ok !== true) throw new Error("strict release gate did not pass");
  return report;
}

function packageDigestRecord(item) {
  return {
    name: item.name,
    version: item.version,
    filename: item.filename,
    size: item.size,
    sha256: item.sha256,
    npm_shasum: item.npm_shasum,
    npm_integrity: item.npm_integrity,
  };
}

function assertCandidateBinding(current, baseline) {
  if (
    current.metadata.schema !== baseline.metadata.schema
    || current.metadata.source_commit !== baseline.metadata.source_commit
    || current.metadata.provider_image !== baseline.metadata.provider_image
  ) {
    throw new Error("candidate metadata changed after the release gate");
  }
  for (const role of PACKAGE_ROLES) {
    if (
      JSON.stringify(packageDigestRecord(current.packages[role]))
      !== JSON.stringify(packageDigestRecord(baseline.packages[role]))
    ) {
      throw new Error(`${role} package changed after the release gate`);
    }
  }
}

function npmNotFound(error) {
  const output = [error?.stdout, error?.stderr, error?.message]
    .filter(Boolean)
    .join("\n");
  return /\bE404\b|404\s+Not Found|no match found|is not in this registry/i.test(output);
}

async function npmViewPackage({
  npmCommand = process.env.MYCOMESH_NPM_CLI || "npm",
  registry,
  name,
  version,
}) {
  let stdout = "";
  try {
    ({ stdout } = await execute(
      npmCommand,
      ["view", `${name}@${version}`, "--json", "--registry", registry],
      { encoding: "utf8", maxBuffer: 512 * 1024 },
    ));
  } catch (error) {
    if (npmNotFound(error)) return false;
    throw new Error(
      `npm registry preflight failed for ${name}@${version}: ${error?.message || error}`,
    );
  }
  let value;
  try {
    value = JSON.parse(stdout);
  } catch (error) {
    throw new Error(`npm registry preflight returned invalid JSON for ${name}@${version}: ${error.message}`);
  }
  const manifest = Array.isArray(value) ? value[0] : value;
  const observedVersion = typeof manifest === "string"
    ? manifest
    : manifest && typeof manifest.version === "string" ? manifest.version : null;
  if (observedVersion !== version) {
    throw new Error(`npm registry preflight returned an unexpected version for ${name}@${version}`);
  }
  const dist = manifest && typeof manifest === "object" && manifest.dist && typeof manifest.dist === "object"
    ? manifest.dist
    : manifest && typeof manifest === "object" ? manifest : {};
  return {
    version,
    npm_shasum: typeof dist.shasum === "string" ? dist.shasum : null,
    npm_integrity: typeof dist.integrity === "string" ? dist.integrity : null,
  };
}

export async function preflightRegistry({
  npmCommand = process.env.MYCOMESH_NPM_CLI || "npm",
  registry,
  packages,
  allowExisting = false,
} = {}) {
  const status = {};
  for (const role of PACKAGE_ROLES) {
    const item = packages?.[role];
    if (!item?.name || !item?.version) throw new Error(`missing ${role} package for npm preflight`);
    const existing = await npmViewPackage({ npmCommand, registry, name: item.name, version: item.version });
    if (!existing) {
      status[role] = "absent";
      continue;
    }
    if (!allowExisting) {
      throw new Error(`npm package version already exists for ${item.name}@${item.version}; refusing to publish`);
    }
    if (existing.npm_shasum !== item.npm_shasum || existing.npm_integrity !== item.npm_integrity) {
      throw new Error(`npm package version already exists with a different digest: ${item.name}@${item.version}`);
    }
    status[role] = "published";
  }
  return status;
}

function defaultJournalPath(candidatePath) {
  return resolve(dirname(candidatePath), `.${basename(candidatePath)}.npm-publish.json`);
}

function assertJournalPackage(item, role, label) {
  if (!item || typeof item !== "object" || item.name !== PACKAGE_NAMES[role]
      || !assertBoundedText(item.version, `${label} version`, 128)
      || !NPM_FILENAME_RE.test(item.filename) || item.filename.includes("..")
      || !Number.isInteger(item.size) || item.size <= 0 || item.size > 64 * 1024 * 1024
      || !SHA256_RE.test(item.sha256)
      || !SHA1_RE.test(item.npm_shasum) || !NPM_INTEGRITY_RE.test(item.npm_integrity)
      || !["pending", "published"].includes(item.status)
      || (item.published_at !== null && (!Number.isInteger(item.published_at) || item.published_at <= 0))) {
    throw new Error(`${label} is invalid`);
  }
}

function journalValue({ candidate, registry, tag, statuses = {} }) {
  return {
    schema: PUBLISH_JOURNAL_SCHEMA,
    candidate_dir: candidate.candidate,
    source_commit: candidate.metadata.source_commit,
    registry,
    tag,
    packages: Object.fromEntries(PACKAGE_ROLES.map((role) => {
      const item = candidate.packages[role];
      return [role, {
        name: item.name,
        version: item.version,
        filename: item.filename,
        size: item.size,
        sha256: item.sha256,
        npm_shasum: item.npm_shasum,
        npm_integrity: item.npm_integrity,
        status: statuses[role] || "pending",
        published_at: null,
      }];
    })),
  };
}

function assertJournalBinding(journal, candidate, registry, tag) {
  assertExactKeys(journal, ["schema", "candidate_dir", "source_commit", "registry", "tag", "packages"], "publish journal");
  if (journal.schema !== PUBLISH_JOURNAL_SCHEMA
      || journal.candidate_dir !== candidate.candidate
      || journal.source_commit !== candidate.metadata.source_commit
      || journal.registry !== registry || journal.tag !== tag) {
    throw new Error("publish journal does not match this candidate, registry, or tag");
  }
  assertExactKeys(journal.packages, PACKAGE_ROLES, "publish journal packages");
  for (const role of PACKAGE_ROLES) {
    const item = candidate.packages[role];
    const entry = journal.packages[role];
    assertExactKeys(entry, ["name", "version", "filename", "size", "sha256", "npm_shasum", "npm_integrity", "status", "published_at"], `publish journal ${role}`);
    assertJournalPackage(entry, role, `publish journal ${role}`);
    if (entry.name !== item.name || entry.version !== item.version
        || entry.filename !== item.filename || entry.size !== item.size
        || entry.sha256 !== item.sha256 || entry.npm_shasum !== item.npm_shasum
        || entry.npm_integrity !== item.npm_integrity) {
      throw new Error(`publish journal ${role} digest binding differs from candidate`);
    }
  }
}

async function writeJournal(path, journal) {
  const parent = dirname(path);
  const parentInfo = await lstat(parent);
  if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory()) {
    throw new Error("publish journal parent must be a regular directory");
  }
  try {
    const current = await lstat(path);
    if (current.isSymbolicLink() || !current.isFile()) throw new Error("publish journal must be a regular file");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const temporary = join(parent, `.${basename(path)}.${process.pid}.${Date.now()}.tmp`);
  try {
    await writeFile(temporary, `${JSON.stringify(journal, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true }).catch(() => {});
  }
}

async function loadJournal(path, candidate, registry, tag) {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink() || !info.isFile()) throw new Error("publish journal must be a regular file");
    const journal = JSON.parse(await readFile(path, "utf8"));
    assertJournalBinding(journal, candidate, registry, tag);
    return { journal, existed: true };
  } catch (error) {
    if (error?.code !== "ENOENT") throw new Error(`publish journal is invalid: ${error?.message || error}`);
    const journal = journalValue({ candidate, registry, tag });
    await writeJournal(path, journal);
    return { journal, existed: false };
  }
}

function setJournalStatus(journal, role, status) {
  if (journal.packages[role].status === status) return;
  journal.packages[role].status = status;
  journal.packages[role].published_at = status === "published" ? Math.floor(Date.now() / 1000) : null;
}

async function packageSnapshot(item, directory) {
  const raw = await readFile(item.path);
  if (raw.length !== item.size || digest(raw, "sha256") !== item.sha256
      || digest(raw, "sha1") !== item.npm_shasum
      || `sha512-${digest(raw, "sha512", "base64")}` !== item.npm_integrity) {
    throw new Error(`${item.name} tarball changed while creating publish snapshot`);
  }
  const path = join(directory, item.filename);
  await writeFile(path, raw, { mode: 0o600, flag: "wx" });
  return path;
}

async function assertJournalOutsideCandidate(journalPath, candidatePath) {
  const canonicalCandidate = await realpath(candidatePath);
  const parent = dirname(journalPath);
  let canonicalParent;
  try {
    canonicalParent = await realpath(parent);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    canonicalParent = resolve(parent);
  }
  const canonicalJournal = join(canonicalParent, basename(journalPath));
  const relativePath = relative(canonicalCandidate, canonicalJournal);
  if (!relativePath || (!relativePath.startsWith("..") && !relativePath.startsWith("/"))) {
    throw new Error("publish journal must be outside the candidate directory");
  }
}

async function acquirePublishLock(journalPath, candidatePath) {
  await assertJournalOutsideCandidate(journalPath, candidatePath);
  const lockPath = `${journalPath}.lock`;
  const parent = dirname(lockPath);
  const parentInfo = await lstat(parent);
  if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory()) {
    throw new Error("publish lock parent must be a regular directory");
  }
  try {
    await mkdir(lockPath, { mode: 0o700 });
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error(
        `publish lock already exists at ${lockPath}; refusing concurrent or uncertain retry`,
      );
    }
    throw error;
  }
  return async () => {
    try {
      await rmdir(lockPath);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  };
}

async function registryPackageStatus({ npmCommand, registry, item }) {
  const existing = await npmViewPackage({
    npmCommand,
    registry,
    name: item.name,
    version: item.version,
  });
  if (!existing) return "absent";
  if (existing.npm_shasum !== item.npm_shasum || existing.npm_integrity !== item.npm_integrity) {
    throw new Error(`npm package version already exists with a different digest: ${item.name}@${item.version}`);
  }
  return "published";
}

async function publishPackages({
  npmCommand = process.env.MYCOMESH_NPM_CLI || "npm",
  registry,
  tag,
  candidate,
  tarCommand,
  journal = null,
  journalPath = null,
  lockHeld = false,
}) {
  const resolvedJournalPath = journalPath ? resolve(journalPath) : null;
  if ((journal && !resolvedJournalPath) || (!journal && resolvedJournalPath)) {
    throw new Error("publish journal and journal path must be supplied together");
  }
  const run = async () => {
    const snapshotDirectory = await mkdtemp(join(tmpdir(), "mycomesh-npm-publish-"));
    try {
      for (const role of ["provider", "consumer"]) {
        const refreshed = await validateCandidate({ candidateDir: candidate.candidate, tarCommand });
        assertCandidateBinding(refreshed, candidate);
        const item = refreshed.packages[role];
        const state = await registryPackageStatus({ npmCommand, registry, item });
        if (state === "published") {
          if (journal) {
            if (journal.packages[role].status === "pending") {
              setJournalStatus(journal, role, "published");
              await writeJournal(resolvedJournalPath, journal);
            }
          }
          continue;
        }
        if (journal && journal.packages[role].status === "published") {
          throw new Error(`publish journal marks ${item.name}@${item.version} published but registry did not confirm it`);
        }
        const snapshot = await packageSnapshot(item, snapshotDirectory);
        await execute(
          npmCommand,
          ["publish", snapshot, "--ignore-scripts", "--provenance", "--access", "public", "--tag", tag, "--registry", registry],
          { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 },
        );
        if (journal) {
          setJournalStatus(journal, role, "published");
          await writeJournal(resolvedJournalPath, journal);
        }
      }
    } finally {
      await rm(snapshotDirectory, { recursive: true, force: true });
    }
  };
  if (lockHeld) return run();
  const releaseLock = await acquirePublishLock(
    resolvedJournalPath || defaultJournalPath(candidate.candidate),
    candidate.candidate,
  );
  try {
    return await run();
  } finally {
    await releaseLock();
  }
}

export async function publishNpmRelease(options = {}) {
  const candidate = await validateCandidate(options);
  const registry = options.registry || "https://registry.npmjs.org";
  let parsedRegistry;
  try {
    parsedRegistry = new URL(registry);
  } catch (error) {
    throw new Error(`registry URL is invalid: ${error.message}`);
  }
  if (parsedRegistry.protocol !== "https:") throw new Error("npm registry must use HTTPS");
  if (parsedRegistry.username || parsedRegistry.password || parsedRegistry.search || parsedRegistry.hash) {
    throw new Error("npm registry URL must not contain credentials, query parameters, or fragments");
  }
  const tag = options.tag || "latest";
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(tag)) throw new Error("npm dist-tag is invalid");
  await runReleaseGate({ ...options, ...candidate });
  if (options.publish !== true) {
    return {
      source_commit: candidate.metadata.source_commit,
      registry,
      tag,
      published: false,
      packages: Object.fromEntries(PACKAGE_ROLES.map((role) => [
        role,
        { name: candidate.packages[role].name, version: candidate.packages[role].version },
      ])),
    };
  }
  const attestation = await verifyCandidateAttestations({
    candidate: candidate.candidate,
    sourceCommit: candidate.metadata.source_commit,
  });
  const journalPath = resolve(options.journalPath || defaultJournalPath(candidate.candidate));
  await assertJournalOutsideCandidate(journalPath, candidate.candidate);
  const releaseLock = await acquirePublishLock(journalPath, candidate.candidate);
  try {
    const loadedJournal = await loadJournal(journalPath, candidate, registry, tag);
    const registryPreflight = await preflightRegistry({
      ...options,
      registry,
      packages: candidate.packages,
      allowExisting: loadedJournal.existed,
    });
    const journal = loadedJournal.journal;
    for (const role of PACKAGE_ROLES) {
      if (registryPreflight[role] === "published" && journal.packages[role].status === "pending") {
        setJournalStatus(journal, role, "published");
        await writeJournal(journalPath, journal);
      }
    }
    await publishPackages({ ...options, registry, tag, candidate, journal, journalPath, lockHeld: true });
    return {
      source_commit: candidate.metadata.source_commit,
      registry,
      tag,
      published: true,
      attestation_verified: attestation.files.length,
      registry_preflight: registryPreflight,
      journal_path: journalPath,
      journal: Object.fromEntries(PACKAGE_ROLES.map((role) => [role, journal.packages[role].status])),
      packages: Object.fromEntries(PACKAGE_ROLES.map((role) => [
        role,
        { name: candidate.packages[role].name, version: candidate.packages[role].version },
      ])),
    };
  } finally {
    await releaseLock();
  }
}

async function main(argv) {
  try {
    const parsed = parseArguments(argv);
    if (parsed.help) {
      process.stdout.write(`${usage()}\n`);
      return 0;
    }
    if (!parsed.candidateDir) throw new Error("--candidate-dir is required");
    const result = await publishNpmRelease(parsed);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`publish npm release: ${error instanceof Error ? error.message : String(error)}\n`);
    process.stderr.write(`${usage()}\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === SCRIPT_PATH) {
  process.exitCode = await main(process.argv.slice(2));
}

export {
  ATTESTATION_REPOSITORY,
  ATTESTATION_SIGNER_WORKFLOW,
  ATTESTATION_SOURCE_REF,
  METADATA_FILE,
  METADATA_SCHEMA,
  parseArguments,
  publishPackages,
  loadJournal,
  validateCandidate,
};
